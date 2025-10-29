from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from collections import deque

import logging
import threading
import time

log = core.getLogger()
for handler in logging.getLogger().handlers:
    formatter = logging.Formatter(fmt="%(asctime)s.%(msecs)03d %(levelname)s:%(name)s: %(message)s",
                                  datefmt="%H:%M:%S")
    handler.setFormatter(formatter)

PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK = 24
PRIVATE_IP = IPAddr("192.168.1.254")
PUBLIC_IP = IPAddr("200.0.0.254")
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")
PUBLIC_PORT = 1


class NAT(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.nat_table = {}
        self.reverse_nat_table = {}
        self.mac_port_table = {}
        self.arp_cache = {}
        self.pending_events = {}
        self.next_port = 10000
        self.nat_timestamps = {}

        threading.Thread(target=self.cleanup_loop, daemon=True).start()

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        if not packet.parsed:
            log.warning("Ignorando paquete sin parsear")
            return

        self.mac_port_table[packet.src] = in_port

        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(packet, in_port)
        elif packet.type == ethernet.IP_TYPE:
            self.handle_ip(packet, event)

    def handle_arp(self, packet, in_port):
        arp_pkt = packet.payload
        self.arp_cache[arp_pkt.protosrc] = arp_pkt.hwsrc

        if arp_pkt.opcode == arp.REQUEST:
            log.info(
                f"[ARP RX] REQUEST {arp_pkt.hwsrc} -> {arp_pkt.protodst} (port {in_port})")
            if arp_pkt.protodst == PRIVATE_IP or arp_pkt.protodst == PUBLIC_IP:
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = arp_pkt.protodst
                arp_reply.hwsrc = PRIVATE_MAC if arp_pkt.protodst == PRIVATE_IP else PUBLIC_MAC
                arp_reply.protodst = arp_pkt.protosrc
                arp_reply.hwdst = arp_pkt.hwsrc

                eth = ethernet()
                eth.type = ethernet.ARP_TYPE
                eth.src = PRIVATE_MAC if arp_pkt.protodst == PRIVATE_IP else PUBLIC_MAC
                eth.dst = arp_pkt.hwsrc
                eth.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)
                log.info(
                    f"[ARP TX] Reply para {arp_pkt.protodst} a {arp_pkt.hwsrc} (port {in_port})")

        elif arp_pkt.opcode == arp.REPLY:
            log.info(
                f"[ARP RX] REPLY {arp_pkt.hwsrc} -> {arp_pkt.protodst} (port {in_port})")

            # Al recibir reply, procesar pendientes si hay
            if arp_pkt.protosrc in self.pending_events:
                for evt in self.pending_events[arp_pkt.protosrc]:
                    log.info(
                        f"[REENVIO] Procesando paquete pendiente para IP {arp_pkt.protosrc}")
                    self.handle_ip(evt.parsed, evt)
                del self.pending_events[arp_pkt.protosrc]

    def handle_ip(self, packet, event):
        ip_pkt = packet.payload
        transport_pkt = ip_pkt.payload  # Puede ser TCP o UDP

        # Verifica que tenga puertos (es decir, que sea TCP o UDP)
        if not hasattr(transport_pkt, 'srcport') or not hasattr(transport_pkt, 'dstport'):
            return

        eth = packet
        in_port = event.port

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            key = (ip_pkt.srcip, transport_pkt.srcport)
            if key not in self.nat_table:
                self.nat_table[key] = self.next_port
                self.reverse_nat_table[self.next_port] = key
                self.next_port += 1

            self.nat_timestamps[key] = time.time()

            ext_port = self.nat_table[key]
            dst_mac = self.arp_cache.get(ip_pkt.dstip)
            if not dst_mac:
                self.send_arp_request(ip_pkt.dstip)
                self.pending_events.setdefault(
                    ip_pkt.dstip, deque()).append(event)
                log.info(
                    f"[PENDING] Paquete pendiente para IP {ip_pkt.dstip} almacenado")
                return

            log.info(
                f"Paquete desde red privada: {ip_pkt.srcip}:{transport_pkt.srcport} -> {ip_pkt.dstip}:{transport_pkt.dstport} | Protocolo={ip_pkt.protocol}")
            log.info(f"[SNAT] Match: {ip_pkt.srcip}:{transport_pkt.srcport} → {ip_pkt.dstip}:{transport_pkt.dstport} | Set src IP: {PUBLIC_IP}, src port: {ext_port} | MAC: {PUBLIC_MAC} → {dst_mac} | Out: {PUBLIC_PORT}")

            # Instalar flujo SNAT
            fm = of.ofp_flow_mod()
            fm.match.dl_type = 0x800
            fm.match.nw_proto = ip_pkt.protocol  # TCP (6) o UDP (17)
            fm.match.nw_src = ip_pkt.srcip
            fm.match.tp_src = transport_pkt.srcport
            fm.idle_timeout = 60
            fm.hard_timeout = 0
            fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
            fm.actions.append(of.ofp_action_tp_port.set_src(ext_port))
            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            self.connection.send(fm)

            # Instalar flujo SNAT (respuesta)
            fm_back = of.ofp_flow_mod()
            fm_back.match.dl_type = 0x800
            fm_back.match.nw_proto = ip_pkt.protocol
            fm_back.match.nw_dst = PUBLIC_IP
            fm_back.match.tp_dst = ext_port
            fm_back.idle_timeout = 60
            fm_back.hard_timeout = 0
            fm_back.actions.append(of.ofp_action_nw_addr.set_dst(ip_pkt.srcip))
            fm_back.actions.append(
                of.ofp_action_tp_port.set_dst(transport_pkt.srcport))
            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(eth.src))
            fm_back.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(fm_back)

            # Reenviar paquete original (SNAT aplicado)
            ip_pkt.srcip = PUBLIC_IP
            transport_pkt.srcport = ext_port
            eth.src = PUBLIC_MAC
            eth.dst = dst_mac

            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            self.connection.send(msg)

    def send_arp_request(self, ip):
        arp_req = arp()
        arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
        arp_req.prototype = arp_req.PROTO_TYPE_IP
        arp_req.hwlen = 6
        arp_req.protolen = 4
        arp_req.opcode = arp.REQUEST
        arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        arp_req.protodst = ip
        arp_req.hwsrc = PUBLIC_MAC
        arp_req.protosrc = PUBLIC_IP

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = PUBLIC_MAC
        eth.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)

        log.info(f"[ARP TX] Request para {ip}")

    def cleanup_loop(self):
        TIMEOUT = 60
        while True:
            now = time.time()
            to_delete = [key for key,
                         t in self.nat_timestamps.items() if now - t > TIMEOUT]
            for key in to_delete:
                ext_port = self.nat_table.pop(key, None)
                if ext_port:
                    self.reverse_nat_table.pop(ext_port, None)
                    log.info(
                        f"[TIMEOUT] Entrada NAT expirada: {key} → {ext_port}")
                self.nat_timestamps.pop(key, None)
            time.sleep(10)


def launch():
    def start_switch(event):
        log.info(f"Iniciando NAT para switch {event.connection.dpid}")
        NAT(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
