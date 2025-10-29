from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
import pox.forwarding.l2_learning as l2_learning
import json

log = core.getLogger()


def _handle_ConnectionUp(event):
    with open("pox/ext/jhonson.json", "r") as f:
        all_sw_rules = json.load(f)

    rules = all_sw_rules.get(str(event.dpid), [])
    log.info(
        f"Switch {event.dpid} conectado. {len(rules)} reglas encontradas.")

    for rule in rules:
        match = of.ofp_match()

        if any(k in rule for k in ("ip_src", "ip_dst", "transport", "port_src", "port_dst")):
            match.dl_type = 0x0800

        for key, value in rule.items():
            if key in ("mac_src", "mac_dst"):
                setattr(match, "dl" + key[3:], EthAddr(value))

            elif key in ("ip_src", "ip_dst"):
                setattr(match, "nw" + key[2:], IPAddr(value))

            elif key == "transport":
                setattr(match, "nw_proto", int(value))

            elif key in ("port_src", "port_dst"):
                setattr(match, "tp" + key[4:], int(value))

            else:
                print("Atributo no soportado para firewall")

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.actions = []  # Drop
        event.connection.send(msg)

        log.info(f"Regla instalada: {rule}")


def launch():
    l2_learning.launch()
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("Controlador con l2_learning + reglas de bloqueo activo.")
