from dataclasses import dataclass
from typing import Any
import louie
from logger import *

XPT_UPDATE_SIGNAL = "XPT_UPDATE"
LEVELS = 32

log = logging.getLogger("RtrState")
#log.setLevel(logging.INFO)


@dataclass
class Port:
    idx: int
    isinput: bool = True
    xpt: Any = None


@dataclass
class LogicPort:
    name: str
    ports = {i+1: None for i in range(LEVELS)}


class Rtr:
    NotConnectedPort = Port(idx=0)

    def __init__(self, ninputs, noutputs, levels=LEVELS):
        self.levels = levels
        self.lvl_mask = sum([1 << x for x in range(levels)])
        inputs, outputs, i, o = {}, {}, 1, 1
        for lvl in range(1, levels+1):
            inputs[lvl] = [Port(idx=idx+i) for idx in range(ninputs)]
            outputs[lvl] = [Port(idx=idx+o, isinput=False, xpt=self.NotConnectedPort) for idx in range(noutputs)]
            i += ninputs
            o += noutputs

        def do_logic_ports(prefix: str, num: int, physic_ports: dict) -> dict:
            logic_ports = {}
            for idx in range(1, num+1):
                lport = LogicPort(name=f"{prefix}-{idx}")
                lport.ports = dict.copy(lport.ports)
                for lvl in range(1, levels+1):
                    lport.ports[lvl] = physic_ports[lvl][idx-1]
                logic_ports[idx] = lport
            return logic_ports

        self.sources = do_logic_ports(prefix="SRC", num=ninputs, physic_ports=inputs)
        self.destinations = do_logic_ports(prefix="DST", num=noutputs, physic_ports=outputs)
        self.log_table(self.state_table)

    def __repr__(self) -> str:
        return "%s(sources=%r, destinations=%r)" % (
            self.__class__, self.sources, self.destinations)

    @property
    def size(self):
        return self.sources.__len__(), self.destinations.__len__()

    @property
    def state_table(self) -> list:
        table = [["Idx", "Label", "Ports"]]
        for dst_idx in sorted(self.destinations.keys()):
            table.append([dst_idx, self.destinations[dst_idx].name, self.destinations[dst_idx].ports])
        return table

    @staticmethod
    def log_table(table):
        log.debug("-" * 20)
        for item in table:
            log.debug(item)
        log.debug("-" * 20)

    def set_xpt(self, src_idx, dst_idx, lvl_mask):
        try:
            for lvl in range(LEVELS):
                if lvl_mask & (1 << lvl):
                    self.destinations[dst_idx].ports[lvl+1].xpt = self.sources[src_idx].ports[lvl+1]
        except [KeyError, ValueError]:
            pass
        else:
            log.info("XPT Changed dst_idx:%r src_idx:%r lvl_mask:%r", dst_idx, src_idx, lvl_mask)
            louie.send(XPT_UPDATE_SIGNAL, src_idx=src_idx, dst_idx=dst_idx, lvl_mask=lvl_mask)

