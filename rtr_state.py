from dataclasses import dataclass
from typing import Any
import louie
from logger import *

XPT_UPDATE_SIGNAL = "XPT_UPDATE"
LEVELS = 32

log = logging.getLogger("RtrState")


class Port:
    inpCount, outCount = 0, 0

    def __init__(self, isinput: bool = True, xpt: Any = None):
        self.xpt = xpt
        self.isinput = isinput
        if isinput:
            self.idx = Port.inpCount
            Port.inpCount += 1
        else:
            self.idx = Port.outCount
            Port.outCount += 1

    def __repr__(self):
        xpt = "" if self.isinput else f", xpt={self.xpt}"
        return f"{type(self).__name__}(idx={self.idx!r}, isinput={self.isinput!r}{xpt})"


@dataclass
class LogicPort:
    name: str
    ports = {}


#pidx - port index
#lidx - logic port index
#lvl - level index

class Rtr:
    fakeInpPort = Port()
    fakeOutPort = Port(isinput=False)

    def __init__(self, ninputs, noutputs, levels=LEVELS):
        self.levels = levels
        self.lvl_mask = sum([1 << x for x in range(levels)])

        inputs = {lvl: [Port() for _ in range(ninputs)] for lvl in range(1, levels + 1)}
        outputs = {lvl: [Port(isinput=False, xpt=self.fakeInpPort) for _ in range(noutputs)]
                   for lvl in range(1, levels + 1)}

        def doLogicPorts(prefix: str, num: int, ports: dict) -> dict:
            logicPorts = {lidx: LogicPort(name=f"{prefix}-{lidx}") for lidx in range(1, num + 1)}
            for lidx, lport in logicPorts.items():
                lport.ports = {lvl: ports[lvl][lidx - 1] for lvl in range(1, LEVELS + 1)}
            return logicPorts

        self.sources = doLogicPorts(prefix="SRC", ports=inputs, num=ninputs)
        self.destinations = doLogicPorts(prefix="DST", ports=outputs, num=noutputs)
        self.logTable(self.stateTable)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(sources={self.sources!r}, destinations={self.destinations!r})"

    @property
    def size(self):
        return len(self.sources), len(self.destinations)

    @property
    def stateTable(self) -> list:
        table = [["Idx", "Name", "Ports"]]
        for lidx in sorted(self.destinations.keys()):
            table.append([lidx, self.destinations[lidx].name, self.destinations[lidx].ports])
        return table

    @staticmethod
    def logTable(table: list):
        log.debug("-" * 20)
        for item in table:
            log.debug(item)
        log.debug("-" * 20)

    def setXpt(self, src_idx: int, dst_idx: int, lvl_mask: int):
        try:
            for lvl in range(1, LEVELS + 1):
                if lvl_mask & (1 << (lvl-1)):
                    self.destinations[dst_idx].ports[lvl].xpt = self.sources[src_idx].ports[lvl]
        except (KeyError, ValueError):
            pass
        else:
            log.info(f"XPT Changed dst_idx:{dst_idx} src_idx:{src_idx} lvl_mask:{lvl_mask}")
            louie.send(XPT_UPDATE_SIGNAL, src_idx=src_idx, dst_idx=dst_idx, lvl_mask=lvl_mask)


