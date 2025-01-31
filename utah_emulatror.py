import random
import louie
from struct import pack
from twisted.internet.protocol import Factory, Protocol, connectionDone
from twisted.internet import reactor, task
from twisted.python import failure

from logger import *
from rtr_state import XPT_UPDATE_SIGNAL, Rtr
from cmd_parser import create_packet, XPT_STATUS, CmdParser


UTAH_SIZE = 10, 10
UTAH_PORT = 5001
MAX_INACTIVITY_TIME = 30

logging.root.setLevel(logging.DEBUG)
log = logging.getLogger("UtahEmulator")


class RCP(Protocol):
    close_task, parser, rtr, addr, _verbosity = None, None, None, None, False

    def connectionMade(self) -> None:
        self.addr = f"{self.transport.getHost().host}:{self.transport.getPeer().port}"
        log.info(f"RCP {self.addr} connected")
        self.close_task = task.LoopingCall(lambda: self.transport.loseConnection())
        self.close_task.start(MAX_INACTIVITY_TIME, now=False)
        self.parser = CmdParser()
        self.parser.pcol = self

    def dataReceived(self, data: bytes) -> None:
        log.debug(f"Received from RCP {self.addr} data: {data}")
        self.close_task.reset()
        try:
            self.parser.do_parse(data)
        except ValueError:
            self.transport.loseConnection()
            log.error(f"RCP {self.addr} wrong data: {data}")

    def xpt_update(self, src_idx, dst_idx, lvl_mask) -> None:
        resp = create_packet(
            cmd=XPT_STATUS,
            dmsg=pack(">HHL", src_idx, dst_idx, lvl_mask)
        )
        log.debug(f"Send to {self.addr} XPT status changed: {resp}")
        self.transport.write(resp)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        self.verbosity = False
        log.info(f"RCP {self.addr} disconnected for reason: {reason.value}")

    @property
    def verbosity(self):
        return self._verbosity

    @verbosity.setter
    def verbosity(self, value):
        if value != self._verbosity:
            self._verbosity = value
            func = louie.connect if value else louie.disconnect
            func(self.xpt_update, signal=XPT_UPDATE_SIGNAL)


def random_change_xpt(rtr):
    src_idx = random.randint(1, UTAH_SIZE[0])
    dst_idx = random.randint(1, UTAH_SIZE[1])
    rtr.set_xpt(src_idx, dst_idx, rtr.lvl_mask)


if __name__ == "__main__":
    log.info(f"Utah Emulator Started - TCP Port:{UTAH_PORT} - RTR Size:{UTAH_SIZE}")
    rtr = Rtr(ninputs=UTAH_SIZE[0], noutputs=UTAH_SIZE[1], levels=16)

    t = task.LoopingCall(random_change_xpt, rtr)
    t.start(5, now=False)

    Factory.protocol = RCP
    Factory.protocol.rtr = rtr
    reactor.listenTCP(UTAH_PORT, Factory())
    reactor.run()
