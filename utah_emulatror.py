import random
import louie
from twisted.internet.protocol import Factory, Protocol, connectionDone
from twisted.internet import reactor, task
from twisted.python import failure
from logger import *
from rtr_state import XPT_UPDATE_SIGNAL, Rtr
from cmd_processor import CmdProcessor

UTAH_SIZE = 5, 5
UTAH_PORT = 5001
MAX_INACTIVITY_TIME = 30

logging.root.setLevel(logging.DEBUG)
log = logging.getLogger("UtahMain")


class RCP(Protocol):
    closeTask, cmdProc, rtr, addr, _verbosity = None, None, None, None, False

    def connectionMade(self) -> None:
        self.addr = f"{self.transport.getHost().host}:{self.transport.getPeer().port}"
        log.info(f"RCP {self.addr} connected")
        self.closeTask = task.LoopingCall(self.transport.loseConnection)
        self.closeTask.start(MAX_INACTIVITY_TIME, now=False)
        self.cmdProc = CmdProcessor()
        self.cmdProc.pcol = self

    def dataReceived(self, data: bytes) -> None:
        log.debug(f"Received from RCP {self.addr} data: {data}")
        self.closeTask.reset()
        try:
            self.cmdProc.doParse(data)
        except ValueError:
            self.transport.loseConnection()
            log.error(f"RCP {self.addr} wrong data: {data}")

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        self.verbosity = False
        log.info(f"RCP {self.addr} disconnected for reason: {reason.value}")

    def sendData(self, data: bytes, log_msg: str):
        self.transport.write(data)
        log.debug(f"Send to {self.addr} {log_msg}: {data}")

    @property
    def verbosity(self):
        return self._verbosity

    @verbosity.setter
    def verbosity(self, value):
        if value != self._verbosity:
            self._verbosity = value
            func = louie.connect if value else louie.disconnect
            func(self.cmdProc.xptUpdate, signal=XPT_UPDATE_SIGNAL)


def randomChangeXpt(rtr: Rtr):
    src_idx = random.randint(1, UTAH_SIZE[0])
    dst_idx = random.randint(1, UTAH_SIZE[1])
    rtr.setXpt(src_idx, dst_idx, rtr.lvl_mask)


if __name__ == "__main__":
    log.info(f"Utah Emulator Started - TCP Port:{UTAH_PORT} - RTR Size:{UTAH_SIZE}")

    Factory.protocol = RCP
    Factory.protocol.rtr = Rtr(ninputs=UTAH_SIZE[0], noutputs=UTAH_SIZE[1], levels=32)
    reactor.listenTCP(UTAH_PORT, Factory())

    t = task.LoopingCall(randomChangeXpt, Factory.protocol.rtr)
    t.start(5, now=False)

    reactor.run()
