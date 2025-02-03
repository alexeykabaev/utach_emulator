from struct import unpack
from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone, ReconnectingClientFactory
from twisted.python import failure
from logger import *

log = logging.getLogger("RcpClient")

UTAH_PORT = 5001
PING_TIME = 15
PING_CMD = b"\x03\xFE\x00\x00\x00\x00"
VERBOSITY_CMD = b"\x04\x00\x02\x00\x00\x02\x00\x02"
GET_MATRIX_CMD = b"\x12\x16\x04\x00\x00\x04\x00\x01\x00\x03"
STATUS_SIZE_CMD = b"\x12\x0E\x00\x00\x00\x00"
STATUS_DUMP_CMD = b"\x12\x40\x00\x00\x00\x00"
SOURCE_LIST_CMD = b"\x80\x0D\x00\x00\x00\x01\x00"
DESTINATION_LIST_CMD = b"\x80\x0D\x01\x00\x00\x01\x01"
SET_XTP_CMD_1 = b"\x12\x00\x09\x00\x00\x08\x00\x03\x00\x05\x00\x00\x00\x01"
SET_XTP_CMD_2 = b"\x12\x00\x21\x00\x00\x08\x00\x09\x00\x09\x00\x00\x00\x0F"
WRONG_CMD = b"\x12\x00\x09\x00\x00\x08\x00\x09\x00\x09\x00\x00\x00\x17"

HEADER_LEN, HEADER_STRUCT = 6, ">BBBBH"


class RCPClient(Protocol):
    pingTask = None
    buf = b""

    @staticmethod
    def dmsgCheck(chksum: int, dmsg: bytes) -> None:
        if sum(dmsg) & 0xFF != chksum:
            log.error("Parser.Checksum Error")
            raise ValueError

    def connectionMade(self):
        log.info("Connected to Rtr")
        self.pingTask = task.LoopingCall(self.transport.write, PING_CMD)
        self.pingTask.start(PING_TIME, now=False)
        self.sendData(VERBOSITY_CMD)

        self.sendData(GET_MATRIX_CMD)
        self.sendData(STATUS_SIZE_CMD)

        self.sendData(SOURCE_LIST_CMD)
        self.sendData(DESTINATION_LIST_CMD)

        self.sendData(SET_XTP_CMD_1)
        self.sendData(SET_XTP_CMD_2)

        self.sendData(WRONG_CMD)

        self.sendData(STATUS_DUMP_CMD)

    def sendData(self, data: bytes):
        self.transport.write(data)
        self.pingTask.reset()

    def dataReceived(self, data):
        self.buf += data
        log.debug(f"Buffer state: {self.buf}")

        while len(self.buf) >= HEADER_LEN:
            iface, cmd, chksum, _, dmsgLen = unpack(HEADER_STRUCT, self.buf[:HEADER_LEN])
            if len(self.buf) < (packetLen := HEADER_LEN + dmsgLen):
                break
            dmsg = self.buf[HEADER_LEN: packetLen]
            self.dmsgCheck(chksum, dmsg)
            self.buf = self.buf[packetLen:]
            log.info(f"Got command - iface:{iface}, cmd:{cmd}, dmsg:{dmsg}")

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        log.info(f"Connection lost for reason: {reason.value}")


if __name__ == "__main__":
    log.info(f"Utah RCP client")
    ReconnectingClientFactory.maxDelay = 10
    ReconnectingClientFactory.protocol = RCPClient
    reactor.connectTCP("localhost", UTAH_PORT, ReconnectingClientFactory())
    reactor.run()

