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
GET_MATRIX_CMD = b"\x12\x16\x00\x00\x00\x04\x00\x00\x00\x00"
STATUS_CMD = b"\x12\x0E\x00\x00\x00\x00"
SOURCE_LIST_CMD = b"\x80\x0D\x00\x00\x00\x01\x00"
DESTINATION_LIST_CMD = b"\x80\x0D\x01\x00\x00\x01\x01"
SET_XTP_CMD_1 = b"\x12\x00\x09\x00\x00\x08\x00\x03\x00\x05\x00\x00\x00\x01"
SET_XTP_CMD_2 = b"\x12\x00\x21\x00\x00\x08\x00\x09\x00\x09\x00\x00\x00\x0F"
WRONG_CMD = b"\x12\x00\x09\x00\x00\x08\x00\x09\x00\x09\x00\x00\x00\x17"

HEADER_LEN, HEADER_STRUCT = 6, ">BBBBH"


class RCPClient(Protocol):
    ping_task = None
    buf = b""

    @staticmethod
    def dmsg_check(chksum: int, dmsg: bytes) -> None:
        if sum(dmsg) & 0xFF != chksum:
            log.error("Parser.Checksum Error")
            raise ValueError

    def connectionMade(self):
        log.info("Connected to Rtr")
        self.ping_task = task.LoopingCall(lambda: self.transport.write(PING_CMD))
        self.ping_task.start(PING_TIME, now=False)
        self.send(VERBOSITY_CMD)

        self.send(GET_MATRIX_CMD)
        self.send(STATUS_CMD)

        self.send(SOURCE_LIST_CMD)
        self.send(DESTINATION_LIST_CMD)

        self.send(SET_XTP_CMD_1)
        self.send(SET_XTP_CMD_2)

        self.send(WRONG_CMD)

    def send(self, data: bytes):
        self.transport.write(data)
        self.ping_task.reset()

    def dataReceived(self, data):
        self.buf += data
        log.debug(f"Buffer state: {self.buf}")

        while len(self.buf) >= HEADER_LEN:
            iface, cmd, chksum, _, dmsg_len = unpack(HEADER_STRUCT, self.buf[:HEADER_LEN])
            if len(self.buf) < (packet_len := HEADER_LEN + dmsg_len):
                break
            dmsg = self.buf[HEADER_LEN: packet_len]
            self.dmsg_check(chksum, dmsg)
            self.buf = self.buf[packet_len:]
            log.info(f"Got command - iface:{iface}, cmd:{cmd}, dmsg:{dmsg}")
            #if func := self.iface_func.get(iface):
            #    func(self, cmd, dmsg)


    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        log.info(f"Connection lost for reason: {reason.value}")


if __name__ == "__main__":
    log.info(f"Utah RCP client")
    ReconnectingClientFactory.maxDelay = 10
    ReconnectingClientFactory.protocol = RCPClient
    reactor.connectTCP("localhost", UTAH_PORT, ReconnectingClientFactory())
    reactor.run()

