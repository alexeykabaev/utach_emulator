"""
SC-4 IP Port=5001

Packet Format:
Packet Header(6 bytes), Block of Data

Packet Header:
Interface, Command/Status Type, Data Checksum, 0x00, data length (bits 15-8), data length (bits 7-0)
Data Checksum is a simple byte sum of the data that follows the header.
Data Length is simply the number of bytes of data that follow the header.

Interface in the packet header is 0x12.
Interface for ping command is 0x02.

PING Command: 0x03,0xFE,0x00,0x00,0x00,0x00
PING Response: 0x03,0xFD,0x07,0x00,0x00,0x01,0x07

VERBOSITY Command: 0x04,0x00,0x02,0x00,0x00,0x02,0x00,0x02 or 0x04,0x00,0x00,0x00,0x00,0x02,0x00,0x00
VERBOSITY Response: 0x04,0x01,0x02,0x00,0x00,0x02,0x00,0x02 or 0x04,0x01,0x00,0x00,0x00,0x02,0x00,0x00

TAKE Command: 0x12,0x00,0xcs,0x00,0x00,0x08,(src & 0xFFFF),(dst & 0xFFFF),(lvl & 0xFFFFFFFF)
TAKE Response: 0x12,0x01,0xcs,0x00,0x00,0x08,(src & 0xFFFF),(dst & 0xFFFF),(lvl & 0xFFFFFFFF)
TAKE Status: 0x12,0x5F,0xcs,0x00,0x00,0x08,(src & 0xFFFF),(dst & 0xFFFF),(lvl & 0xFFFFFFFF)

GET Matrix Command: 0x12,0x16,(chksum & 0xFF),0x00,0x00,0x04,(dst & 0xFFFF),(num & 0xFFFF)
GET Matrix Response: 0x12,0x17,(chksum & 0xFF),0x00,(len & 0xFFFF),(dst & 0xFFFF),(src_lvl1 & 0xFFFF),(src_lvl2 & 0xFFFF),...

Get Source List Command: 0x80,0x0D,0x00,0x00,0x00,0x01,0x00
Get Destination List Command: 0x80,0x0D,0x01,0x00,0x00,0x01,0x01

Status Command: 0x12,0x0E,0x00,0x00,0x00,0x00
Status Response: 0x12,0x0F,(chksum & 0xFF),0x00,0x00,0x04,(src_num & 0xFFFF),(dst_dst & 0xFFFF)

CHECK
Ping:               03 FE 00 00 00 00
Verbosity:          04 00 02 00 00 02 00 02
Status Size:        12 0E 00 00 00 00
Status Dump:        12 40 00 00 00 00
Source List:        80 0D 00 00 00 01 00
Destination List:   80 0D 01 00 00 01 01
Set XTP:            12 00 09 00 00 08 00 03 00 05 00 00 00 01
GET Matrix:         12 16 06 00 00 04 00 05 00 01
GET Matrix:         12 16 00 00 00 04 00 00 00 00

"""

from logger import *
from struct import pack, unpack

HEADER_LEN, HEADER_STRUCT = 6, ">BBBBH"
PING, VERBOSITY, ERROR, DEFAULT, NAME = 0x03, 0x04, 0x07, 0x12, 0x80
PING_CMD, PING_RESP, PING_DATA = 0xFE, 0xFD, b"\x07"
VERBOSITY_CMD, VERBOSITY_RESP = 0x00, 0x01
XPT_CMD, XPT_RESP, XPT_STATUS = 0x00, 0x01, 0x5F
NAME_DST_DONE, NAME_SRC_DONE = 0x26, 0x27
NAME_CMD, NAME_RESP = 0x0D, 0x0E
STATUS_SIZE_CMD, STATUS_SIZE_RESP = 0x0E, 0x0F
STATUS_DUMP_CMD, STATUS_DUMP_RESP, STATUS_DUMP_END = 0x40, 0x41, 0x42
MATRIX_CMD, MATRIX_RESP = 0x16, 0x17

log = logging.getLogger("CmdProc_")


def createPacket(cmd: int, iface=DEFAULT, dmsg=b""):
    return pack(HEADER_STRUCT, iface, cmd, sum(dmsg) & 0xFF, 0, len(dmsg)) + dmsg


class CmdProcessor:
    buf = b""
    pcol = None

    @staticmethod
    def pingIFace(obj, cmd, dmsg):
        log.debug(f"PING - cmd: {cmd}, dmsg: {dmsg}")
        if cmd == PING_CMD:
            # ping response = b"\x03\xFD\x07\x00\x00\x01\x07"

            resp = createPacket(iface=PING, cmd=PING_RESP, dmsg=PING_DATA)
            obj.pcol.sendData(data=resp, log_msg="Response Ping")

    @staticmethod
    def errorIFace(obj, cmd, dmsg):
        log.debug(f"ERROR - cmd: {cmd}, dmsg: {dmsg}")

    @staticmethod
    def verbosityIFace(obj, cmd, dmsg):
        log.debug(f"VERBOSITY - cmd: {cmd}, dmsg: {dmsg}")
        if cmd == VERBOSITY_CMD:
            obj.pcol.verbosity = unpack(">H", dmsg)[0] == 2
            # verbosity response = b"\x04\x01\x__\x00\x00\x02\x00\x__"

            resp = createPacket(iface=VERBOSITY, cmd=VERBOSITY_RESP, dmsg=dmsg)
            obj.pcol.sendData(data=resp, log_msg="Response Verbosity")

    @staticmethod
    def defaultIFace(obj, cmd, dmsg):
        log.debug(f"DEFAULT - cmd: {cmd}, dmsg: {dmsg}")
        if cmd == XPT_CMD:
            src_idx, dst_idx, lvl_mask = unpack(">HHL", dmsg[0:8])
            log.debug(f"Command Set Xpt src_idx:{src_idx}, dst_idx:{dst_idx}, lvl_mask:{lvl_mask}")

            resp = createPacket(cmd=XPT_RESP, dmsg=dmsg)
            obj.pcol.sendData(data=resp, log_msg="Response XPT")

            obj.pcol.rtr.setXpt(src_idx, dst_idx, lvl_mask)

        elif cmd == MATRIX_CMD:
            dst_idx, dst_num = unpack(">HH", dmsg[:4])
            dst_idx = dst_idx if dst_idx else 1
            log.debug(f"Command Get Matrix dst_idx:{dst_idx}, dst_num:{dst_num}")

            for idx in range(dst_idx, dst_num + dst_idx if dst_num else 0xFFFF):
                try:
                    data = b"".join([pack(">H", obj.pcol.rtr.destinations[idx].ports[lvl].xpt.idx)
                                     for lvl in range(1, obj.pcol.rtr.levels + 1)])

                    resp = createPacket(cmd=MATRIX_RESP, dmsg=pack(">HH", idx, 1) + data)
                    obj.pcol.sendData(data=resp, log_msg="Response Get Matrix")

                except KeyError:
                    break

        elif cmd == STATUS_DUMP_CMD:
            log.debug(f"Command Get Status Dump")
            for idx in range(1, 0xFFFF):
                try:
                    data = b"".join([pack(">H", obj.pcol.rtr.destinations[idx].ports[lvl].xpt.idx)
                                     for lvl in range(1, obj.pcol.rtr.levels + 1)])

                    resp = createPacket(cmd=STATUS_DUMP_RESP, dmsg=pack(">HH", idx, 1) + data)
                    obj.pcol.sendData(data=resp, log_msg="Response Get Status Dump")

                except KeyError:
                    break

            resp = createPacket(cmd=STATUS_DUMP_END)
            obj.pcol.sendData(data=resp, log_msg="Response Get Status Dump End")

        elif cmd == STATUS_SIZE_CMD:
            log.debug(f"Command Status Size")

            resp = createPacket(cmd=STATUS_SIZE_RESP, dmsg=pack(">HH", *obj.pcol.rtr.size))
            obj.pcol.sendData(data=resp, log_msg="Response Status Size")

    @staticmethod
    def nameIFace(obj, cmd, dmsg):
        log.debug(f"NAME - cmd: {cmd}, dmsg: {dmsg}")
        if cmd == NAME_CMD:

            dev_type, logic_ports, end_cmd = (0, obj.pcol.rtr.sources, NAME_SRC_DONE) \
                if dmsg[0] else (1, obj.pcol.rtr.destinations, NAME_DST_DONE)

            for logic_port_idx, logic_port in logic_ports.items():
                data = b"".join([pack(">H", port.idx if port else 0) for _, port in sorted(logic_port.ports.items())])
                resp = createPacket(
                    iface=NAME,
                    cmd=NAME_RESP,
                    dmsg=pack(">HH8sL", dev_type, logic_port_idx, logic_port.name.encode(), 0) + data
                )
                obj.pcol.sendData(data=resp, log_msg="Response Logic Port Name")

            resp = createPacket(iface=NAME, cmd=end_cmd)
            obj.pcol.sendData(data=resp, log_msg="Response Logic Port Name End")

    iface_func = {PING: pingIFace.__func__, ERROR: errorIFace.__func__, VERBOSITY: verbosityIFace.__func__,
                  DEFAULT: defaultIFace.__func__, NAME: nameIFace.__func__, }

    @staticmethod
    def dmsgCheck(chksum: int, dmsg: bytes) -> None:
        if sum(dmsg) & 0xFF != chksum:
            raise ValueError

    def xptUpdate(self, src_idx, dst_idx, lvl_mask) -> None:
        resp = createPacket(cmd=XPT_STATUS, dmsg=pack(">HHL", src_idx, dst_idx, lvl_mask))
        self.pcol.sendData(data=resp, log_msg="XPT status changed")

    def doParse(self, data) -> None:
        self.buf += data
        log.debug(f"Buffer state: {self.buf}")

        while len(self.buf) >= HEADER_LEN:
            iface, cmd, chksum, _, dmsgLen = unpack(HEADER_STRUCT, self.buf[:HEADER_LEN])
            if len(self.buf) < (packetLen := HEADER_LEN + dmsgLen):
                break
            dmsg = self.buf[HEADER_LEN: packetLen]
            self.buf = self.buf[packetLen:]
            try:
                self.dmsgCheck(chksum, dmsg)
            except ValueError:
                log.error(f"Checksum Error - iface:{iface}, cmd:{cmd}, chksum:{chksum}, len:{dmsgLen}, dmsg:{dmsg}")
                continue
            log.debug(f"Got command - iface:{iface}, cmd:{cmd}, dmsg:{dmsg}")
            if func := self.iface_func.get(iface):
                func(self, cmd, dmsg)
