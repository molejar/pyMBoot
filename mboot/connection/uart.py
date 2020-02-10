# Copyright (c) 2020 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


import logging
from time import time
from easy_enum import Enum
from struct import pack, unpack_from
from serial import Serial
from serial.tools.list_ports import comports
from .base import DevConnBase
from ..commands import CmdPacket, CmdResponse, parse_cmd_response


logger = logging.getLogger('MBOOT:UART')


########################################################################################################################
# Helper Methods
########################################################################################################################

def crc16(data: bytes, crc_init: int = 0) -> int:
    """
    Calculate 16-bit CRC from input data

    :param data: Input data
    :param crc_init: Initialization value
    """
    crc = crc_init
    for c in data:
        crc ^= c << 8
        for _ in range(8):
            temp = crc << 1
            if crc & 0x8000:
                temp ^= 0x1021
            crc = temp
    return crc


########################################################################################################################
# UART Packet
########################################################################################################################

class FPT(Enum):
    # Framing Packet Type.
    ACK = (0xA1, 'ACK', 'The previous packet was received successfully')
    NAK = (0xA2, 'NAK', 'The previous packet was corrupt and must be re-sent')
    ABORT = (0xA3, 'AckAbort', 'The data phase is being aborted')
    CMD = (0xA4, 'Command', 'The command packet payload')
    DATA = (0xA5, 'Data', 'The data packet payload')
    PING = (0xA6, 'Ping', 'Verify that the other side is alive')
    RESP = (0xA7, 'PingResp', 'A response to Ping')


class UartPacket:

    START_BYTE = 0x5A

    def __init__(self, fp_type: int, data: bytes = None):
        self.fp_type = fp_type
        self.data = data

    def to_bytes(self) -> bytes:
        raw_data = pack('2B', self.START_BYTE, self.fp_type)
        if self.data is None:
            raw_data += b'\x00\x00'
            crc = crc16(raw_data)
            raw_data += pack('<H', crc)
        else:
            raw_data += pack('<H', len(self.data))
            crc = crc16(raw_data + bytes(self.data))
            raw_data += pack('<H', crc) + bytes(self.data)
        return raw_data


########################################################################################################################
# Scan UART method
########################################################################################################################

def scan_uart(port=None):
    """
    Scan for connected devices

    :param port: The serial port name Windows (COM<X>), Linux (/dev/tty<XX>) or None
    """
    devices = []
    ports = comports()

    if port:
        ports = [p for p in ports if p.device == port]

    for p in ports:
        dev = Uart(p)
        # TODO: Check connection
        devices.append(dev)

    return devices


########################################################################################################################
# UART Interface Class
########################################################################################################################

class Uart(DevConnBase):

    @property
    def is_opened(self):
        return self._ser.is_open

    def __init__(self, port, baudrate=115200, **kwargs):
        super().__init__(**kwargs)
        self._ser = Serial(baudrate=baudrate, timeout=0.5)
        self._ser.port = port

    def _send_ufp(self, ufp: UartPacket):
        self._ser.write(ufp.to_bytes())

    def open(self):
        self._ser.open()

    def close(self):
        self._ser.close()

    def abort(self):
        if self._ser.is_open:
            self._send_ufp(UartPacket(FPT.ABORT))

    def info(self):
        pass

    def read(self, timeout=1000):
        """
        Read data from UART

        :param timeout:
        """
        raise NotImplementedError()

    def write(self, packet):
        """
        Write data to UART

        :param packet: Command or Data packet
        """
        if isinstance(packet, CmdPacket):
            uart_packet = UartPacket(FPT.CMD, packet.to_bytes())
        elif isinstance(packet, (bytes, bytearray)):
            uart_packet = UartPacket(FPT.DATA, packet)
        else:
            raise Exception()

        data = uart_packet.to_bytes()
