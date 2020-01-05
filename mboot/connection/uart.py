# Copyright (c) 2017 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


import sys
import glob
import serial
from time import time
from struct import pack, unpack_from
from .base import DevConnBase


def crc16(data, crc_init=0):
    """ Calculate 16-bit CRC from input data
    :param data:
    :param crc_init: Initialization value
    :rtype: int value
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


def scan_uart(port):
    raise NotImplemented("Function is not implemented")


########################################################################################################################
# UART Interface Class
########################################################################################################################
class FPType:
    # MBoot Framing Packet Type.
    ACK = 0xA1
    NACK = 0xA2
    ABORT = 0xA3
    CMD = 0xA4
    DATA = 0xA5
    PING = 0xA6
    PINGR = 0xA7


class Uart(DevConnBase):

    @property
    def is_opened(self):
        return False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def open(self, port=None):
        pass

    def close(self):
        pass

    def info(self):
        pass

    def read(self, timeout=1000, length=None, cmd=False):
        pass

    def write(self, data, cmd=False):
        pass


