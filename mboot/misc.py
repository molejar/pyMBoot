# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

from string import printable


def size_fmt(num, kibibyte=True):
    base, suffix = [(1000., 'B'), (1024., 'iB')][kibibyte]
    for x in ['B'] + [x + suffix for x in list('kMGTP')]:
        if -base < num < base:
            break
        num /= base

    return "{} {}".format(num, x) if x == 'B' else "{:3.1f} {}".format(num, x)


def atos(data, separator=' ', fmt='02X'):
    """ Convert array of bytes to string
    :param data: Data in bytes or bytearray type
    :param separator: String separator
    :param fmt: String format
    :return string
    """
    ret = ''
    for x in data:
        if fmt == 'c' and x not in printable.encode():
            ret += '.'
            continue
        ret += ('{:'+fmt+'}').format(x)
        ret += separator
    return ret


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
