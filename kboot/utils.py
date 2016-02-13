# Copyright 2015 Martin Olejar
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__all__    = ["long_to_array",
              "string_to_array",
              "array_to_long",
              "array_to_string",
              "crc16"]


def long_to_array(value, length, endian='little'):
    """
    Convert Long value into array of bytes
    :rtype: array
    """
    buf = bytearray(length)
    for n in range(length):

        if endian == 'little':
            shift = 8 * n
        else:
            shift = 8 * ((length - 1) - n)

        buf[n] = (value >> shift) & 0xff

    return buf

def string_to_array(strval, chlen, format=0, test_align=True):
    """
    Convert string value into array of bytes
    :rtype: Long
    """
    array_len = len(strval)/chlen
    if test_align and len(strval) % chlen:
        raise Exception("string not aligned by chlen")

    buf = bytearray(array_len)
    for i in range(array_len):
        ch = strval[i*chlen:i*chlen+chlen]
        if format == 2 or format == 10 or format == 16:
            buf[i] = int(ch, format)
        else:
            buf[i] = ord(ch)
    return buf


def array_to_long(data, endian='little'):
    """
    Convert array of bytes into Long value
    :rtype: Long
    """
    ret = 0
    for n in range(len(data)):
        if endian == 'little':
            ret |= (data[n] << (n * 8))
        else:
            ret |= (data[n] << (8 * ((len(data) - 1) - n)))

    return ret


def array_to_string(data, sep=' ', fmt='02X'):
    """
    Convert array of bytes into HEX String
    :rtype: String
    """
    ret = ''
    for x in data:
        if fmt == 'c':
            if 0x00 < x < 0x7F:
                ret += ('{:'+fmt+'}').format(x)
            else:
                ret += '.'
        else:
            ret += ('{:'+fmt+'}').format(x)
        ret += sep
    return ret


def crc16(data, crc_init=0):
    """
    Calculate CRC from input data
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