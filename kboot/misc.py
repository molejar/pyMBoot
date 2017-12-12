# Copyright 2016 Martin Olejar
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

from string import printable


def atos(data, sep=' ', fmt='02X'):
    """ Convert array of bytes to String
    """
    ret = ''
    for x in data:
        if fmt == 'c' and x not in printable.encode():
            ret += '.'
            continue
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