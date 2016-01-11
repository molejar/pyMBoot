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
              "array_to_long",
              "array_to_string"]


def long_to_array(value, length, little_endian=True):
    """
    Convert Long value into array of bytes
    :rtype: array
    """
    buf = []
    for n in range(length):

        if little_endian:
            shift = 8 * n
        else:
            shift = 8 * ((length - 1) - n)

        buf.append((value >> shift) & 0xff)

    return buf


def array_to_long(data, little_endian=True):
    """
    Convert array of bytes into Long value
    :rtype: Long
    """
    ret = 0
    for n in range(len(data)):

        if little_endian:
            ret |= data[n] << (n * 8)
        else:
            ret |= data[n] << 8 * ((len(data) - 1) - n)

    return ret


def array_to_string(data, sep=' '):
    """
    Convert array of bytes into HEX String
    :rtype: String
    """
    ret = ''.join('{0:02X}{1}'.format(x, sep) for x in data)
    return ret