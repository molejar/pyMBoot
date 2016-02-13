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

import os
import sys
from flufl.enum import Enum
from utils import *


# module exceptions

class SRecFileError(Exception):
    '''Base Exception class for SRecFile module'''

    _fmt = 'SRecFile base error'   #: format string

    def __init__(self, msg=None, **kw):
        """Initialize the Exception with the given message.
        """
        self.msg = msg
        for key, value in kw.items():
            setattr(self, key, value)

    def __str__(self):
        """Return the message in this Exception."""
        if self.msg:
            return self.msg
        try:
            return self._fmt % self.__dict__
        except (NameError, ValueError, KeyError):
            e = sys.exc_info()[1]     # current exception
            return 'Unprintable exception %s: %s' % (repr(e), str(e))

class SRecLengthError(SRecFileError):
    _fmt = 'Record at line %(line)d has invalid length'

class SRecAlignError(SRecFileError):
    _fmt = 'Record at line %(line)d has invalid align'

class SRecTypeError(SRecFileError):
    _fmt = 'Record at line %(line)d has invalid record type'

class SRecChecksumError(SRecFileError):
    _fmt = 'Record at line %(line)d has invalid checksum'

class SRecCountError(SRecFileError):
    _fmt = 'Invalid records count: is %(count)d instead %(rcount)d'


# public classes


class SRecFile:

    class __RecordType(Enum):
        HEADER = 0
        DATA = 1
        COUNT = 2
        TERMINATION = 3

    __RecordMark = {
    #  Mark  | Addr Len |  Record Type
        'S0' : (  2,     __RecordType.HEADER ),
        'S1' : (  2,     __RecordType.DATA ),
        'S2' : (  3,     __RecordType.DATA ),
        'S3' : (  4,     __RecordType.DATA ),
        'S5' : (  2,     __RecordType.COUNT ),
        'S7' : (  4,     __RecordType.TERMINATION ),
        'S8' : (  3,     __RecordType.TERMINATION ),
        'S9' : (  2,     __RecordType.TERMINATION ),
    }

    __MIN_RECORD_LEN = 8


    def __init__(self, empty_value=0xFF):
        # public members
        self.header = None
        self.start_addr = 0
        self.jump_addr = 0
        self.data = bytearray()

        # private members
        self.__empty_value = empty_value


    def __del__(self):
        pass


    def __calc_crc(self, data):
        sum = 0

        for position in range(0, len(data), 2):
            current_byte = data[position : position + 2]
            sum += int(current_byte, 16)

        crc = ~(sum & 0xFF) & 0xFF

        return crc


    def __check_crc(self, rec):
        """
            Validate if the checksum of the supplied s-record is valid
            Returns: True if valid, False if not
        """
        state = False
        crc = rec[len(rec)-2:]

        # Strip the original checksum and compare with the computed one
        if self.__calc_crc(rec[2:len(rec) - 2]) == int(crc, 16):
            state = True

        return state

    def __create_header_record(self):
        hval = 'KBOOT' if self.header is None else self.header
        htemp = ''.join('{:02X}'.format(ord(c)) for c in hval)
        record = 'S0{:02X}0000'.format(len(hval) + 2 + 1)
        record += htemp
        record += '{:02X}'.format(self.__calc_crc(record[2:]))
        record += '\r\n'
        return record

    def __create_data_record(self, rtype, addr, data):
        dlen = len(data)
        if rtype == 1:
            record = 'S1{0:02X}{1:04X}'.format(dlen + 2 + 1, addr)
        elif rtype == 2:
            record = 'S2{0:02X}{1:06X}'.format(dlen + 3 + 1, addr)
        else:
            record = 'S3{0:02X}{1:08X}'.format(dlen + 4 + 1, addr)
        record += array_to_string(data, sep='')
        record += '{:02X}'.format(self.__calc_crc(record[2:]))
        record += '\r\n'
        return record

    def __create_count_record(self, count):
        record = 'S503{:04X}'.format(count)
        record += '{:02X}'.format(self.__calc_crc(record[2:]))
        record += '\r\n'
        return record

    def __create_termination_record(self, rtype, jump_addr):
        if rtype == 1:
            record = 'S903{:04X}'.format(jump_addr)
        elif rtype == 2:
            record = 'S804{:06X}'.format(jump_addr)
        else:
            record = 'S705{:08X}'.format(jump_addr)
        record += '{:02X}'.format(self.__calc_crc(record[2:]))
        record += '\r\n'
        return record


    def open(self, file):

        saddr = 0xFFFFFFFF
        count = 0

        with open(file, 'r') as f:
            lnum = 0
            for line in f:
                line = line.strip('\r\n')
                lnum += 1

                if len(line) <= self.__MIN_RECORD_LEN:
                    raise SRecLengthError(line=lnum)

                if len(line) % 2 != 0:
                    raise SRecAlignError(line=lnum)

                if line[0] != 'S':
                    raise SRecTypeError(line=lnum)

                if self.__check_crc(line) is not True:
                    raise SRecChecksumError(line=lnum)

                rec_id = line[0:2]
                rec_len = int(line[2:4], 16) * 2

                if not self.__RecordMark.has_key(rec_id):
                    raise SRecTypeError(line=lnum)

                addr_len = self.__RecordMark[rec_id][0] * 2
                str_addr = line[4:4 + addr_len]

                data_len = rec_len - (addr_len + 2)
                str_data = line[4 + addr_len:4 + addr_len + data_len]

                address = int(str_addr, 16)

                if self.__RecordMark[rec_id][1] == self.__RecordType.HEADER:
                    # Parse SRecord Header
                    count += 1
                    rec_header = [int(str_data[i:i + 2], 16) for i in range(data_len)[::2]]
                    self.header = ''.join(map(chr, rec_header))

                elif self.__RecordMark[rec_id][1] == self.__RecordType.DATA:
                    # Parse SRecord Data
                    count += 1
                    if data_len > 0: # test for empty data
                        rec_data = [int(str_data[i:i + 2], 16) for i in range(data_len)[::2]]

                        if saddr > address:
                            if self.data:
                                empty_bytes = (saddr - address) - len(rec_data)
                                self.data = rec_data + [self.__empty_value]*empty_bytes + self.data
                            else:
                                self.data = rec_data
                            saddr = address

                        elif saddr + len(rec_data) > address:
                            index = address - saddr
                            for val in rec_data:
                                if index >= len(self.data):
                                    self.data += rec_data[index:]
                                    break
                                self.data[index] = val
                                index += 1
                        else:
                            empty_bytes = (address - saddr) - len(self.data)
                            self.data += [self.__empty_value]*empty_bytes + rec_data

                elif self.__RecordMark[rec_id][1] == self.__RecordType.TERMINATION:
                    # Parse SRecord Jump Address and Finish
                    self.jump_addr = address
                    break
                else:
                    # Check SRecord Count
                    if count != address:
                        raise SRecCountError(count=count, rcount=address)

            self.start_addr = saddr


    def save(self, file, rtype=0):

        if not self.data:
            raise IOError('No data to save !')

        dlen = len(self.data)

        if dlen > 0xFFFFFFFF:
            raise OverflowError('Buffer size is to long')
        elif dlen > 0x00FFFFFF:
            srec_type = 3
        elif dlen > 0x0000FFFF:
            srec_type = 2
        else:
            srec_type = 1

        if rtype != 0:
            if rtype < srec_type:
                raise ValueError('Wrong record type')
            else:
                srec_type = rtype

        with open(file, 'w') as f:
            f.write(self.__create_header_record())
            cnt = 1
            offset = 0
            while dlen > 0:
                length = 16
                if dlen < length:
                    length = dlen
                data = self.data[offset:offset+length]
                f.write(self.__create_data_record(srec_type, self.start_addr + offset, data))
                dlen -= length
                offset += length
                cnt += 1
            f.write(self.__create_count_record(cnt))
            f.write(self.__create_termination_record(srec_type, self.jump_addr))
            f.close()

