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

import sys


# module exceptions
# --------------------------------------------------------------------
class SRecError(Exception):
    '''Base Exception class for SRecFile module'''

    _fmt = 'SRecFile base error'  #: format string

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
            e = sys.exc_info()[1]  # current exception
            return 'Unprintable exception %s: %s' % (repr(e), str(e))


class SRecLengthError(SRecError):
    _fmt = 'Record at line: %(line)d has invalid length'


class SRecAlignError(SRecError):
    _fmt = 'Record at line: %(line)d has invalid align'


class SRecMarkError(SRecError):
    _fmt = 'Record at line: %(line)d has invalid mark: %(mark)s'


class SRecChecksumError(SRecError):
    _fmt = 'Record at line: %(line)d has invalid checksum'


class SRecCountError(SRecError):
    _fmt = 'File has invalid records count: %(count)d instead %(rcount)d'


# public classes
# -----------------------------------------------------------------------
class SRecFile(object):
    _RecordType = {
        'HEADER': 0,
        'DATA': 1,
        'COUNT': 2,
        'TERMINATION': 3
    }

    _RecordMark = {
        # ID | Addr Len | Record Type
        'S0': (2, _RecordType['HEADER']),
        'S1': (2, _RecordType['DATA']),
        'S2': (3, _RecordType['DATA']),
        'S3': (4, _RecordType['DATA']),
        'S5': (2, _RecordType['COUNT']),
        'S7': (4, _RecordType['TERMINATION']),
        'S8': (3, _RecordType['TERMINATION']),
        'S9': (2, _RecordType['TERMINATION']),
    }

    _MIN_RECORD_LEN = 10
    _MAX_RAW_DATA_LEN = 16
    _LINE_TERMINATION = '\n'

    def __init__(self, saddr=0, data=None, header=None, jump=0, empty_value=0xFF):
        # public members
        self.header = header
        self.start_address = saddr
        self.jump_address = jump
        self.data = data
        self.empty_value = empty_value

    def __str__(self):
        return '< %s, 0x%X @ %d Bytes, EmptyValue: 0x%02X >' % (self.header or '...',
                                                                self.start_address,
                                                                self.size,
                                                                self.empty_value)

    def __repr__(self):
        return str(self)

    def __contains__(self, address):
        return self.start_address <= address <= self.end_address

    def __getitem__(self, address):
        if isinstance(address, slice):
            start = address.start or self.start_address
            stop  = address.stop or self.end_address + 1
            step  = address.step

            if start not in self or stop - 1 not in self:
                raise IndexError('Address out of range 0x%08X - 0x%08X' % (self.start_address, self.end_address))

            d = self.data[start - self.start_address:stop - self.start_address:step]
            return SRecFile(saddr=start, data=d, header=self.header, jump=self.jump_address, empty_value=self.empty_value)
        else:
            if not address in self:
                raise IndexError('Address 0x%08X out of range 0x%08X - 0x%08X' % (address,
                                                                                  self.start_address,
                                                                                  self.end_address))
            return self.data[address - self.start_address]

    def __setitem__(self, address, value):
        if not isinstance(address, int):
            raise IndexError('Index must be integer value: %r' % address)
        if not address in self:
            raise IndexError('Address 0x%08X out of range 0x%08X - 0x%08X' % (address, self.start_address, self.end_address))
        if not 0x00 <= value <= 0xFF:
            raise ValueError('Value must be in range 0x00 - 0xFF: 0x%X' % value)
        self.data[address - self.start_address] = value

    def __len__(self):
        return self.size

    def __iter__(self):
        return iter(zip(range(self.start_address, self.end_address + 1), self.data))

    def _calc_crc(self, recnocrc):
        """ SREC: Returns checksum of specified data
        :param recnocrc: Record string without crc
        :return: crc value
        """
        rdata = [int(recnocrc[i:i+2], 16) for i in range(2, len(recnocrc), 2)]
        crc = ~(sum(rdata) & 0xFF) & 0xFF
        return crc

    def _check_crc(self, record):
        """ SREC: Validate if the checksum of the supplied record is valid
        :param record: Record string with crc
        :return: True if valid, False if not
        """
        orig_crc = int(record[-2:], 16)
        calc_crc = self._calc_crc(record[:-2])
        return orig_crc == calc_crc

    def _create_header_record(self):
        """ SREC: Returns header record line
        :return {str} Record line
        """
        hval = self.header or 'S-REC'
        record = 'S0{:02X}0000'.format(len(hval) + 2 + 1)
        record += ''.join('{:02X}'.format(ord(c)) for c in hval)
        record += '{:02X}'.format(self._calc_crc(record))
        record += self._LINE_TERMINATION
        return record

    def _create_data_record(self, rtype, addr, data):
        """ SREC: Returns data record line
        :param rtype: Record Type 0 - auto, 1 - 16bit, 2 - 24bit, 3 - 32bit
        :param addr:  The value of address
        :param data:  The data array
        :return {str} Record line
        """
        alen = rtype + 1
        dlen = len(data)
        record = ('S{0:d}{1:02X}{2:0'+str(alen*2)+'X}').format(rtype, dlen + alen + 1, addr)
        record += ''.join('{:02X}'.format(x) for x in data)
        record += '{:02X}'.format(self._calc_crc(record))
        record += self._LINE_TERMINATION
        return record

    def _create_count_record(self, count):
        """ SREC: Returns count record line
        :param count: The count value of all data records
        :return {str} Record line
        """
        record = 'S503{:04X}'.format(count)
        record += '{:02X}'.format(self._calc_crc(record))
        record += self._LINE_TERMINATION
        return record

    def _create_termination_record(self, rtype, jump_addr):
        """ SREC: Returns termination record line
        :param rtype: Record Type 0 - auto, 1 - 16bit, 2 - 24bit, 3 - 32bit
        :param jump_addr: The value of jump address
        :return {str} Record line
        """
        alen = rtype + 1
        record = ('S{0:d}{1:02X}{2:0'+str(alen*2)+'X}').format(10 - rtype, alen + 1, jump_addr)
        record += '{:02X}'.format(self._calc_crc(record))
        record += self._LINE_TERMINATION
        return record

    @property
    def size(self):
        return 0 if not self.data else len(self.data)

    @property
    def end_address(self):
        return self.start_address if self.size == 0 else self.start_address + self.size - 1

    def insert_data(self, address, data):
        """ SREC: Insert data at specific address
        :param address: start address
        :param data:
        """
        assert type(data) is list or bytearray, "data is not an list or bytearray: %r" % data

        if isinstance(data, list):
            data = bytearray(data)

        if not self.data:
            self.start_address = address
            self.data = data
            return

        if address < self.start_address:
            offset = address + len(data)
            if offset <= self.start_address:
                empty_data = bytearray([self.empty_value] * (self.start_address - offset))
                if empty_data: data += empty_data
                self.data = data + self.data
                self.start_address = address
                return
            else:
                self.data = data[:-(offset - self.start_address)] + self.data
                data = data[-(offset - self.start_address):]
                address, self.start_address = self.start_address, address

        if self.start_address <= address <= self.end_address:
            index = address - self.start_address
            for i in range(len(data)):
                if index >= self.size:
                    data = data[-i:]
                    address = self.end_address + 1
                    break
                self.data[index] = data[i]
                index += 1

        if address > self.end_address:
            empty_data = bytearray([self.empty_value] * (address - (self.end_address + 1)))
            if empty_data: self.data += empty_data
            self.data += data

    def open(self, file, empty_value=None):
        """ SREC: Open and load content of S-Record file into internal buffer
        :param file: Path to SRecord file
        """
        count = 0
        self.data = None

        if empty_value:
            self.empty_value = empty_value

        with open(file, 'r') as f:
            lnum = 0
            for line in f:
                lnum += 1
                line = line.strip()
                if not line.startswith('S'):
                    continue

                if len(line) < self._MIN_RECORD_LEN:
                    raise SRecLengthError(line=lnum)

                if len(line) % 2 != 0:
                    raise SRecAlignError(line=lnum)

                if self._check_crc(line) is not True:
                    raise SRecChecksumError(line=lnum)

                rec_id = line[0:2]
                rec_len = int(line[2:4], 16) * 2

                if not rec_id in self._RecordMark:
                    raise SRecMarkError(line=lnum, mark=rec_id)

                addr_len = self._RecordMark[rec_id][0] * 2
                data_len = rec_len - (addr_len + 2)

                address = int(line[4:4 + addr_len], 16)
                data_st = 4 + addr_len

                if data_len > 0:
                    rec_data = [int(line[data_st + i:data_st + i + 2], 16) for i in range(0, data_len, 2)]

                if self._RecordMark[rec_id][1] == self._RecordType['HEADER']:
                    # Parse SRecord Header
                    if data_len == 0: raise SRecLengthError(line=lnum)
                    self.header = ''.join(map(chr, rec_data))
                    count += 1
                elif self._RecordMark[rec_id][1] == self._RecordType['DATA']:
                    # Insert SRecord Data
                    if data_len == 0: raise SRecLengthError(line=lnum)
                    self.insert_data(address, rec_data)
                    count += 1
                elif self._RecordMark[rec_id][1] == self._RecordType['TERMINATION']:
                    # Parse SRecord Jump Address and Finish
                    self.jump_address = address
                    break
                else:
                    # Check SRecord Count
                    if count != address:
                        raise SRecCountError(count=count, rcount=address)

    def save(self, file, wrap=False, rtype=0, rcnt=False, rterm=True):
        """ SREC: Save content of internal buffer into S-Record file
        :param file:  Path to S-Record file
        :param wrap:  Compress the output file (remove empty records)
        :param rtype: Record Type 0 - auto, 1 - 16bit, 2 - 24bit, 3 - 32bit
        :param rcnt:  Add Count Record (True/False)
        :param rterm: Add Termination Record (True/False)
        """
        if not self.data:
            raise SRecError('No data to save !')

        dlen = len(self.data)

        if   (self.start_address + dlen - 1) > 0xFFFFFFFF:
            raise SRecError('Buffer size: %d is to long' % dlen)
        elif (self.start_address + dlen - 1) > 0xFFFFFF:
            srec_type = 3
        elif (self.start_address + dlen - 1) > 0xFFFF:
            srec_type = 2
        else:
            srec_type = 1

        if rtype != 0:
            if rtype < srec_type:
                raise SRecError('Wrong record type')
            else:
                srec_type = rtype

        with open(file, 'w') as f:
            f.write(self._create_header_record())
            count = 1
            offset = 0
            length = self._MAX_RAW_DATA_LEN
            while dlen > 0:
                ignore = False
                if length > dlen: length = dlen
                wrdata = self.data[offset:offset + length]
                if wrap and all(x == self.empty_value for x in wrdata):
                    ignore = True
                if not ignore:
                    f.write(self._create_data_record(srec_type, self.start_address + offset, wrdata))
                    count += 1
                dlen -= length
                offset += length
            if rcnt:
                f.write(self._create_count_record(count))
            if rterm:
                f.write(self._create_termination_record(srec_type, self.jump_address))
            f.close()

# Example of usage
if __name__ == "__main__":
    srec = SRecFile()
    print('Load S-Rec File < in.s19 >:')
    srec.open('../temp/in.s19')
    if not srec.header: srec.header = 'S-REC File'

    print('- saddr = 0x%X' % srec.start_address)
    print('- eaddr = 0x%X' % srec.end_address)
    print('- size  = %d Bytes' % srec.size)

    print('\n %s \n' % srec)

    # copy part of srec
    print('Copy first 20 bytes from srec:')
    srec_cut = srec[:srec.start_address + 20]
    print('\n %s \n' % srec_cut)

    # insert new data segment
    print('Insert new data segment:')
    srec.insert_data(0x8000, ([0xAA] * 100))
    print('\n %s \n' % srec)

    # iterator
    print('Read data:\n')
    for addr, val in srec[srec.end_address - 5:]:
        print('Addr[0x%X] = %d' % (addr, val))

    print('\nSet value:')
    srec[srec.end_address] = 10

    print('\nAddr[0x%X] = %d' % (srec.end_address, srec[srec.end_address]))

    # save srec into file
    srec.save('../temp/out.s19', wrap=True)