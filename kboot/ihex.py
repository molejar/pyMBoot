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
import itertools


# module exceptions
# --------------------------------------------------------------------
class IHexError(Exception):
    '''Base Exception class for IHexFile module'''

    _fmt = 'IHexFile base error'  #: format string

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


class IHexLengthError(IHexError):
    _fmt = 'Record at line %(line)d has invalid length'


class IHexAlignError(IHexError):
    _fmt = 'Record at line %(line)d has invalid align'


class IHexTypeError(IHexError):
    _fmt = 'Record at line %(line)d has invalid record type'


class IHexChecksumError(IHexError):
    _fmt = 'Record at line %(line)d has invalid checksum'


class IHexCountError(IHexError):
    _fmt = 'Invalid records count: is %(count)d instead %(rcount)d'


# public classes
# -----------------------------------------------------------------------

class IHexSegment(object):

    @property
    def size(self):
        return len(self)

    @property
    def end_address(self):
        return self.start_address + self.size - 1

    def __init__(self, saddr, data, name=None):
        self.name = name
        self.start_address = saddr
        self.data = data

    def __str__(self):
        return '< 0x%08X @ %d Bytes >' % (self.start_address, self.size)

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
            return IHexSegment(saddr=start, data=d)
        else:
            if not address in self:
                raise IndexError("Address 0x%x is not in this segment" % address)
            return self.data[address - self.start_address]

    def __setitem__(self, address, value):
        if not isinstance(address, int):
            raise IndexError('Index must be integer value: %r' % address)
        if not address in self:
            raise IndexError('Address 0x%08X out of range 0x%08X - 0x%08X' % (address, self.start_address,
                                                                              self.end_address))
        if not 0x00 <= value <= 0xFF:
            raise ValueError('Value must be in range 0x00 - 0xFF: 0x%X' % value)
        self.data[address - self.start_address] = value

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(zip(range(self.start_address, self.end_address + 1), self.data))


class IHexFile(object):
    RECORD_TYPE = {
        'DATA':           0x00,  # Data Record
        'EOF':            0x01,  # End of File Record
        'EXT_SEG_ADDR':   0x02,  # Extended Segment Address Record
        'START_SEG_ADDR': 0x03,  # Start Segment Address Record
        'EXT_LIN_ADDR':   0x04,  # Extended Linear Address Record
        'START_LIN_ADDR': 0x05   # Start Linear Address Record
    }

    MIN_RECORD_LEN = 10
    MAX_RAW_DATA_LEN = 16
    LINE_TERMINATION = '\n'

    @property
    def start_address(self):
        saddr = 0xFFFFFFFF
        for seg in self.segments:
            if saddr > seg.start_address:
                saddr = seg.start_address
        return saddr

    @property
    def end_address(self):
        eaddr = 0
        for seg in self.segments:
            if eaddr < seg.end_address:
                eaddr = seg.end_address
        return eaddr

    @property
    def data(self):
        buf = bytearray((self.end_address - self.start_address) + 1)
        for i in range(len(buf)):
            buf[i] = self.empty_value
        for seg in self.segments:
            offset = seg.start_address - self.start_address
            for i, v in enumerate(seg.data):
                buf[offset + i] = v
        return buf

    @property
    def size(self):
        return len(self)

    def __init__(self, segments=None, empty_value=0xFF, **kwargs):
        self.eip = None
        self.cs  = None
        self.ip  = None

        self.empty_value = empty_value
        self.segments = segments or []

        for key, value in kwargs.items():
            setattr(self, key, value)

    def __getitem__(self, addr):
        address = addr if not isinstance(addr, slice) else addr.start

        for segment in self.segments:
            if address in segment:
                return segment[address]

        raise IndexError('No segment contains address 0x%x' % address)

    def __setitem__(self, addr, val):
        if not isinstance(addr, int):
            raise IndexError('Index must be integer value: %r' % addr)
        if not 0x00 <= val <= 0xFF:
            raise ValueError('Value must be in range 0x00 - 0xFF: 0x%X' % val)

        for segment in self.segments:
            if addr in segment:
                segment[addr] = val
                return

        raise IndexError('No segment contains address 0x%x' % addr)

    def __len__(self):
        return sum(map(len, self.segments))

    def __iter__(self):
        return itertools.chain(*self.segments)

    def _calc_crc(self, recnocrc):
        """ IHEX: Calculate checksum of specified data
        :param recnocrc: Record string without crc
        :return: crc value
        """
        rdata = [int(recnocrc[i:i+2], 16) for i in range(0, len(recnocrc), 2)]
        crc = (256 - sum(rdata) & 0xFF) & 0xFF
        return crc

    def _check_crc(self, record):
        """ IHEX: Validate if the checksum of the supplied record is valid
        :param record: Record string with crc
        :return: True if valid, False if not
        """
        orig_crc = int(record[-2:], 16)
        calc_crc = self._calc_crc(record[:-2])
        return orig_crc == calc_crc

    def _create_data_record(self, addr, data):
        record  = ':{0:02X}{1:04X}00'.format(len(data), addr)
        record += ''.join('{:02X}'.format(x) for x in data)
        record += '{:02X}'.format(self._calc_crc(record[1:]))
        record += self.LINE_TERMINATION
        return record

    def _create_eof_record(self):
        record = ':00000001FF'
        record += self.LINE_TERMINATION
        return record

    def _create_ext_seg_addr_record(self, value):
        record  = ':02000002{0:04X}'.format(value)
        record += '{:02X}'.format(self._calc_crc(record[1:]))
        record += self.LINE_TERMINATION
        return record

    def _create_start_seg_addr_record(self):
        record  = ':04000003{0:04X}{1:04X}'.format(self.cs, self.ip)
        record += '{:02X}'.format(self._calc_crc(record[1:]))
        record += self.LINE_TERMINATION
        return record

    def _create_ext_lin_addr_record(self, value):
        record = ':02000004{0:04X}'.format(value)
        record += '{:02X}'.format(self._calc_crc(record[1:]))
        record += self.LINE_TERMINATION
        return record

    def _create_start_lin_addr_record(self):
        record = ':04000005{0:04X}'.format(self.eip)
        record += '{:02X}'.format(self._calc_crc(record[1:]))
        record += self.LINE_TERMINATION
        return record

    def append(self, segment):
        self.segments.append(segment)

    def open(self, file, empty_value=None):
        """ IHEX: Open and load content of S-Record file into internal buffer
        :param file: Path to SRecord file
        """
        if empty_value:
            self.empty_value = empty_value

        with open(file, 'r') as f:
            ext_lin_addr = 0
            ext_seg_addr = 0
            lnum = 0

            for line in f:
                lnum += 1
                line = line.strip()
                if not line.startswith(':'):
                    continue

                line = line.strip(':')

                if len(line) < self.MIN_RECORD_LEN:
                    #print(len(line))
                    raise IHexLengthError(line=lnum)

                if len(line) % 2 != 0:
                    raise IHexAlignError(line=lnum)

                if self._check_crc(line) is not True:
                    raise IHexChecksumError(line=lnum)

                datalen = int(line[0:2], 16)
                address = int(line[2:6], 16)
                rectype = int(line[6:8], 16)
                rawdata = line[8:-2]

                if len(rawdata) != (datalen * 2):
                    raise IHexLengthError(line=lnum)

                if rectype == self.RECORD_TYPE['DATA']:
                    current_addr = (address + ext_lin_addr + ext_seg_addr) & 0xffffffff
                    new_segment = True
                    data = [int(rawdata[i:i+2], 16) for i in range(0, len(rawdata), 2)]
                    for segment in self.segments:
                        if (segment.end_address + 1) == current_addr:
                            segment.data.extend(data)
                            new_segment = False
                            break
                    if new_segment:
                        self.segments.append(IHexSegment(saddr=current_addr, data=data))

                elif rectype == self.RECORD_TYPE['EOF']:
                    break

                elif rectype == self.RECORD_TYPE['EXT_SEG_ADDR']:
                    if datalen != 2: raise IHexLengthError(line=lnum)
                    ext_seg_addr = int(rawdata, 16) << 4

                elif rectype == self.RECORD_TYPE['START_SEG_ADDR']:
                    if datalen != 4: raise IHexLengthError(line=lnum)
                    self.cs = int(rawdata[0:4], 16)
                    self.ip = int(rawdata[4:8], 16)

                elif rectype == self.RECORD_TYPE['EXT_LIN_ADDR']:
                    if datalen != 2: raise IHexLengthError(line=lnum)
                    ext_lin_addr = int(rawdata, 16) << 16

                elif rectype == self.RECORD_TYPE['START_LIN_ADDR']:
                    if datalen != 4: raise IHexLengthError(line=lnum)
                    self.eip = int(rawdata, 16)

                else:
                    raise IHexError("Unknown record type: %s" % rectype)

    def save(self, file, wrap=False):
        """ IHEX: Save content of internal buffer into S-Record file
        :param file:  Path to S-Record file
        :param wrap:
        """
        if not self.segments:
            raise IHexError('No data to save !')

        with open(file, 'w') as fw:
            for segment in self.segments:
                addr = segment.start_address
                data = segment.data
                dlen = segment.size
                index = 0
                while dlen > 0:
                    ignore = False
                    if addr > 0xFFFF:
                        fw.write(self._create_ext_lin_addr_record(addr >> 16))
                        addr &= 0xFFFF
                    length = dlen if dlen < self.MAX_RAW_DATA_LEN else self.MAX_RAW_DATA_LEN
                    wrdata = data[index:index + length]
                    if wrap and wrdata == bytearray([self.empty_value]*length):
                        ignore = True
                    if not ignore:
                        fw.write(self._create_data_record(addr, wrdata))
                    dlen  -= length
                    addr  += length
                    index += length
            if self.cs is not None and self.ip is not None:
                fw.write(self._create_start_seg_addr_record())
            if self.eip is not None:
                fw.write(self._create_start_lin_addr_record())
            fw.write(self._create_eof_record())
            fw.close()

# Example of usage
if __name__ == "__main__":
    ihex = IHexFile()
    ihex.open('../temp/in.hex')
    print(len(ihex.data))
    ihex.save('../temp/out.hex')