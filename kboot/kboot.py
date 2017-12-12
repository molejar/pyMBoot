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

import sys
import logging
from enum import IntEnum, unique
from struct import pack, unpack_from

from .misc import atos
from .usbif import USBIF
from .uartif import UARTIF

#logging.basicConfig(level=logging.INFO)


########################################################################################################################
# KBoot Enums
########################################################################################################################
@unique
class CmdEnum(IntEnum):
    # KBoot Commands.
    FlashEraseAll            = 0x01
    FlashEraseRegion         = 0x02
    ReadMemory               = 0x03
    WriteMemory              = 0x04
    FillMemory               = 0x05
    FlashSecurityDisable     = 0x06
    GetProperty              = 0x07
    ReceiveSBFile            = 0x08
    Execute                  = 0x09
    Call                     = 0x0A
    Reset                    = 0x0B
    SetProperty              = 0x0C
    FlashEraseAllUnsecure    = 0x0D
    FlashProgramOnce         = 0x0E
    FlashReadOnce            = 0x0F
    FlashReadResource        = 0x10
    ConfigureQuadSpi         = 0x11


@unique
class PropEnum(IntEnum):
    # KBoot Property constants.
    CurrentVersion           = 0x01
    AvailablePeripherals     = 0x02
    FlashStartAddress        = 0x03
    FlashSize                = 0x04
    FlashSectorSize          = 0x05
    FlashBlockCount          = 0x06
    AvailableCommands        = 0x07
    CrcCheckStatus           = 0x08
    VerifyWrites             = 0x0A
    MaxPacketSize            = 0x0B
    ReservedRegions          = 0x0C
    ValidateRegions          = 0x0D
    RAMStartAddress          = 0x0E
    RAMSize                  = 0x0F
    SystemDeviceIdent        = 0x10
    FlashSecurityState       = 0x11
    UniqueDeviceIdent        = 0x12
    FlashFacSupport          = 0x13
    FlashAccessSegmentSize   = 0x14
    FlashAccessSegmentCount  = 0x15
    FlashReadMargin          = 0x16
    QspiInitStatus           = 0x17
    TargetVersion            = 0x18
    ExternalMemoryAttributes = 0x19


@unique
class StatEnum(IntEnum):
    # Generic status codes.
    Success                  = 0
    Fail                     = 1
    ReadOnly                 = 2
    OutOfRange               = 3
    InvalidArgument          = 4

    # Flash driver errors.
    FlashSizeError           = 100
    FlashAlignmentError      = 101
    FlashAddressError        = 102
    FlashAccessError         = 103
    FlashProtectionViolation = 104
    FlashCommandFailure      = 105
    FlashUnknownProperty     = 106

    # I2C driver errors.
    I2C_SlaveTxUnderrun      = 200
    I2C_SlaveRxOverrun       = 201
    I2C_AribtrationLost      = 202

    # SPI driver errors.
    SPI_SlaveTxUnderrun      = 300
    SPI_SlaveRxOverrun       = 301

    # QuadSPI driver errors
    QSPI_FlashSizeError      = 400
    QSPI_FlashAlignmentError = 401
    QSPI_FlashAddressError   = 402
    QSPI_FlashCommandFailure = 403
    QSPI_FlashUnknownProperty= 404
    QSPI_NotConfigured       = 405
    QSPI_CommandNotSupported = 406

    # Bootloader errors.
    UnknownCommand           = 10000
    SecurityViolation        = 10001
    AbortDataPhase           = 10002
    PingError                = 10003
    NoResponse               = 10004
    NoResponseExpected       = 10005

    # SB loader errors.
    RomLdrSectionOverrun     = 10100
    RomLdrSignature          = 10101
    RomLdrSectionLength      = 10102
    RomLdrUnencryptedOnly    = 10103
    RomLdrEOFReached         = 10104
    RomLdrChecksum           = 10105
    RomLdrCrc32Error         = 10106
    RomLdrUnknownCommand     = 10107
    RomLdrIdNotFound         = 10108
    RomLdrDataUnderrun       = 10109
    RomLdrJumpReturned       = 10110
    RomLdrCallFailed         = 10111
    RomLdrKeyNotFound        = 10112
    RomLdrSecureOnly         = 10113

    # Memory interface errors.
    MemoryRangeInvalid       = 10200
    MemoryReadFailed         = 10201
    MemoryWriteFailed        = 10202

    # Property store errors.
    UnknownProperty          = 10300
    ReadOnlyProperty         = 10301
    InvalidPropertyValue     = 10302

    # Property store errors.
    AppCrcCheckPassed        = 10400
    AppCrcCheckFailed        = 10401
    AppCrcCheckInactive      = 10402
    AppCrcCheckInvalid       = 10403
    AppCrcCheckOutOfRange    = 10404


########################################################################################################################
# KBoot USB interface
########################################################################################################################

# USB default ID's
DEFAULT_USB_VID = 0x15A2
DEFAULT_USB_PID = 0x0073


def scan_usb(usb_vid=DEFAULT_USB_VID, usb_pid=DEFAULT_USB_PID):
    """ KBoot: Scan commected USB devices
    :rtype : object
    """
    devs = USBIF.enumerate(usb_vid, usb_pid)
    if devs:
        logging.info('Founded MCUs with KBoot: %d', len(devs))
    else:
        logging.info('No MCU with KBoot detected')

    return devs


def scan_uart():
    raise NotImplemented("Function is not implemented")


########################################################################################################################
# KBoot Main Class
########################################################################################################################
class KBoot(object):

    HID_REPORT = {
        # KBoot USB HID Reports.
        'CMD_OUT':  0x01,
        'CMD_IN':   0x03,
        'DATA_OUT': 0x02,
        'DATA_IN':  0x04
    }

    INTERFACES = {
        #  KBoot Interface  |     mask     |  default speed
        'UART'              : [ 0x00000001,  115200 ],
        'I2C-Slave'         : [ 0x00000002,  400 ],
        'SPI-Slave'         : [ 0x00000004,  400 ],
        'CAN'               : [ 0x00000008,  500 ],
        'USB-HID'           : [ 0x00000010,  12000000 ],
        'USB-CDC'           : [ 0x00000020,  12000000 ],
        'USB-DFU'           : [ 0x00000040,  12000000 ],
    }

    class __fptype(IntEnum):
        # KBoot Framing Packet Type.
        ACK   = 0xA1
        NACK  = 0xA2
        ABORT = 0xA3
        CMD   = 0xA4
        DATA  = 0xA5
        PING  = 0xA6
        PINGR = 0xA7

    def __init__(self):
        self._usb_dev = None
        self._uart_dev = None
        self._pg_func = None
        self._pg_start = 0
        self._pg_end = 100
        self._abort = False

    def _parse_status(self, data):
        return unpack_from('<I', data, 4)[0]

    def _parse_value(self, data):
        return unpack_from('<I', data, 8)[0]

    def _parse_property(self, prop_tag, packet):
        raw_value = self._parse_value(packet)
        if prop_tag == int(PropEnum.CurrentVersion):
            str_value = "{0:d}.{1:d}.{2:d}".format((raw_value >> 16) & 0xFF,
                                                   (raw_value >> 8) & 0xFF,
                                                    raw_value & 0xFF)
        elif prop_tag == int(PropEnum.AvailablePeripherals):
            str_value = []
            for key, value in self.INTERFACES.items():
                if value[0] & raw_value:
                    str_value.append(key)
        elif prop_tag == int(PropEnum.FlashSecurityState):
            if raw_value == 0:
                str_value = 'Unlocked'
            else:
                str_value = 'Locked'
        elif prop_tag == int(PropEnum.AvailableCommands):
            str_value = []
            for cmd in CmdEnum:
                if int(1 << cmd.value) & raw_value:
                    str_value.append(cmd.name)
        elif (prop_tag == int(PropEnum.MaxPacketSize) or
              prop_tag == int(PropEnum.FlashSectorSize) or
              prop_tag == int(PropEnum.FlashSize) or
              prop_tag == int(PropEnum.RAMSize)):
            if raw_value >= 1024:
                str_value = '{0:d}kB'.format(raw_value // 1024)
            else:
                str_value = '{0:d}B'.format(raw_value)
        elif (prop_tag == int(PropEnum.RAMStartAddress) or
              prop_tag == int(PropEnum.FlashStartAddress) or
              prop_tag == int(PropEnum.SystemDeviceIdent)):
            str_value = '0x{:08X}'.format(raw_value)
        else:
            str_value = '{:d}'.format(raw_value)
        # ---
        logging.info('RX-CMD: %s = %s', PropEnum(prop_tag).name, str_value)
        return { 'raw_value' : raw_value, 'string' : str_value }

    def _process_cmd(self, data, timeout=1000):
        """Process Command Data
        :rtype : object
        """
        if self._usb_dev is None and self._uart_dev is None:
            logging.info('RX-CMD: USB Disconnected')
            raise ConnError('USB Disconnected')

        # log TX raw command data
        logging.debug('TX-CMD [0x]: %s', atos(data))

        if self._usb_dev:
            # Send USB-HID CMD OUT Report
            self._usb_dev.write(self.HID_REPORT['CMD_OUT'], data)

            # Read USB-HID CMD IN Report
            try:
                rxpkg = self._usb_dev.read(timeout)[1]
            except:
                logging.info('RX-CMD: USB Disconnected')
                raise TimeOutError('USB Disconnected')
        else:
            # Send UART
            self._uart_dev.write(self.__fptype.CMD, data)

            # Read USB-HID CMD IN Report
            try:
                rxpkg = self._uart_dev.read()[1]
            except:
                logging.info('RX-CMD: UART Disconnected')
                raise TimeOutError('UART Disconnected')

        # log RX raw command data
        logging.debug('RX-CMD [0x]: %s', atos(rxpkg))

        # Parse and validate status flag
        status = self._parse_status(rxpkg)
        if status != StatEnum.Success:
            logging.info('RX-CMD: %s', StatEnum(status).name)
            raise CommandError(errname=StatEnum(status).name, errval=status)

        return rxpkg

    def _read_data(self, length, timeout=1000):
        n = 0
        data = bytearray()
        pg_dt = float(self._pg_end - self._pg_start) / length
        self._abort = False

        if self._usb_dev is None and self._uart_dev is None:
            logging.info('RX-DATA: Disconnected')
            raise ConnError('Disconnected')

        while n < length:
            # Read USB-HID DATA IN Report
            try:
                rep_id, pkg = self._usb_dev.read(timeout)
            except:
                logging.info('RX-DATA: USB Disconnected')
                raise TimeOutError('USB Disconnected')

            if rep_id != self.HID_REPORT['DATA_IN']:
                status = self._parse_status(pkg)
                logging.info('RX-DATA: %s' % StatEnum(status).name)
                raise DataError(mode='read', errname=StatEnum(status).name, errval=status)

            data.extend(pkg)
            n += len(pkg)

            if self._pg_func:
                self._pg_func(self._pg_start + int(n * pg_dt))

            if self._abort:
                logging.info('Read Aborted By User')
                return

        # Read USB-HID CMD IN Report
        try:
            rep_id, pkg = self._usb_dev.read(timeout)
        except:
            logging.info('RX-DATA: USB Disconnected')
            raise TimeOutError('USB Disconnected')

        # Parse and validate status flag
        status = self._parse_status(pkg)
        if status != StatEnum.Success:
            logging.info('RX-DATA: %s' % StatEnum(status).name)
            raise DataError(mode='read', errname=StatEnum(status).name, errval=status)

        logging.info('RX-DATA: Successfully Received %d Bytes', len(data))
        return data

    def _send_data(self, data):
        n = len(data)
        start = 0
        pg_dt = float(self._pg_end - self._pg_start) / n
        self._abort = False

        if self._usb_dev is None and self._uart_dev is None:
            logging.info('TX-DATA: Disconnected')
            raise ConnError('Disconnected')

        while n > 0:
            length = 0x20
            if n < length:
                length = n
            txbuf = data[start:start+length]

            # send USB-HID command OUT report
            self._usb_dev.write(self.HID_REPORT['DATA_OUT'], txbuf)

            n -= length
            start += length

            if self._pg_func:
                self._pg_func(self._pg_start + int(start * pg_dt))

            if self._abort:
                logging.info('Write Aborted By User')
                return
        try:
            rep_id, pkg = self._usb_dev.read()
        except:
            logging.info('TX-DATA: USB Disconnected')
            raise TimeOutError('USB Disconnected')

        # Parse and validate status flag
        status = self._parse_status(pkg)
        if status != StatEnum.Success:
            logging.info('TX-DATA: %s' % StatEnum(status).name)
            raise DataError(mode='write', errname=StatEnum(status).name, errval=status)

        logging.info('TX-DATA: Successfully Send %d Bytes', len(data))
        return start

    def set_handler(self, progressbar, start_val=0, end_val=100):
        self._pg_func = progressbar
        self._pg_start = start_val
        self._pg_end = end_val

    def abort(self):
        self._abort = True

    def is_open(self):
        """ KBoot: Check if device connected
        """
        if self._usb_dev is not None:
            return True
        else:
            return False

    def open_usb(self, dev):
        """ KBoot: Connect by USB
        """
        if dev is not None:
            logging.info('Connect: %s', dev.getInfo())
            self._usb_dev = dev
            self._usb_dev.open()

            return True
        else:
            logging.info('USB Disconnected !')
            return False

    def open_uart(self, port, baudrate):
        """ KBoot: Connect by UART
        """
        if port is not None:
            self._uart_dev = UARTIF()
            self._uart_dev.open(port, baudrate)
            if self._uart_dev.ping():
                return True
            else:
                self.close()
                return False
        else:
            logging.info('UART Disconnected !')
            return False


    def close(self):
        """ KBoot: Disconnect device
        """
        if self._usb_dev:
            self._usb_dev.close()
            self._usb_dev = None
        elif self._uart_dev:
            self._uart_dev.close()
            self._uart_dev = None
        else:
            return

    def get_mcu_info(self):
        """ KBoot: Get MCU info (available properties collection)
        :return List of {dict}
        """
        mcu_info = {}
        if self._usb_dev is None and self._uart_dev is None:
            logging.info('Disconnected !')
            return None

        for p in PropEnum:
            try:
                value = self.get_property(p.value)
            except CommandError:
                continue
            mcu_info.update({p.name : value})

        return mcu_info

    def get_property(self, prop_tag, ext_mem_identifier=None):
        """ KBoot: Get value of specified property
        :param prop_tag: The property ID (see Property enumerator)
        :param ext_mem_identifier:
        :return {dict} with 'RAW' and 'STRING' value
        """
        prop_tag = int(prop_tag)
        logging.info('TX-CMD: GetProperty->%s', PropEnum(prop_tag).name)
        # Prepare GetProperty command
        cmd = pack('3B', CmdEnum.GetProperty.value, 0x00, 0x00)
        if ext_mem_identifier is None:
            cmd += pack('<BI', 0x01, prop_tag)
        else:
            cmd += pack('<BII', 0x02, prop_tag, ext_mem_identifier)
        # Process GetProperty command
        rpkg = self._process_cmd(cmd)
        # Parse property value
        return self._parse_property(prop_tag, rpkg)

    def set_property(self, prop_tag, value):
        """ KBoot: Set value of specified property
        :param  property_tag: The property ID (see Property enumerator)
        :param  value: The value of selected property
        """
        prop_tag = int(prop_tag)
        logging.info('TX-CMD: SetProperty->%s = %d', PropEnum(prop_tag).name, value)
        # Prepare SetProperty command
        cmd  = pack('4B', CmdEnum.SetProperty.value, 0x00, 0x00, 0x02)
        cmd += pack('<II', prop_tag, value)
        # Process SetProperty command
        self._process_cmd(cmd)

    def flash_read_resource(self, start_address, length, option=1):
        """ KBoot: Read resource of flash module
        :param start_address:
        :param length:
        :param option:
        :return resource list
        """
        logging.info('TX-CMD: FlashReadResource [ StartAddr=0x%08X | len=%d ]', start_address, length)
        # Prepare FlashReadResource command
        cmd  = pack('4B', CmdEnum.FlashReadResource.value, 0x00, 0x00, 0x03)
        cmd += pack('<3I', start_address, length, option)
        # Process FlashReadResource command
        pkg = self._process_cmd(cmd)
        rxlen = self._parse_value(pkg)
        if length > rxlen:
            length = rxlen
        # Process Read Data
        return self._read_data(length)

    def flash_security_disable(self, backdoor_key):
        """ KBoot: Disable flash security by backdoor key
        :param backdoor_key:
        """
        logging.info('TX-CMD: FlashSecurityDisable [ backdoor_key [0x] = %s ]', atos(backdoor_key))
        # Prepare FlashSecurityDisable command
        cmd = pack('4B', CmdEnum.FlashSecurityDisable.value, 0x00, 0x00, 0x02)
        if len(backdoor_key) < 8:
            raise ValueError('Short range of backdoor key')
        cmd += bytes(backdoor_key[3::-1])
        cmd += bytes(backdoor_key[:3:-1])
        # Process FlashSecurityDisable command
        self._process_cmd(cmd)

    def flash_erase_region(self, start_address, length):
        """ KBoot: Erase specified range of flash
        :param start_address:
        :param length:
        """
        logging.info('TX-CMD: FlashEraseRegion [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare FlashEraseRegion command
        cmd  = pack('4B', CmdEnum.FlashEraseRegion.value, 0x00, 0x00, 0x02)
        cmd += pack('<II', start_address, length)
        # Process FlashEraseRegion command
        self._process_cmd(cmd, 5000)

    def flash_erase_all(self):
        """ KBoot: Erase complete flash memory without recovering flash security section
        """
        logging.info('TX-CMD: FlashEraseAll')
        # Prepare FlashEraseAll command
        cmd = pack('4B', CmdEnum.FlashEraseAll.value, 0x00, 0x00, 0x00)
        # Process FlashEraseAll command
        self._process_cmd(cmd)

    def flash_erase_all_unsecure(self):
        """ KBoot: Erase complete flash memory and recover flash security section
        """
        logging.info('TX-CMD: FlashEraseAllUnsecure')
        # Prepare FlashEraseAllUnsecure command
        cmd = pack('4B', CmdEnum.FlashEraseAllUnsecure.value, 0x00, 0x00, 0x00)
        # Process FlashEraseAllUnsecure command
        self._process_cmd(cmd)

    def flash_read_once(self, index, length):
        """ KBoot: Read from MCU flash program once region (max 8 bytes)
        :param index: Start index
        :param length: Count of bytes
        :return List of bytes
        """
        if (index + length) > 8: length = 8 - index
        if length == 0:
            raise ValueError('Index out of range')
        logging.info('TX-CMD: FlashReadOnce [ Index=%d | len=%d   ]', index, length)
        # Prepare FlashReadOnce command
        cmd  = pack('4B', CmdEnum.FlashReadOnce.value, 0x00, 0x00, 0x02)
        cmd += pack('<II', index, length)
        # Process FlashReadOnce command
        self._process_cmd(cmd)
        # Process Read Data
        return self._read_data(length)

    def flash_program_once(self, index, data):
        """ KBoot: Write into MCU flash program once region (max 8 bytes)
        :param index: Start index
        :param data: List of bytes
        """
        length = len(data)
        if (index + length) > 8: length = 8 - index
        if length == 0:
            raise ValueError('Index out of range')
        logging.info('TX-CMD: FlashProgramOnce [ Index=%d | Data[0x]: %s  ]', index, atos(data[:length]))
        # Prepare FlashProgramOnce command
        cmd  = pack('4B', CmdEnum.FlashProgramOnce.value, 0x00, 0x00, 0x03)
        cmd += pack('<II', index, length)
        cmd += bytes(data)
        # Process FlashProgramOnce command
        self._process_cmd(cmd)
        return length

    def read_memory(self, start_address, length):
        """ KBoot: Read data from MCU memory
        :param start_address: Start address
        :param length: Count of bytes
        :return List of bytes
        """
        if length == 0:
            raise ValueError('Data len is zero')
        logging.info('TX-CMD: ReadMemory [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare ReadMemory command
        cmd  = pack('4B', CmdEnum.ReadMemory.value, 0x00, 0x00, 0x02)
        cmd += pack('<II', start_address, length)
        # Process ReadMemory command
        self._process_cmd(cmd)
        # Process Read Data
        return self._read_data(length)

    def write_memory(self, start_address, data):
        """ KBoot: Write data into MCU memory
        :param start_address: Start address
        :param data: List of bytes
        :return Count of wrote bytes
        """
        if len(data) == 0:
            raise ValueError('Data len is zero')
        logging.info('TX-CMD: WriteMemory [ StartAddr=0x%08X | len=%d  ]', start_address, len(data))
        # Prepare WriteMemory command
        cmd  = pack('4B', CmdEnum.WriteMemory.value, 0x00, 0x00, 0x03)
        cmd += pack('<II', start_address, len(data))
        # Process WriteMemory command
        self._process_cmd(cmd)
        # Process Write Data
        return self._send_data(data)

    def fill_memory(self, start_address, length, pattern=0xFFFFFFFF):
        """ KBoot: Fill MCU memory with specified pattern
        :param start_address: Start address (must be word aligned)
        :param length: Count of words (must be word aligned)
        :param pattern: Count of wrote bytes
        """
        logging.info('TX-CMD: FillMemory [ StartAddr=0x%08X | len=%d  | patern=0x%08X ]', start_address, length, pattern)
        # Prepare FillMemory command
        cmd  = pack('4B', CmdEnum.FillMemory.value, 0x00, 0x00, 0x03)
        cmd += pack('<III', start_address, length, pattern)
        # Process FillMemory command
        self._process_cmd(cmd)

    def receive_sb_file(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"receive_sb_file()\" not implemented yet')

    def configure_quad_spi(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"configure_quad_spi()\" not implemented yet')

    def execute(self, jump_address, argument, sp_address):
        """ KBoot: Fill MCU memory with specified pattern
        :param jump_address: Jump address (must be word aligned)
        :param argument: Function arguments address
        :param sp_address: Stack pointer address
        """
        logging.info('TX-CMD: Execute [ JumpAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', jump_address, argument, sp_address)
        # Prepare Execute command
        cmd  = pack('4B', CmdEnum.Execute.value, 0x00, 0x00, 0x03)
        cmd += pack('<III', jump_address, argument, sp_address)
        # Process Execute command
        self._process_cmd(cmd)

    def call(self, call_address, argument, sp_address):
        """ KBoot: Fill MCU memory with specified pattern
        :param call_address: Call address (must be word aligned)
        :param argument: Function arguments address
        :param sp_address: Stack pointer address
        """
        logging.info('TX-CMD: Call [ CallAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', call_address, argument, sp_address)
        # Prepare Call command
        cmd  = pack('4B', CmdEnum.Call.value, 0x00, 0x00, 0x03)
        cmd += pack('<III', call_address, argument, sp_address)
        # Process Call command
        self._process_cmd(cmd)

    def reset(self):
        """ KBoot: Reset MCU
        """
        logging.info('TX-CMD: Reset MCU')
        # Prepare Reset command
        cmd = pack('4B', CmdEnum.Reset.value, 0x00, 0x00, 0x00)
        # Process Reset command
        try:
            self._process_cmd(cmd)
        except:
            pass


########################################################################################################################
# KBoot Exceptions
########################################################################################################################
class GenericError(Exception):
    """ Base Exception class for SRecFile module
    """
    _fmt = 'KBoot Error'   #: format string

    def __init__(self, msg=None, **kw):
        """ Initialize the Exception with the given message. """
        self.msg = msg
        for key, value in kw.items():
            setattr(self, key, value)

    def __str__(self):
        """ Return the message in this Exception. """
        if self.msg:
            return self.msg
        try:
            return self._fmt % self.__dict__
        except (NameError, ValueError, KeyError):
            e = sys.exc_info()[1]     # current exception
            return 'Unprintable exception %s: %s' % (repr(e), str(e))

    def GetErrorVal(self):
        if self.errval:
            return self.errval
        else:
            return -1


class CommandError(GenericError):
    _fmt = 'Command operation break: %(errname)s'


class DataError(GenericError):
    _fmt = 'Data %(mode)s break: %(errname)s'


class ConnError(GenericError):
    _fmt = 'KBoot connection error'


class TimeOutError(GenericError):
    _fmt = 'KBoot timeout error'
