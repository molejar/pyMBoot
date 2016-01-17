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

from usbif import *
from utils import *

from flufl.enum import IntEnum


#logging.basicConfig(level=logging.INFO)

class Property(IntEnum):
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


# Status groups.
StatusGroup_Generic = 0
StatusGroup_FlashDriver = 1
StatusGroup_I2CDriver = 2
StatusGroup_SPIDriver = 3
StatusGroup_QuadSPIDriver = 4
StatusGroup_Bootloader = 100
StatusGroup_SBLoader = 101
StatusGroup_MemoryInterface = 102
StatusGroup_PropertyStore = 103
StatusGroup_AppCrcCheck = 104

class Status(IntEnum):
    # Generic status codes.
    Success                  = ((StatusGroup_Generic * 100) + 0)
    Fail                     = ((StatusGroup_Generic * 100) + 1)
    ReadOnly                 = ((StatusGroup_Generic * 100) + 2)
    OutOfRange               = ((StatusGroup_Generic * 100) + 3)
    InvalidArgument          = ((StatusGroup_Generic * 100) + 4)

    # Flash driver errors.
    FlashSizeError           = ((StatusGroup_FlashDriver * 100) + 0)
    FlashAlignmentError      = ((StatusGroup_FlashDriver * 100) + 1)
    FlashAddressError        = ((StatusGroup_FlashDriver * 100) + 2)
    FlashAccessError         = ((StatusGroup_FlashDriver * 100) + 3)
    FlashProtectionViolation = ((StatusGroup_FlashDriver * 100) + 4)
    FlashCommandFailure      = ((StatusGroup_FlashDriver * 100) + 5)
    FlashUnknownProperty     = ((StatusGroup_FlashDriver * 100) + 6)

    # I2C driver errors.
    I2C_SlaveTxUnderrun      = ((StatusGroup_I2CDriver * 100) + 0)
    I2C_SlaveRxOverrun       = ((StatusGroup_I2CDriver * 100) + 1)
    I2C_AribtrationLost      = ((StatusGroup_I2CDriver * 100) + 2)

    # SPI driver errors.
    SPI_SlaveTxUnderrun      = ((StatusGroup_SPIDriver * 100) + 0)
    SPI_SlaveRxOverrun       = ((StatusGroup_SPIDriver * 100) + 1)

    # Bootloader errors.
    UnknownCommand           = ((StatusGroup_Bootloader * 100) + 0)
    SecurityViolation        = ((StatusGroup_Bootloader * 100) + 1)
    AbortDataPhase           = ((StatusGroup_Bootloader * 100) + 2)
    PingError                = ((StatusGroup_Bootloader * 100) + 3)
    NoResponse               = ((StatusGroup_Bootloader * 100) + 4)
    NoResponseExpected       = ((StatusGroup_Bootloader * 100) + 5)

    # SB loader errors.
    RomLdrSectionOverrun     = ((StatusGroup_SBLoader * 100) + 0)
    RomLdrSignature          = ((StatusGroup_SBLoader * 100) + 1)
    RomLdrSectionLength      = ((StatusGroup_SBLoader * 100) + 2)
    RomLdrUnencryptedOnly    = ((StatusGroup_SBLoader * 100) + 3)
    RomLdrEOFReached         = ((StatusGroup_SBLoader * 100) + 4)
    RomLdrChecksum           = ((StatusGroup_SBLoader * 100) + 5)
    RomLdrCrc32Error         = ((StatusGroup_SBLoader * 100) + 6)
    RomLdrUnknownCommand     = ((StatusGroup_SBLoader * 100) + 7)
    RomLdrIdNotFound         = ((StatusGroup_SBLoader * 100) + 8)
    RomLdrDataUnderrun       = ((StatusGroup_SBLoader * 100) + 9)
    RomLdrJumpReturned       = ((StatusGroup_SBLoader * 100) + 10)
    RomLdrCallFailed         = ((StatusGroup_SBLoader * 100) + 11)
    RomLdrKeyNotFound        = ((StatusGroup_SBLoader * 100) + 12)
    RomLdrSecureOnly         = ((StatusGroup_SBLoader * 100) + 13)

    # Memory interface errors.
    MemoryRangeInvalid       = ((StatusGroup_MemoryInterface * 100) + 0)
    MemoryReadFailed         = ((StatusGroup_MemoryInterface * 100) + 1)
    MemoryWriteFailed        = ((StatusGroup_MemoryInterface * 100) + 2)

    # Property store errors.
    UnknownProperty          = ((StatusGroup_PropertyStore * 100) + 0)
    ReadOnlyProperty         = ((StatusGroup_PropertyStore * 100) + 1)
    InvalidPropertyValue     = ((StatusGroup_PropertyStore * 100) + 2)

    # Property store errors.
    AppCrcCheckPassed        = ((StatusGroup_AppCrcCheck * 100) + 0)
    AppCrcCheckFailed        = ((StatusGroup_AppCrcCheck * 100) + 1)
    AppCrcCheckInactive      = ((StatusGroup_AppCrcCheck * 100) + 2)
    AppCrcCheckInvalid       = ((StatusGroup_AppCrcCheck * 100) + 3)
    AppCrcCheckOutOfRange    = ((StatusGroup_AppCrcCheck * 100) + 4)

    # QuadSPI driver errors
    QspiFlashSizeError       = ((StatusGroup_QuadSPIDriver * 100) + 0)
    QspiFlashAlignmentError  = ((StatusGroup_QuadSPIDriver * 100) + 1)
    QspiFlashAddressError    = ((StatusGroup_QuadSPIDriver * 100) + 2)
    QspiFlashCommandFailure  = ((StatusGroup_QuadSPIDriver * 100) + 3)
    QspiFlashUnknownProperty = ((StatusGroup_QuadSPIDriver * 100) + 4)
    QspiNotConfigured        = ((StatusGroup_QuadSPIDriver * 100) + 5)
    QspiCommandNotSupported  = ((StatusGroup_QuadSPIDriver * 100) + 6)



class KBoot(object):
    # USB default ID's
    DEFAULT_VID = 0x15A2
    DEFAULT_PID = 0x0073

    class __hidreport(IntEnum):
        # KBoot USB HID Reports.
        CMD_OUT                  = 0x01
        CMD_IN                   = 0x03
        DATA_OUT                 = 0x02
        DATA_IN                  = 0x04

    class __command(IntEnum):
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

    INTERFACES = {
        #  KBoot Interface  |     mask     |  default speed
        'UART'              : [ 0x00000001,  115200 ],
        'I2C_Slave'         : [ 0x00000002,  400 ],
        'SPI_Slave'         : [ 0x00000004,  400 ],
        'CAN'               : [ 0x00000008,  500 ],
        'USB_HID'           : [ 0x00000010,  12000000 ],
        'USB_CDC'           : [ 0x00000020,  12000000 ],
        'USB_DFU'           : [ 0x00000040,  12000000 ],
    }


    def __init__(self):
        self.__usb_dev = None
        self.__pg_func = None
        self.__pg_start = 0
        self.__pg_end = 100
        self.__abort = False

    def __parse_status(self, packet):
        return array_to_long(packet[4:8])

    def __parse_value(self, packet):
        return array_to_long(packet[4:8])

    def __process_cmd(self, data, timeout=1000):
        """Process Command Data
        :rtype : object
        """
        if self.__usb_dev is None:
            logging.info('RX-CMD: USB Disconnected')
            raise KBootConnectionError('USB Disconnected')

        # Send USB-HID CMD OUT Report
        logging.debug('TX-CMD [0x]: %s', array_to_string(data))
        self.__usb_dev.write(self.__hidreport.CMD_OUT, data)

        # Read USB-HID CMD IN Report
        try:
            rxpkg = self.__usb_dev.read(timeout)[1]
        except:
            logging.info('RX-CMD: USB Disconnected')
            raise KBootTimeoutError('USB Disconnected')

        # log RX raw command data
        logging.debug('RX-CMD [0x]: %s', array_to_string(rxpkg))

        # Parse and validate status flag
        status = self.__parse_status(rxpkg)
        if status != Status.Success:
            logging.info('RX-CMD: %s', Status(status).name)
            raise KBootCommandError(errval=Status(status).name)

        return rxpkg

    def __read_data(self, length, timeout=1000):
        n = 0
        data = []
        pg_dt = float(self.__pg_end - self.__pg_start)/length
        self.__abort = False

        if self.__usb_dev is None:
            logging.info('RX-DATA: USB Disconnected')
            raise KBootConnectionError('USB Disconnected')

        while n < length:
            # Read USB-HID DATA IN Report
            try:
                rep_id, pkg = self.__usb_dev.read(timeout)
            except:
                logging.info('RX-DATA: USB Disconnected')
                raise KBootTimeoutError('USB Disconnected')

            if rep_id != self.__hidreport.DATA_IN:
                status = self.__parse_status(pkg)
                logging.info('RX-DATA: %s' % Status(status).name)
                raise KBootDataError(mode='read', errval=Status(status).name)

            data += pkg
            n += len(pkg)

            if self.__pg_func:
                self.__pg_func(self.__pg_start + int(n * pg_dt))

            if self.__abort:
                logging.info('Read Aborted By User')
                return

        # Read USB-HID CMD IN Report
        try:
            rep_id, pkg = self.__usb_dev.read(timeout)
        except:
            logging.info('RX-DATA: USB Disconnected')
            raise KBootTimeoutError('USB Disconnected')

        # Parse and validate status flag
        status = self.__parse_status(pkg)
        if status != Status.Success:
            logging.info('RX-DATA: %s' % Status(status).name)
            raise KBootDataError(mode='read', errval=Status(status).name)

        logging.info('RX-DATA: Successfully Received %d Bytes', len(data))
        return data

    def __send_data(self, data):
        n = len(data)
        start = 0
        pg_dt = float(self.__pg_end - self.__pg_start)/n
        self.__abort = False

        if self.__usb_dev is None:
            logging.info('TX-DATA: USB Disconnected')
            raise KBootConnectionError('USB Disconnected')

        while n > 0:
            length = 0x20
            if n < length:
                length = n
            txbuf = data[start:start+length]

            # send USB-HID command OUT report
            self.__usb_dev.write(self.__hidreport.DATA_OUT, txbuf)

            n -= length
            start += length

            if self.__pg_func:
                self.__pg_func(self.__pg_start + int(start * pg_dt))

            if self.__abort:
                logging.info('Write Aborted By User')
                return
        try:
            rep_id, pkg = self.__usb_dev.read()
        except:
            logging.info('TX-DATA: USB Disconnected')
            raise KBootTimeoutError('USB Disconnected')

        # Parse and validate status flag
        status = self.__parse_status(pkg)
        if status != Status.Success:
            logging.info('TX-DATA: %s' % Status(status).name)
            raise KBootDataError(mode='write', errval=Status(status).name)

        logging.info('TX-DATA: Successfully Send %d Bytes', len(data))
        return start

    def set_handler(self, progressbar, start_val=0, end_val=100):
        self.__pg_func = progressbar
        self.__pg_start = start_val
        self.__pg_end = end_val

    def abort(self):
        self.__abort = True

    def scan_usb_devs(self, kboot_vid=DEFAULT_VID, kboot_pid=DEFAULT_PID):
        """ KBoot: Scan commected USB devices
        :rtype : object
        """
        devs = getAllConnectedTargets(kboot_vid, kboot_pid)

        if devs:
            logging.info('Founded MCUs with KBoot: %d', len(devs))
        else:
            logging.info('No MCU with KBoot detected')

        return devs

    def is_connected(self):
        """ KBoot: Check if device connected
        """
        if self.__usb_dev is not None:
            return True
        else:
            return False

    def connect(self, dev):
        """ KBoot: Connect device
        """
        if dev is not None:
            logging.info('Connect: %s', dev.getInfo())
            self.__usb_dev = dev
            self.__usb_dev.open()
            return True
        else:
            logging.info('USB Disconnected !')
            return False

    def disconnect(self):
        """ KBoot: Disconnect device
        """
        if self.__usb_dev is not None:
            self.__usb_dev.close()
            self.__usb_dev = None

    def get_mcu_info(self):
        """ KBoot: Get MCU info (available properties collection)
        :return List of {dict}
        """
        mcu_info = {}
        if self.__usb_dev is None:
            logging.info('USB Disconnected !')
            return None

        for p in Property:
            try:
                value = self.get_property(p.value)
            except KBootCommandError:
                continue
            mcu_info.update({p.name : value})

        return mcu_info

    def get_property(self, property_tag, ext_mem_identifier=None):
        """ KBoot: Get value of specified property
        :param property_tag: The property ID (see Property enumerator)
        :param ext_mem_identifier:
        :return {dict} with 'RAW' and 'STRING' value
        """
        logging.info('TX-CMD: GetProperty->%s', Property(property_tag).name)
        # Prepare GetProperty command
        cmd = [self.__command.GetProperty, 0x00, 0x00, 0x01]
        cmd += long_to_array(property_tag, 4)
        if ext_mem_identifier is not None:
            cmd[3] = 0x02  # change parameter count to 2
            cmd += long_to_array(ext_mem_identifier, 4)
        # Process GetProperty command
        rpkg = self.__process_cmd(cmd)
        # Parse property value
        if property_tag == Property.CurrentVersion:
            raw_value = array_to_long(rpkg[8 : 8 + 4])
            str_value = "{0:d}.{1:d}.{2:d}".format((raw_value >> 16) & 0xFF, (raw_value >> 8) & 0xFF, raw_value & 0xFF)
        elif property_tag == Property.AvailablePeripherals:
            raw_value = array_to_long(rpkg[8 : 8 + 4])
            str_value = ''
            for key, value in self.INTERFACES.iteritems():
                if value[0] & raw_value:
                    str_value += '{:s}, '.format(key)
            str_value = str_value[:-2]
        elif property_tag == Property.FlashSecurityState:
            raw_value = array_to_long(rpkg[8 : 8 + 4])
            if raw_value == 0:
                str_value = 'Unlocked'
            else:
                str_value = 'Locked'
        elif property_tag == Property.AvailableCommands:
            raw_value = array_to_long(rpkg[8 : 8 + 4])
            str_value = ''
            for cmd in self.__command:
                if int(1 << cmd.value) & raw_value:
                    str_value += '{:s}, '.format(cmd.name)
            str_value = str_value[:-2]
        elif (property_tag == Property.MaxPacketSize or
              property_tag == Property.FlashSectorSize or
              property_tag == Property.FlashSize or
              property_tag == Property.RAMSize):
            raw_value = array_to_long(rpkg[8 : 8 + 4])
            if raw_value >= 1024:
                str_value = '{0:d}kB'.format(raw_value/1024)
            else:
                str_value = '{0:d}B'.format(raw_value)
        elif (property_tag == Property.RAMStartAddress or
              property_tag == Property.FlashStartAddress or
              property_tag == Property.SystemDeviceIdent):
            raw_value = array_to_long(rpkg[8 : 8 + 4])
            str_value = '0x{:08X}'.format(raw_value)
        else:
            raw_value = array_to_long(rpkg[8 : 8 + 4])
            str_value = '{:d}'.format(raw_value)

        logging.info('RX-CMD: %s = %s', Property(property_tag).name, str_value)
        return { 'raw_value' : raw_value, 'string' : str_value }

    def set_property(self, property_tag, value):
        """ KBoot: Set value of specified property
        :param  property_tag: The property ID (see Property enumerator)
        :param  value: The value of selected property
        """
        logging.info('TX-CMD: SetProperty->%s = %d', Property(property_tag).name, value)
        # Prepare SetProperty command
        cmd = [self.__command.SetProperty, 0x00, 0x00, 0x02]
        cmd += long_to_array(property_tag, 4)
        cmd += long_to_array(value, 4)
        # Process SetProperty command
        self.__process_cmd(cmd)

    def flash_read_resource(self, start_address, length, option=1):
        """ KBoot: Read resource of flash module
        :param start_address:
        :param length:
        :param option:
        :return resource list
        """
        logging.info('TX-CMD: FlashReadResource [ StartAddr=0x%08X | len=%d ]', start_address, length)
        # Prepare FlashReadResource command
        cmd = [self.__command.FlashReadResource, 0x00, 0x00, 0x03]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(length, 4)
        cmd += long_to_array(option, 4)
        # Process FlashReadResource command
        pkg = self.__process_cmd(cmd)
        rxlen = self.__parse_value(pkg)
        if length > rxlen:
            length = rxlen
        # Process Read Data
        return self.__read_data(length)

    def flash_security_disable(self, backdoor_key):
        """ KBoot: Disable flash security by backdoor key
        :param backdoor_key:
        """
        logging.info('TX-CMD: FlashSecurityDisable [ backdoor_key [0x] = %s ]', array_to_string(backdoor_key))
        # Prepare FlashSecurityDisable command
        cmd = [self.__command.FlashSecurityDisable, 0x00, 0x00, 0x01]
        cmd += backdoor_key
        # Process FlashSecurityDisable command
        self.__process_cmd(cmd)

    def flash_erase_region(self, start_address, length):
        """ KBoot: Erase specified range of flash
        :param start_address:
        :param length:
        """
        logging.info('TX-CMD: FlashEraseRegion [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare FlashEraseRegion command
        cmd = [self.__command.FlashEraseRegion, 0x00, 0x00, 0x02]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(length, 4)
        # Process FlashEraseRegion command
        self.__process_cmd(cmd, 5000)

    def flash_erase_all(self):
        """ KBoot: Erase complete flash memory without recovering flash security section
        """
        logging.info('TX-CMD: FlashEraseAll')
        # Prepare FlashEraseAll command
        cmd = [self.__command.FlashEraseAll, 0x00, 0x00, 0x00]
        # Process FlashEraseAll command
        self.__process_cmd(cmd)

    def flash_erase_all_unsecure(self):
        """ KBoot: Erase complete flash memory and recover flash security section
        """
        logging.info('TX-CMD: FlashEraseAllUnsecure')
        # Prepare FlashEraseAllUnsecure command
        cmd = [self.__command.FlashEraseAllUnsecure, 0x00, 0x00, 0x00]
        # Process FlashEraseAllUnsecure command
        self.__process_cmd(cmd)

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
        cmd = [self.__command.FlashReadOnce, 0x00, 0x00, 0x02]
        cmd += long_to_array(index, 4)
        cmd += long_to_array(length, 4)
        # Process FlashReadOnce command
        self.__process_cmd(cmd)
        # Process Read Data
        return self.__read_data(length)

    def flash_program_once(self, index, data):
        """ KBoot: Write into MCU flash program once region (max 8 bytes)
        :param index: Start index
        :param data: List of bytes
        """
        length = len(data)
        if (index + length) > 8: length = 8 - index
        if length == 0:
            raise ValueError('Index out of range')
        logging.info('TX-CMD: FlashProgramOnce [ Index=%d | Data[0x]: %s  ]', index, array_to_string(data[:length]))
        # Prepare FlashProgramOnce command
        cmd = [self.__command.FlashProgramOnce, 0x00, 0x00, 0x03]
        cmd += long_to_array(index, 4)
        cmd += long_to_array(length, 4)
        cmd += data
        # Process FlashProgramOnce command
        self.__process_cmd(cmd)
        # Process Write Data
        self.__send_data(data)
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
        cmd = [self.__command.ReadMemory, 0x00, 0x00, 0x02]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(length, 4)
        # Process ReadMemory command
        self.__process_cmd(cmd)
        # Process Read Data
        return self.__read_data(length)

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
        cmd = [self.__command.WriteMemory, 0x00, 0x00, 0x03]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(len(data), 4)
        # Process WriteMemory command
        self.__process_cmd(cmd)
        # Process Write Data
        return self.__send_data(data)

    def fill_memory(self, start_address, length, pattern=0xFFFFFFFF):
        """ KBoot: Fill MCU memory with specified pattern
        :param start_address: Start address (must be word aligned)
        :param length: Count of words (must be word aligned)
        :param pattern: Count of wrote bytes
        """
        logging.info('TX-CMD: FillMemory [ StartAddr=0x%08X | len=%d  | patern=0x%08X ]', start_address, length, patern)
        # Prepare FillMemory command
        cmd = [self.__command.FillMemory, 0x00, 0x00, 0x03]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(length, 4)
        cmd += long_to_array(pattern, 4)
        # Process FillMemory command
        self.__process_cmd(cmd)

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
        cmd = [self.__command.Execute, 0x00, 0x00, 0x03]
        cmd += long_to_array(jump_address, 4)
        cmd += long_to_array(argument, 4)
        cmd += long_to_array(sp_address, 4)
        # Process Execute command
        self.__process_cmd(cmd)

    def call(self, call_address, argument, sp_address):
        """ KBoot: Fill MCU memory with specified pattern
        :param call_address: Call address (must be word aligned)
        :param argument: Function arguments address
        :param sp_address: Stack pointer address
        """
        logging.info('TX-CMD: Call [ CallAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', call_address, argument, sp_address)
        # Prepare Call command
        cmd = [self.__command.Call, 0x00, 0x00, 0x03]
        cmd += long_to_array(call_address, 4)
        cmd += long_to_array(argument, 4)
        cmd += long_to_array(sp_address, 4)
        # Process Execute command
        self.__process_cmd(cmd)

    def reset(self):
        """ KBoot: Reset MCU
        """
        logging.info('TX-CMD: Reset MCU')
        # Prepare Reset command
        cmd = [self.__command.Reset, 0x00, 0x00, 0x00]
        # Process Reset command
        try:
            self.__process_cmd(cmd)
        except:
            pass


class KBootGenericError(Exception):
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


class KBootCommandError(KBootGenericError):
    _fmt = 'Command operation break: %(errval)s'

class KBootDataError(KBootGenericError):
    _fmt = 'Data %(mode)s break: %(errval)s'

class KBootConnectionError(KBootGenericError):
    _fmt = 'KBoot connection error'

class KBootTimeoutError(KBootGenericError):
    _fmt = 'KBoot timeout error'
