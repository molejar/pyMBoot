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

    def __get_status_value(self, data):
        return array_to_long(data[4:8])

    def __process_cmd(self, data):
        """Process Command Data
        :rtype : object
        """
        if self.__usb_dev is None:
            logging.info('USB Is Disconnected')                               # log status info
            return (-1, None)
        logging.debug('TX-CMD [0x]: %s', array_to_string(data))               # log TX raw command data
        try:
            self.__usb_dev.write(self.__hidreport.CMD_OUT, data)                 # send USB-HID command OUT report
            rep_id, rxpkg = self.__usb_dev.read()                               # receive USB-HID command IN report
            status = self.__get_status_value(rxpkg)                           #
            logging.debug('RX-CMD [0x]: %s', array_to_string(rxpkg))          # log RX raw command data
            if status != Status.Success:
                logging.info('RX-CMD: %s', Status(status).name)               # log status info
        except Exception as e:
            logging.error('RX-CMD: %s', str(e))                               # log status info
            return (-1, None)
        return (status, rxpkg)

    def __read_data(self, length):
        n = 0
        data = []
        pg_dt = float(self.__pg_end - self.__pg_start)/length
        if self.__usb_dev is None:
            logging.info('USB Is Disconnected')                               # log status info
            return (-1, None)
        try:
            self.__abort = False
            while n < length:
                rep_id, pkg = self.__usb_dev.read()                             # receive USB-HID command IN report
                if rep_id != self.__hidreport.DATA_IN:
                    status = self.__get_status_value(pkg)
                    logging.error('RX-DATA: %s', Status(status).name)           # log error info
                    return (status, None)
                data += pkg
                n += len(pkg)
                if self.__pg_func:
                    self.__pg_func(self.__pg_start + int(n * pg_dt))
                if self.__abort:
                    logging.info('RX-DATA: Aborted By User')                  # log error info
                    return (-1, None)
            rep_id, pkg = self.__usb_dev.read()                                 # receive USB-HID command IN report
            status = self.__get_status_value(pkg)
            if status != Status.Success:
                logging.error('RX-DATA: %s', Status(status).name)              # log status info
            else:
                logging.info('RX-DATA: Successfully Received %d Bytes', len(data))
        except IOError as e:
            logging.error('RX-DATA: %s', str(e))                              # log status error
            if e.errno == 19:
                return (-1, None)
            else:
                return (Status.Fail, None)
        except Exception as e:
            logging.error('RX-DATA: %s', str(e))                              # log status error
            return (-1, None)
        return (status, data)

    def __send_data(self, data):
        n = len(data)
        start = 0
        pg_dt = float(self.__pg_end - self.__pg_start)/n
        if self.__usb_dev is None:
            logging.info('USB Is Disconnected')                               # log status info
            return (-1, None)
        try:
            self.__abort = False
            while n > 0:
                length = 0x20
                if n < length:
                    length = n
                txbuf = data[start:start+length]
                self.__usb_dev.write(self.__hidreport.DATA_OUT, txbuf)         # send USB-HID command OUT report
                n -= length
                start += length
                if self.__pg_func:
                    self.__pg_func(self.__pg_start + int(start * pg_dt))
                if self.__abort:
                    logging.info('TX-DATA: Aborted By User')                  # log error info.
                    return (-1, None)
            rep_id, pkg = self.__usb_dev.read()                               # receive USB-HID command IN report
            status = self.__get_status_value(pkg)
            if status != Status.Success:
                logging.error('TX-DATA: %s', Status(status).name)             # log error info
            else:
                logging.info('TX-DATA: Send %d Bytes', len(data))             # log status info
        except IOError as e:
            logging.error('RX-DATA: %s', str(e))                              # log status error
            if e.errno == 19:
                return (-1, None)
            else:
                return (Status.Fail, None)
        except Exception as e:
            logging.error('TX-DATA: %s', str(e))                              # log error info
            return (-1, None)
        return status, pkg

    def set_handler(self, progressbar, start_val=0, end_val=100):
        self.__pg_func = progressbar
        self.__pg_start = start_val
        self.__pg_end = end_val

    def abort(self):
        self.__abort = True

    def scan_usb_devs(self, kboot_vid=DEFAULT_VID, kboot_pid=DEFAULT_PID):
        """Scan commected USB devices
        :rtype : object
        """
        devs = getAllConnectedTargets(kboot_vid, kboot_pid)

        if devs:
            logging.info('Founded MCUs with KBoot: %d', len(devs))
        else:
            logging.info('No MCU with KBoot detected')

        return devs

    def is_connected(self):
        if self.__usb_dev is not None:
            return True
        else:
            return False

    def connect(self, dev):
        if dev is not None:
            logging.info('Connect: %s', dev.getInfo())
            self.__usb_dev = dev
            self.__usb_dev.open()
            return True
        else:
            logging.info('USB Is Disconnected')                               # log status info
            return False

    def disconnect(self):
        if self.__usb_dev is not None:
            self.__usb_dev.close()
            self.__usb_dev = None

    def get_mcu_info(self):
        """ KBoot: Get MCU info
        :return
        """
        mcu_info = {}
        if self.__usb_dev is None:
            logging.info('USB Is Disconnected')                               # log status info
            return None
        for p in Property:
            status, value = self.get_property(p.value)
            if status != Status.Success:
                continue
            mcu_info.update({p.name : value})
        return mcu_info

    def get_property(self, property_tag, ext_mem_identifier=None):
        """ KBoot: Get property method
        :param property_tag:
        :param ext_mem_identifier:
        :return
        """
        logging.info('TX-CMD: GetProperty->%s', Property(property_tag).name)
        # Prepare GetProperty command
        cmd = [self.__command.GetProperty, 0x00, 0x00, 0x01]
        cmd += long_to_array(property_tag, 4)
        if ext_mem_identifier is not None:
            cmd[3] = 0x02  # change parameter count to 2
            cmd += long_to_array(ext_mem_identifier, 4)
        # Process GetProperty command
        status, rpkg = self.__process_cmd(cmd)
        if status != Status.Success:
            return status, None
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
        return status, { 'raw_value' : raw_value, 'string' : str_value }

    def set_property(self, property_tag, value):
        """ KBoot: Set property method
        :param  property_tag: The property ID (see Property enumerator)
        :param  value: The value of selected property
        :return Status value (0x0 if OK, for possible errors see Status enumerator)
        """
        logging.info('TX-CMD: SetProperty->%s = %d', Property(property_tag).name, value)
        # Prepare SetProperty command
        cmd = [self.__command.SetProperty, 0x00, 0x00, 0x02]
        cmd += long_to_array(property_tag, 4)
        cmd += long_to_array(value, 4)
        # Process SetProperty command
        return self.__process_cmd(cmd)[0]

    def flash_read_resource(self, start_address, byte_count, option=1):
        """ KBoot: Flash read resource method
        :param start_address:
        :param byte_count:
        :param option:
        :return Status value (0x0 if OK, for possible errors see Status enumerator)
        """
        logging.info('TX-CMD: FlashReadResource [ StartAddr=0x%08X | len=%d ]', start_address, byte_count)
        # Prepare FlashReadResource command
        cmd = [self.__command.FlashReadResource, 0x00, 0x00, 0x03]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(byte_count, 4)
        cmd += long_to_array(option, 4)
        # Process FlashReadResource command
        return self.__process_cmd(cmd)[0]

    def flash_security_disable(self, backdoor_key):
        """ KBoot: Flash security disable method
        :param backdoor_key:
        :return Status value (0x0 if OK, for possible errors see Status enumerator)
        """
        logging.info('TX-CMD: FlashSecurityDisable [ backdoor_key [0x] = %s ]', array_to_string(backdoor_key))
        # Prepare FlashSecurityDisable command
        cmd = [self.__command.FlashSecurityDisable, 0x00, 0x00, 0x01]
        cmd += backdoor_key
        # Process FlashSecurityDisable command
        return self.__process_cmd(cmd)[0]

    def flash_erase_region(self, start_address, length):
        """ KBoot: Flash erase region method
        :param start_address:
        :param length:
        :return Status value (0x0 if OK, for possible errors see Status enumerator)
        """
        logging.info('TX-CMD: FlashEraseRegion [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare FlashEraseRegion command
        cmd = [self.__command.FlashEraseRegion, 0x00, 0x00, 0x02]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(length, 4)
        # Process FlashEraseRegion command
        return self.__process_cmd(cmd)[0]

    def flash_erase_all(self):
        """ KBoot: Flash erase all method
        :return Status value (0x0 if OK, for possible errors see Status enumerator)
        """
        logging.info('TX-CMD: FlashEraseAll')
        # Prepare FlashEraseAll command
        cmd = [self.__command.FlashEraseAll, 0x00, 0x00, 0x00]
        # Process FlashEraseAll command
        return self.__process_cmd(cmd)[0]

    def flash_erase_all_unsecure(self):
        """ KBoot: Flash erase all unsecure method
        :return Status value (0x0 if OK, for possible errors see Status enumerator)
        """
        logging.info('TX-CMD: FlashEraseAllUnsecure')
        # Prepare FlashEraseAllUnsecure command
        cmd = [self.__command.FlashEraseAllUnsecure, 0x00, 0x00, 0x00]
        # Process FlashEraseAllUnsecure command
        return self.__process_cmd(cmd)[0]

    def flash_program_once(self, index, data):

        if len(data) > 8:
            logging.error("Data Length is over 8 bytes")
            return Status.Fail
        logging.info('TX-CMD: FlashProgramOnce [ Index=%d | Data[0x]: %s  ]', index, array_to_string(data))
        # Prepare FlashProgramOnce command
        cmd = [self.__command.FlashProgramOnce, 0x00, 0x00, 0x03]
        cmd += long_to_array(index, 4)
        cmd += long_to_array(len(data), 4)
        cmd += data
        # Process FlashProgramOnce command
        status = self.__process_cmd(cmd)[0]
        if status == Status.Success:
            # Process Write Data
            status = self.__send_data(data)[0]
        return status

    def flash_read_once(self, index, length):

        if length > 8:
            length = 8
        logging.info('TX-CMD: FlashReadOnce [ Index=%d | len=%d   ]', index, length)
        # Prepare FlashReadOnce command
        cmd = [self.__command.FlashReadOnce, 0x00, 0x00, 0x02]
        cmd += long_to_array(index, 4)
        cmd += long_to_array(length, 4)
        # Process FlashReadOnce command
        status, _ = self.__process_cmd(cmd)
        if status != Status.Success:
            return (status, 0)
        # Process Read Data
        status, rdata = self.__read_data(length)
        if status != Status.Success:
            return (status, 0)
        return (Status.Success, rdata)

    def read_memory(self, start_address, length):

        if length == 0:
            return (Status.InvalidArgument, 0)
        logging.info('TX-CMD: ReadMemory [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare ReadMemory command
        cmd = [self.__command.ReadMemory, 0x00, 0x00, 0x02]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(length, 4)
        # Process ReadMemory command
        status, _ = self.__process_cmd(cmd)
        if status != Status.Success:
            return (status, 0)
        # Process Read Data
        status, rdata = self.__read_data(length)
        if status != Status.Success:
            return (status, 0)
        return (Status.Success, rdata)

    def write_memory(self, start_address, data):

        if len(data) == 0:
            return (Status.InvalidArgument, 0)
        logging.info('TX-CMD: WriteMemory [ StartAddr=0x%08X | len=%d  ]', start_address, len(data))
        # Prepare WriteMemory command
        cmd = [self.__command.WriteMemory, 0x00, 0x00, 0x03]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(len(data), 4)
        # Process WriteMemory command
        status = self.__process_cmd(cmd)[0]
        if status == Status.Success:
            # Process Write Data
            status = self.__send_data(data)[0]
        return status

    def fill_memory(self, start_address, length, patern=0xFFFFFFFF):
        logging.info('TX-CMD: FillMemory [ StartAddr=0x%08X | len=%d  | patern=0x%08X ]', start_address, length, patern)
        # Prepare FillMemory command
        cmd = [self.__command.FillMemory, 0x00, 0x00, 0x03]
        cmd += long_to_array(start_address, 4)
        cmd += long_to_array(length, 4)
        cmd += long_to_array(patern, 4)
        # Process FillMemory command
        return self.__process_cmd(cmd)[0]

    def receive_sb_file(self):
        # TODO: Not implemented yet
        return Status.Fail

    def configure_quad_spi(self):
        # TODO: Not implemented yet
        return Status.Fail

    def execute(self, jump_address, argument, sp_address):
        logging.info('TX-CMD: Execute [ JumpAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', jump_address, argument, sp_address)
        # Prepare Execute command
        cmd = [self.__command.Execute, 0x00, 0x00, 0x03]
        cmd += long_to_array(jump_address, 4)
        cmd += long_to_array(argument, 4)
        cmd += long_to_array(sp_address, 4)
        # Process Execute command
        return self.__process_cmd(cmd)[0]

    def call(self, call_address, argument, sp_address):
        logging.info('TX-CMD: Call [ CallAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', call_address, argument, sp_address)
        # Prepare Call command
        cmd = [self.__command.Call, 0x00, 0x00, 0x03]
        cmd += long_to_array(call_address, 4)
        cmd += long_to_array(argument, 4)
        cmd += long_to_array(sp_address, 4)
        # Process Execute command
        return self.__process_cmd(cmd)[0]

    def reset(self):
        logging.info('TX-CMD: Reset MCU')
        # Prepare Reset command
        cmd = [self.__command.Reset, 0x00, 0x00, 0x00]
        # Process Reset command
        return self.__process_cmd(cmd)[0]
