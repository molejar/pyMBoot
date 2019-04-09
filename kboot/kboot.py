# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

import sys
import logging
from struct import pack, unpack_from
from easy_enum import EEnum as Enum

# relative import
from .misc import atos
from .uart import UARTIF
from .usb import RawHid


########################################################################################################################
# KBoot Exceptions
########################################################################################################################
class KBootGenericError(Exception):
    """ Base Exception class for KBoot module """

    _fmt = 'KBoot Error'

    def __init__(self, msg=None, **kw):
        """ Initialize the Exception with given message. """
        self.msg = msg
        for key, value in kw.items():
            setattr(self, key, value)

    def __str__(self):
        """ Return the Exception message. """
        if self.msg:
            return self.msg
        try:
            return self._fmt % self.__dict__
        except (NameError, ValueError, KeyError):
            e = sys.exc_info()[1]  # current exception
            return 'Unprintable exception %s: %s' % (repr(e), str(e))

    def get_error_value(self):
        return getattr(self, 'errval', -1)


class KBootCommandError(KBootGenericError):
    _fmt = 'Command operation break -> %(errname)s'

    def __init__(self, msg=None, **kw):
        super().__init__(msg, **kw)

        if getattr(self, 'errname', None) is None:
            setattr(self, 'errname', 'ErrorCode = %d' % self.get_error_value())


class KBootDataError(KBootGenericError):
    _fmt = 'Data %(mode)s break -> %(errname)s'

    def __init__(self, msg=None, **kw):
        super().__init__(msg, **kw)

        if getattr(self, 'errname', None) is None:
            setattr(self, 'errname', 'ErrorCode = %d' % self.get_error_value())


class KBootConnectionError(KBootGenericError):
    _fmt = 'KBoot connection error'


class KBootTimeOutError(KBootGenericError):
    _fmt = 'KBoot timeout error'


########################################################################################################################
# KBoot Enums
########################################################################################################################
class EnumCommandTag(Enum):
    """ KBoot Commands """

    FLASH_ERASE_ALL = (0x01, 'FlashEraseAll', 'Erase Complete Flash')
    FLASH_ERASE_REGION = (0x02, 'FlashEraseRegion', 'Erase Flash Region')
    READ_MEMORY = (0x03, 'ReadMemory', 'Read Memory')
    WRITE_MEMORY = (0x04, 'WriteMemory', 'Write Memory')
    FILL_MEMORY = (0x05, 'FillMemory', 'Fill Memory')
    FLASH_SECURITY_DISABLE = (0x06, 'FlashSecurityDisable', 'Disable Flash Security')
    GET_PROPERTY = (0x07, 'GetProperty', 'Get Property')
    RECEIVE_SB_FILE = (0x08, 'ReceiveSBFile', 'Receive SB File')
    EXECUTE = (0x09, 'Execute', 'Execute')
    CALL = (0x0A, 'Call', 'Call')
    RESET = (0x0B, 'Reset', 'Reset MCU')
    SET_PROPERTY = (0x0C, 'SetProperty', 'Set Property')
    FLASH_ERASE_ALL_UNSECURE = (0x0D, 'FlashEraseAllUnsecure', 'Erase Complete Flash and Unlock')
    FLASH_PROGRAM_ONCE = (0x0E, 'FlashProgramOnce', 'Flash Program Once')
    FLASH_READ_ONCE = (0x0F, 'FlashReadOnce', 'Flash Read Once')
    FLASH_READ_RESOURCE = (0x10, 'FlashReadResource', 'Flash Read Resource')
    CONFIGURE_MEMORY = (0x11, 'ConfigureMemory', 'Configure Quad-SPI Memory')
    RELIABLE_UPDATE = (0x12, 'ReliableUpdate', 'Reliable Update')
    GENERATE_KEY_BLOB = (0x13, 'GenerateKeyBlob', 'Generate Key Blob')
    GENERATE_KEY_BLOB_RESPONSE = (0xb3, 'GenerateKeyBlobResponse', 'Generate Key Blob Response')
    KEY_PROVISIONING = (0x15, 'KeyProvisioning', 'Key Provisioning')
    KEY_PROVISIONING_RESPONSE = (0xb5, 'KeyProvisionResponse', 'Key Provision Response')
    LOAD_IMAGE = (0x16, 'LoadImage', 'Load Image')


class EnumProperty(Enum):
    """ KBoot Property constants """

    LIST_PROPERTIES = (0x00, 'ListProperties', 'List Properties')
    CURRENT_VERSION = (0x01, 'CurrentVersion', 'Current Version')
    AVAILABLE_PERIPHERALS = (0x02, 'AvailablePeripherals', 'Available Peripherals')
    FLASH_START_ADDRESS = (0x03, 'FlashStartAddress', 'Flash Start Address')
    FLASH_SIZE = (0x04, 'FlashSize', 'Flash Size')
    FLASH_SECTOR_SIZE = (0x05, 'FlashSectorSize', 'Flash Sector Size')
    FLASH_BLOCK_COUNT = (0x06, 'FlashBlockCount', 'Flash Block Count')
    AVAILABLE_COMMANDS = (0x07, 'AvailableCommands', 'Available Commands')
    CRC_CHECK_STATUS = (0x08, 'CrcCheckStatus', 'CRC Check Status')
    VERIFY_WRITES = (0x0A, 'VerifyWrites', 'Verify Writes')
    MAX_PACKET_SIZE = (0x0B, 'MaxPacketSize', 'Max Packet Size')
    RESERVED_REGIONS = (0x0C, 'ReservedRegions', 'Reserved Regions')
    VALIDATE_REGIONS = (0x0D, 'ValidateRegions', 'Validate Regions')
    RAM_START_ADDRESS = (0x0E, 'RAMStartAddress', 'RAM Start Address')
    RAM_SIZE = (0x0F, 'RAMSize', 'RAM Size')
    SYSTEM_DEVICE_IDENT = (0x10, 'SystemDeviceIdent', 'System Device Identification')
    FLASH_SECURITY_STATE = (0x11, 'FlashSecurityState', 'Flash Security State')
    UNIQUE_DEVICE_IDENT = (0x12, 'UniqueDeviceIdent', 'Unique Device Identification')
    FLASH_FAC_SUPPORT = (0x13, 'FlashFacSupport', 'Flash Fac. Support')
    FLASH_ACCESS_SEGMENT_SIZE = (0x14, 'FlashAccessSegmentSize', 'Flash Access Segment Size')
    FLASH_ACCESS_SEGMENT_COUNT = (0x15, 'FlashAccessSegmentCount', 'Flash Access Segment Count')
    FLASH_READ_MARGIN = (0x16, 'FlashReadMargin', 'Flash Read Margin')
    QSPI_INIT_STATUS = (0x17, 'QspiInitStatus', 'QuadSPI Initialization Status')
    TARGET_VERSION = (0x18, 'TargetVersion', 'Target Version')
    EXTERNAL_MEMORY_ATTRIBUTES = (0x19, 'ExternalMemoryAttributes', 'External Memory Attributes')
    RELIABLE_UPDATE_STATUS = (0x1A, 'ReliableUpdateStatus', 'Reliable Update Status')
    FLASH_PAGE_SIZE = (0x1B, 'FlashPageSize', 'Flash Page Size')
    IRQ_NOTIFIER_PIN = (0x1C, 'IrqNotifierPin', 'Irq Notifier Pin')
    PFR_KEYSTORE_UPDATE_OPT = (0x1D, 'PfrKeystoreUpdateOpt', 'PFR Keystore Update Opt')


class EnumStatus(Enum):
    """ Generic status codes """

    SUCCESS = (0, 'Success', 'Success')
    FAIL = (1, 'Fail', 'Fail')
    READ_ONLY = (2, 'ReadOnly', 'Read Only Error')
    OUT_OF_RANGE = (3, 'OutOfRange', 'Out Of Range Error')
    INVALID_ARGUMENT = (4, 'InvalidArgument', 'Invalid Argument Error')
    TIMEOUT = (5, 'Timeout', 'Timeout Error')
    NO_TRANSFER_IN_PROGRESS = (6, 'NoTransferInProgress', 'No Transfer In Progress Error')

    # Flash driver errors.
    FLASH_SIZE_ERROR = (100, 'FlashSizeError', 'FLASH Driver: Size Error')
    FLASH_ALIGNMENT_ERROR = (101, 'FlashAlignmentError', 'FLASH Driver: Alignment Error')
    FLASH_ADDRESS_ERROR = (102, 'FlashAddressError', 'FLASH Driver: Address Error')
    FLASH_ACCESS_ERROR = (103, 'FlashAccessError', 'FLASH Driver: Access Error')
    FLASH_PROTECTION_VIOLATION = (104, 'FlashProtectionViolation', 'FLASH Driver: Protection Violation')
    FLASH_COMMAND_FAILURE = (105, 'FlashCommandFailure', 'FLASH Driver: Command Failure')
    FLASH_UNKNOWN_PROPERTY = (106, 'FlashUnknownProperty', 'FLASH Driver: Unknown Property')

    # I2C driver errors.
    I2C_SLAVE_TX_UNDERRUN = (200, 'I2cSlaveTxUnderrun', 'I2C Driver: Slave Tx Underrun')
    I2C_SLAVE_RX_OVERRUN = (201, 'I2cSlaveRxOverrun', 'I2C Driver: Slave Rx Overrun')
    I2C_ARBITRATION_LOST = (202, 'I2cArbitrationLost', 'I2C Driver: Arbitration Lost')

    # SPI driver errors.
    SPI_SLAVE_TX_UNDERRUN = (300, 'SpiSlaveTxUnderrun', 'SPI Driver: Slave Tx Underrun')
    SPI_SLAVE_RX_OVERRUN = (301, 'SpiSlaveRxOverrun', 'SPI Driver: Slave Rx Overrun')

    # QuadSPI driver errors
    QSPI_FLASH_SIZE_ERROR = (400, 'QspiFlashSizeError', 'QSPI Driver: Flash Size Error')
    QSPI_FLASH_ALIGNMENT_ERROR = (401, 'QspiFlashAlignmentError', 'QSPI Driver: Flash Alignment Error')
    QSPI_FLASH_ADDRESS_ERROR = (402, 'QspiFlashAddressError', 'QSPI Driver: Flash Address Error')
    QSPI_FLASH_COMMAND_FAILURE = (403, 'QspiFlashCommandFailure', 'QSPI Driver: Flash Command Failure')
    QSPI_FLASH_UNKNOWN_PROPERTY = (404, 'QspiFlashUnknownProperty', 'QSPI Driver: Flash Unknown Property')
    QSPI_NOT_CONFIGURED = (405, 'QspiNotConfigured', 'QSPI Driver: Not Configured')
    QSPI_COMMAND_NOT_SUPPORTED = (406, 'QspiCommandNotSupported', 'QSPI Driver: Command Not Supported')

    # Bootloader errors.
    UNKNOWN_COMMAND = (10000, 'UnknownCommand', 'Unknown Command')
    SECURITY_VIOLATION = (10001, 'SecurityViolation', 'Security Violation')
    ABORT_DATA_PHASE = (10002, 'AbortDataPhase', 'Abort Data Phase')
    PING_ERROR = (10003, 'PingError', 'Ping Error')
    NO_RESPONSE = (10004, 'NoResponse', 'No Response')
    NO_RESPONSE_EXPECTED = (10005, 'NoResponseExpected', 'No Response Expected')
    UNSUPPORTED_COMMAND = (10006, 'UnsupportedCommand', 'Unsupported Command')

    # SB loader errors.
    ROMLDR_SECTION_OVERRUN = (10100, 'RomLdrSectionOverrun', 'ROM Loader: Section Overrun')
    ROMLDR_SIGNATURE = (10101, 'RomLdrSignature', 'ROM Loader: Signature Error')
    ROMLDR_SECTION_LENGTH = (10102, 'RomLdrSectionLength', 'ROM Loader: Section Length Error')
    ROMLDR_UNENCRYPTED_ONLY = (10103, 'RomLdrUnencryptedOnly', 'ROM Loader: Unencrypted Only')
    ROMLDR_EOF_REACHED = (10104, 'RomLdrEOFReached', 'ROM Loader: EOF Reached')
    ROMLDR_CHECKSUM = (10105, 'RomLdrChecksum', 'ROM Loader: Checksum Error')
    ROMLDR_CRC32_ERROR = (10106, 'RomLdrCrc32Error', 'ROM Loader: CRC32 Error')
    ROMLDR_UNKNOWN_COMMAND = (10107, 'RomLdrUnknownCommand', 'ROM Loader: Unknown Command')
    ROMLDR_ID_NOT_FOUND = (10108, 'RomLdrIdNotFound', 'ROM Loader: ID Not Found')
    ROMLDR_DATA_UNDERRUN = (10109, 'RomLdrDataUnderrun', 'ROM Loader: Data Underrun')
    ROMLDR_JUMP_RETURNED = (10110, 'RomLdrJumpReturned', 'ROM Loader: Jump Returned')
    ROMLDR_CALL_FAILED = (10111, 'RomLdrCallFailed', 'ROM Loader: Call Failed')
    ROMLDR_KEY_NOT_FOUND = (10112, 'RomLdrKeyNotFound', 'ROM Loader: Key Not Found')
    ROMLDR_SECURE_ONLY = (10113, 'RomLdrSecureOnly', 'ROM Loader: Secure Only')
    ROMLDR_RESET_RETURNED = (10114, 'RomLdrResetReturned', 'ROM Loader: Reset Returned')
    ROMLDR_ROLLBACK_BLOCKED = (10115, 'RomLdrRollbackBlocked', 'ROM Loader: Rollback Blocked')
    ROMLDR_INVALID_SECTION_MAC_COUNT = (10116, 'RomLdrInvalidSectionMacCount', 'ROM Loader: Invalid Section Mac Count')
    ROMLDR_UNEXPECTED_COMMAND = (10117, 'RomLdrUnexpectedCommand', 'ROM Loader: Unexpected Command')

    # Memory interface errors.
    MEMORY_RANGE_INVALID = (10200, 'MemoryRangeInvalid', 'Memory Range Invalid')
    MEMORY_READ_FAILED = (10201, 'MemoryReadFailed', 'Memory Read Failed')
    MEMORY_WRITE_FAILED = (10202, 'MemoryWriteFailed', 'Memory Write Failed')

    # Property store errors.
    UNKNOWN_PROPERTY = (10300, 'UnknownProperty', 'Unknown Property')
    READ_ONLY_PROPERTY = (10301, 'ReadOnlyProperty', 'Read Only Property')
    INVALID_PROPERTY_VALUE = (10302, 'InvalidPropertyValue', 'Invalid Property Value')

    # Property store errors.
    APP_CRC_CHECK_PASSED = (10400, 'AppCrcCheckPassed', 'Application CRC Check: Passed')
    APP_CRC_CHECK_FAILED = (10401, 'AppCrcCheckFailed', 'Application: CRC Check: Failed')
    APP_CRC_CHECK_INACTIVE = (10402, 'AppCrcCheckInactive', 'Application CRC Check: Inactive')
    APP_CRC_CHECK_INVALID = (10403, 'AppCrcCheckInvalid', 'Application CRC Check: Invalid')
    APP_CRC_CHECK_OUT_OF_RANGE = (10404, 'AppCrcCheckOutOfRange', 'Application CRC Check: Out Of Range')


########################################################################################################################
# KBoot USB interface
########################################################################################################################

DEVICES = {
    # NAME   | VID   | PID
    'MKL27': (0x15A2, 0x0073),
    'LPC55': (0x1FC9, 0x0021)
}


def scan_usb(device_name=None):
    """ KBoot: Scan commected USB devices
    :rtype : object
    """
    devs = []

    if device_name is None:
        for name, value in DEVICES.items():
            devs += RawHid.enumerate(value[0], value[1])
    else:
        if ':' in device_name:
            vid, pid = device_name.split(':')
            devs = RawHid.enumerate(int(vid, 0), int(pid, 0))
        else:
            if device_name in DEVICES:
                vid = DEVICES[device_name][0]
                pid = DEVICES[device_name][1]
                devs = RawHid.enumerate(vid, pid)
    return devs


def scan_uart():
    raise NotImplemented("Function is not implemented")


########################################################################################################################
# KBoot Main Class
########################################################################################################################
class KBoot(object):

    HID_REPORT = {
        # KBoot USB HID Reports.
        'CMD_OUT': 0x01,
        'CMD_IN': 0x03,
        'DATA_OUT': 0x02,
        'DATA_IN': 0x04
    }

    INTERFACES = {
        #  KBoot Interface | mask | default speed
        'UART':      [0x00000001, 115200],
        'I2C-Slave': [0x00000002, 400],
        'SPI-Slave': [0x00000004, 400],
        'CAN':       [0x00000008, 500],
        'USB-HID':   [0x00000010, 12000000],
        'USB-CDC':   [0x00000020, 12000000],
        'USB-DFU':   [0x00000040, 12000000],
    }

    class __fptype(Enum):
        # KBoot Framing Packet Type.
        ACK = 0xA1
        NACK = 0xA2
        ABORT = 0xA3
        CMD = 0xA4
        DATA = 0xA5
        PING = 0xA6
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
        if prop_tag == EnumProperty.CURRENT_VERSION:
            str_value = "{0:d}.{1:d}.{2:d}".format((raw_value >> 16) & 0xFF,
                                                   (raw_value >> 8) & 0xFF,
                                                   raw_value & 0xFF)
        elif prop_tag == EnumProperty.AVAILABLE_PERIPHERALS:
            str_value = []
            for key, value in self.INTERFACES.items():
                if value[0] & raw_value:
                    str_value.append(key)
        elif prop_tag == EnumProperty.FLASH_SECURITY_STATE:
            str_value = 'Unlocked' if raw_value == 0 else 'Locked'
        elif prop_tag == EnumProperty.AVAILABLE_COMMANDS:
            str_value = []
            for name, value, desc in EnumCommandTag:
                if (1 << value) & raw_value:
                    str_value.append(name)
        elif prop_tag in (EnumProperty.MAX_PACKET_SIZE, EnumProperty.FLASH_SECTOR_SIZE, EnumProperty.FLASH_SIZE,
                          EnumProperty.RAM_SIZE):
            if raw_value >= 1024:
                str_value = '{0:d}kB'.format(raw_value // 1024)
            else:
                str_value = '{0:d}B'.format(raw_value)
        elif prop_tag in (EnumProperty.RAM_START_ADDRESS, EnumProperty.FLASH_START_ADDRESS,
                          EnumProperty.SYSTEM_DEVICE_IDENT):
            str_value = '0x{:08X}'.format(raw_value)
        else:
            str_value = '{:d}'.format(raw_value)
        # ---
        logging.info('RX-CMD: %s = %s', EnumProperty[prop_tag], str_value)
        return {'raw_value': raw_value, 'string': str_value}

    def _process_cmd(self, data, timeout=1000):
        """Process Command Data
        :rtype : object
        """
        if self._usb_dev is None and self._uart_dev is None:
            logging.info('RX-CMD: USB Disconnected')
            raise KBootConnectionError('USB Disconnected')

        # log TX raw command data
        logging.debug('TX-CMD [%02d]: %s', len(data), atos(data))

        if self._usb_dev:
            # Send USB-HID CMD OUT Report
            self._usb_dev.write(self.HID_REPORT['CMD_OUT'], data)

            # Read USB-HID CMD IN Report
            try:
                rxpkg = self._usb_dev.read(timeout)[1]
            except:
                logging.info('RX-CMD: USB Disconnected')
                raise KBootTimeOutError('USB Disconnected')
        else:
            # Send UART
            self._uart_dev.write(self.__fptype.CMD, data)

            # Read USB-HID CMD IN Report
            try:
                rxpkg = self._uart_dev.read()[1]
            except:
                logging.info('RX-CMD: UART Disconnected')
                raise KBootTimeOutError('UART Disconnected')

        # log RX raw command data
        logging.debug('RX-CMD [%02d]: %s', len(rxpkg), atos(rxpkg))

        # Parse and validate status flag
        status = self._parse_status(rxpkg)
        if status != EnumStatus.SUCCESS:
            if EnumStatus.is_valid(status):
                logging.info('RX-CMD: %s', EnumStatus[status])
                raise KBootCommandError(errname=EnumStatus[status], errval=status)
            else:
                logging.info('RX-CMD: Unknown Error %d', status)
                raise KBootCommandError(errval=status)

        return rxpkg

    def _read_data(self, length, timeout=1000):
        n = 0
        data = bytearray()
        pg_dt = float(self._pg_end - self._pg_start) / length
        self._abort = False

        if self._usb_dev is None and self._uart_dev is None:
            logging.info('RX-DATA: Disconnected')
            raise KBootConnectionError('Disconnected')

        while n < length:
            # Read USB-HID DATA IN Report
            try:
                rep_id, pkg = self._usb_dev.read(timeout)
            except:
                logging.info('RX-DATA: USB Disconnected')
                raise KBootTimeOutError('USB Disconnected')

            if rep_id != self.HID_REPORT['DATA_IN']:
                status = self._parse_status(pkg)
                if EnumStatus.is_valid(status):
                    logging.info('RX-DATA: %s' % EnumStatus.desc(status))
                    raise KBootDataError(mode='read', errname=EnumStatus.desc(status), errval=status)
                else:
                    logging.info('RX-DATA: Unknown Error %d' % status)
                    raise KBootDataError(mode='read', errval=status)

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
            raise KBootTimeOutError('USB Disconnected')

        # Parse and validate status flag
        status = self._parse_status(pkg)
        if status != EnumStatus.SUCCESS:
            if EnumStatus.is_valid(status):
                logging.info('RX-DATA: %s' % EnumStatus.desc(status))
                raise KBootDataError(mode='read', errname=EnumStatus.desc(status), errval=status)
            else:
                logging.info('RX-DATA: Unknown Error %d' % status)
                raise KBootDataError(mode='read', errval=status)

        logging.info('RX-DATA: Successfully Received %d Bytes', len(data))
        return data

    def _send_data(self, data):
        n = len(data)
        start = 0
        pg_dt = float(self._pg_end - self._pg_start) / n
        self._abort = False

        if self._usb_dev is None and self._uart_dev is None:
            logging.info('TX-DATA: Disconnected')
            raise KBootConnectionError('Disconnected')

        while n > 0:
            length = 0x20
            if n < length:
                length = n
            txbuf = data[start:start + length]

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
            raise KBootTimeOutError('USB Disconnected')

        # Parse and validate status flag
        status = self._parse_status(pkg)
        if status != EnumStatus.SUCCESS:
            logging.info('TX-DATA: %s' % EnumStatus[status])
            raise KBootDataError(mode='write', errname=EnumStatus[status], errval=status)

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

        for prop_name, prop_value, _ in EnumProperty:
            try:
                value = self.get_property(prop_value)
            except KBootCommandError:
                continue
            mcu_info.update({prop_name: value})

        return mcu_info

    def flash_erase_all(self):
        """ KBoot: Erase complete flash memory without recovering flash security section
        """
        logging.info('TX-CMD: FlashEraseAll')
        # Prepare FlashEraseAll command
        cmd = pack('4B', EnumCommandTag.FLASH_ERASE_ALL, 0x00, 0x00, 0x00)
        # Process FlashEraseAll command
        self._process_cmd(cmd)

    def flash_erase_region(self, start_address, length):
        """ KBoot: Erase specified range of flash
        :param start_address: Start address
        :param length: Count of bytes
        """
        logging.info('TX-CMD: FlashEraseRegion [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare FlashEraseRegion command
        cmd = pack('<4B2I', EnumCommandTag.FLASH_ERASE_REGION, 0x00, 0x00, 0x02, start_address, length)
        # Process FlashEraseRegion command
        self._process_cmd(cmd, 5000)

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
        cmd = pack('<4B2I', EnumCommandTag.READ_MEMORY, 0x00, 0x00, 0x02, start_address, length)
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
        cmd = pack('<4B2I', EnumCommandTag.WRITE_MEMORY, 0x00, 0x00, 0x03, start_address, len(data))
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
        logging.info('TX-CMD: FillMemory [ address=0x%08X | len=%d  | patern=0x%08X ]', start_address, length, pattern)
        # Prepare FillMemory command
        cmd = pack('<4B3I', EnumCommandTag.FILL_MEMORY, 0x00, 0x00, 0x03, start_address, length, pattern)
        # Process FillMemory command
        self._process_cmd(cmd)

    def flash_security_disable(self, backdoor_key):
        """ KBoot: Disable flash security by backdoor key
        :param backdoor_key:
        """
        logging.info('TX-CMD: FlashSecurityDisable [ backdoor_key [0x] = %s ]', atos(backdoor_key))
        # Prepare FlashSecurityDisable command
        cmd = pack('4B', EnumCommandTag.FLASH_SECURITY_DISABLE, 0x00, 0x00, 0x02)
        if len(backdoor_key) < 8:
            raise ValueError('Short range of backdoor key')
        cmd += bytes(backdoor_key[3::-1])
        cmd += bytes(backdoor_key[:3:-1])
        # Process FlashSecurityDisable command
        self._process_cmd(cmd)

    def get_property(self, prop_tag, ext_mem_identifier=None):
        """ KBoot: Get value of specified property
        :param prop_tag: The property ID (see Property enumerator)
        :param ext_mem_identifier:
        :return {dict} with 'RAW' and 'STRING/LIST' value
        """
        prop_tag = int(prop_tag)
        logging.info('TX-CMD: GetProperty->%s', EnumProperty[prop_tag])
        # Prepare GetProperty command
        if ext_mem_identifier is None:
            cmd = pack('<4BI', EnumCommandTag.GET_PROPERTY, 0x00, 0x00, 0x01, prop_tag)
        else:
            cmd = pack('<4B2I', EnumCommandTag.GET_PROPERTY, 0x00, 0x00, 0x02, prop_tag, ext_mem_identifier)
        # Process GetProperty command
        rpkg = self._process_cmd(cmd)
        # Parse property value
        return self._parse_property(prop_tag, rpkg)

    def set_property(self, prop_tag, value):
        """ KBoot: Set value of specified property
        :param  property_tag: The property ID (see Property enumerator)
        :param  value: The value of selected property
        """
        logging.info('TX-CMD: SetProperty->%s = %d', EnumProperty[prop_tag], value)
        # Prepare SetProperty command
        cmd = pack('<4B2I', EnumCommandTag.SET_PROPERTY, 0x00, 0x00, 0x02, prop_tag, value)
        # Process SetProperty command
        self._process_cmd(cmd)

    def receive_sb_file(self, data):
        """ KBoot: Receive SB file
        :param  data: SB file data
        """
        if len(data) == 0:
            raise ValueError('Data len is zero')
        logging.info('TX-CMD: Receive SB file [ len=%d ]', len(data))
        # Prepare WriteMemory command
        cmd = pack('<4BI', EnumCommandTag.RECEIVE_SB_FILE, 0x00, 0x00, 0x02, len(data))
        # Process WriteMemory command
        self._process_cmd(cmd)
        # Process Write Data
        return self._send_data(data)

    def execute(self, jump_address, argument, sp_address):
        """ KBoot: Fill MCU memory with specified pattern
        :param jump_address: Jump address (must be word aligned)
        :param argument: Function arguments address
        :param sp_address: Stack pointer address
        """
        logging.info('TX-CMD: Execute [ JumpAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', jump_address, argument,
                     sp_address)
        # Prepare Execute command
        cmd = pack('<4B3I', EnumCommandTag.EXECUTE, 0x00, 0x00, 0x03, jump_address, argument, sp_address)
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
        cmd = pack('<4B3I', EnumCommandTag.CALL, 0x00, 0x00, 0x03, call_address, argument, sp_address)
        # Process Call command
        self._process_cmd(cmd)

    def reset(self):
        """ KBoot: Reset MCU """
        logging.info('TX-CMD: Reset MCU')
        # Prepare Reset command
        cmd = pack('4B', EnumCommandTag.RESET, 0x00, 0x00, 0x00)
        # Process Reset command
        try:
            self._process_cmd(cmd)
        except:
            pass

    def flash_erase_all_unsecure(self):
        """ KBoot: Erase complete flash memory and recover flash security section
        """
        logging.info('TX-CMD: FlashEraseAllUnsecure')
        # Prepare FlashEraseAllUnsecure command
        cmd = pack('4B', EnumCommandTag.FLASH_ERASE_ALL_UNSECURE, 0x00, 0x00, 0x00)
        # Process FlashEraseAllUnsecure command
        self._process_cmd(cmd)

    def flash_read_once(self, index, length):
        """ KBoot: Read from MCU flash program once region (max 8 bytes)
        :param index: Start index
        :param length: Count of bytes
        :return List of bytes
        """
        if (index + length) > 8:
            length = 8 - index
        if length == 0:
            raise ValueError('Index out of range')
        logging.info('TX-CMD: FlashReadOnce [ Index=%d | len=%d   ]', index, length)
        # Prepare FlashReadOnce command
        cmd = pack('<4B2I', EnumCommandTag.FLASH_READ_ONCE, 0x00, 0x00, 0x02, index, length)
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
        if (index + length) > 8:
            length = 8 - index
        if length == 0:
            raise ValueError('Index out of range')
        logging.info('TX-CMD: FlashProgramOnce [ Index=%d | Data[0x]: %s  ]', index, atos(data[:length]))
        # Prepare FlashProgramOnce command
        cmd = pack('<4B2I', EnumCommandTag.FLASH_PROGRAM_ONCE, 0x00, 0x00, 0x03, index, length)
        cmd += bytes(data)
        # Process FlashProgramOnce command
        self._process_cmd(cmd)
        return length

    def flash_read_resource(self, start_address, length, option=1):
        """ KBoot: Read resource of flash module
        :param start_address:
        :param length:
        :param option:
        :return resource list
        """
        logging.info('TX-CMD: FlashReadResource [ StartAddr=0x%08X | len=%d ]', start_address, length)
        # Prepare FlashReadResource command
        cmd = pack('<4B3I', EnumCommandTag.FLASH_READ_RESOURCE, 0x00, 0x00, 0x03, start_address, length, option)
        # Process FlashReadResource command
        pkg = self._process_cmd(cmd)
        rx_len = self._parse_value(pkg)
        length = min(length, rx_len)
        # Process Read Data
        return self._read_data(length)

    def configure_memory(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"configure_memory()\" not implemented yet')

    def reliable_update(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"reliable_update()\" not implemented yet')

    def generate_key_blob(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"generate_key_blob()\" not implemented yet')

    def generate_key_blob_response(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"generate_key_blob_response()\" not implemented yet')

    def key_provisioning(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"key_provisioning()\" not implemented yet')

    def key_provisioning_response(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"key_provisioning_response()\" not implemented yet')

    def load_image(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"load_image()\" not implemented yet')
