# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

import sys
import logging
from struct import pack, unpack_from

# relative imports
from .enums import CommandTag, PropertyTag, StatusCode
from .misc import atos, size_fmt
from .uart import UART
from .usb import RawHID


########################################################################################################################
# Helper functions
########################################################################################################################

def decode_property_value(property_tag, raw_value):

    if property_tag == PropertyTag.CURRENT_VERSION:
        str_value = "{0:d}.{1:d}.{2:d}".format((raw_value >> 16) & 0xFF, (raw_value >> 8) & 0xFF, raw_value & 0xFF)

    elif property_tag == PropertyTag.AVAILABLE_PERIPHERALS:
        str_value = []
        for key, value in McuBoot.INTERFACES.items():
            if value[0] & raw_value:
                str_value.append(key)

    elif property_tag == PropertyTag.FLASH_SECURITY_STATE:
        str_value = 'Unlocked' if raw_value == 0 else 'Locked'

    elif property_tag == PropertyTag.AVAILABLE_COMMANDS:
        str_value = []
        for name, value, desc in CommandTag:
            if (1 << value) & raw_value:
                str_value.append(name)

    elif property_tag in (PropertyTag.MAX_PACKET_SIZE, PropertyTag.FLASH_SECTOR_SIZE,
                          PropertyTag.FLASH_SIZE, PropertyTag.RAM_SIZE):
        str_value = size_fmt(raw_value)

    elif property_tag in (PropertyTag.RAM_START_ADDRESS, PropertyTag.FLASH_START_ADDRESS,
                          PropertyTag.SYSTEM_DEVICE_IDENT):
        str_value = '0x{:08X}'.format(raw_value)

    else:
        str_value = '{:d}'.format(raw_value)

    return str_value


def is_command_available(command_tag, property_raw_value):
    return True if (1 << command_tag) & property_raw_value else False


########################################################################################################################
# McuBoot Exceptions
########################################################################################################################

class McuBootGenericError(Exception):
    """ Base Exception class for MBoot module """

    _fmt = 'MBoot Error'

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


class McuBootCommandError(McuBootGenericError):
    _fmt = 'Command operation break -> %(errname)s'

    def __init__(self, msg=None, **kw):
        super().__init__(msg, **kw)

        if getattr(self, 'errname', None) is None:
            setattr(self, 'errname', 'ErrorCode = %d' % self.get_error_value())


class McuBootDataError(McuBootGenericError):
    _fmt = 'Data %(mode)s break -> %(errname)s'

    def __init__(self, msg=None, **kw):
        super().__init__(msg, **kw)

        if getattr(self, 'errname', None) is None:
            setattr(self, 'errname', 'ErrorCode = %d' % self.get_error_value())


class McuBootConnectionError(McuBootGenericError):
    _fmt = 'MBoot connection error'


class McuBootTimeOutError(McuBootGenericError):
    _fmt = 'MBoot timeout error'


########################################################################################################################
# McuBoot interfaces
########################################################################################################################

DEVICES = {
    # NAME   | VID   | PID
    'MKL27': (0x15A2, 0x0073),
    'LPC55': (0x1FC9, 0x0021)
}


def scan_usb(device_name=None):
    """ MBoot: Scan connected USB devices
    :param device_name: The specific device name (MKL27, LPC55, ...) or VID:PID
    :rtype : list
    """
    devices = []

    if device_name is None:
        for name, value in DEVICES.items():
            devices += RawHID.enumerate(value[0], value[1])
    else:
        if ':' in device_name:
            vid, pid = device_name.split(':')
            devices = RawHID.enumerate(int(vid, 0), int(pid, 0))
        else:
            if device_name in DEVICES:
                vid = DEVICES[device_name][0]
                pid = DEVICES[device_name][1]
                devices = RawHID.enumerate(vid, pid)
    return devices


def scan_uart():
    raise NotImplemented("Function is not implemented")


########################################################################################################################
# McuBoot Class
########################################################################################################################

class McuBoot(object):

    HID_REPORT = {
        # MBoot USB HID Reports.
        'CMD_OUT': 0x01,
        'CMD_IN': 0x03,
        'DATA_OUT': 0x02,
        'DATA_IN': 0x04
    }

    INTERFACES = {
        #  MBoot Interface | mask | default speed
        'UART':      [0x00000001, 115200],
        'I2C-Slave': [0x00000002, 400],
        'SPI-Slave': [0x00000004, 400],
        'CAN':       [0x00000008, 500],
        'USB-HID':   [0x00000010, 12000000],
        'USB-CDC':   [0x00000020, 12000000],
        'USB-DFU':   [0x00000040, 12000000],
    }

    class _FPType:
        # MBoot Framing Packet Type.
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

    @staticmethod
    def _parse_status(data):
        return unpack_from('<I', data, 4)[0]

    @staticmethod
    def _parse_value(data):
        return unpack_from('<I', data, 8)[0]

    def _process_cmd(self, data, timeout=1000):
        """Process Command Data
        :rtype : object
        """
        if self._usb_dev is None and self._uart_dev is None:
            logging.info('RX-CMD: USB Disconnected')
            raise McuBootConnectionError('USB Disconnected')

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
                raise McuBootTimeOutError('USB Disconnected')
        else:
            # Send UART
            self._uart_dev.write(self._FPType.CMD, data)

            # Read USB-HID CMD IN Report
            try:
                rxpkg = self._uart_dev.read()[1]
            except:
                logging.info('RX-CMD: UART Disconnected')
                raise McuBootTimeOutError('UART Disconnected')

        # log RX raw command data
        logging.debug('RX-CMD [%02d]: %s', len(rxpkg), atos(rxpkg))

        # Parse and validate status flag
        status = self._parse_status(rxpkg)
        if status != StatusCode.SUCCESS:
            if status in StatusCode:
                logging.info('RX-CMD: %s', StatusCode[status])
                raise McuBootCommandError(errname=StatusCode[status], errval=status)
            else:
                logging.info('RX-CMD: Unknown Error %d', status)
                raise McuBootCommandError(errval=status)

        return rxpkg

    def _read_data(self, length, timeout=1000):
        n = 0
        data = bytearray()
        pg_dt = float(self._pg_end - self._pg_start) / length
        self._abort = False

        if self._usb_dev is None and self._uart_dev is None:
            logging.info('RX-DATA: Disconnected')
            raise McuBootConnectionError('Disconnected')

        while n < length:
            # Read USB-HID DATA IN Report
            try:
                rep_id, pkg = self._usb_dev.read(timeout)
            except:
                logging.info('RX-DATA: USB Disconnected')
                raise McuBootTimeOutError('USB Disconnected')

            if rep_id != self.HID_REPORT['DATA_IN']:
                status = self._parse_status(pkg)
                if status in StatusCode:
                    logging.info('RX-DATA: %s' % StatusCode.desc(status))
                    raise McuBootDataError(mode='read', errname=StatusCode.desc(status), errval=status)
                else:
                    logging.info('RX-DATA: Unknown Error %d' % status)
                    raise McuBootDataError(mode='read', errval=status)

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
            raise McuBootTimeOutError('USB Disconnected')

        # Parse and validate status flag
        status = self._parse_status(pkg)
        if status != StatusCode.SUCCESS:
            if status in StatusCode:
                logging.info('RX-DATA: %s' % StatusCode.desc(status))
                raise McuBootDataError(mode='read', errname=StatusCode.desc(status), errval=status)
            else:
                logging.info('RX-DATA: Unknown Error %d' % status)
                raise McuBootDataError(mode='read', errval=status)

        logging.info('RX-DATA: Successfully Received %d Bytes', len(data))
        return data

    def _send_data(self, data):
        n = len(data)
        start = 0
        pg_dt = float(self._pg_end - self._pg_start) / n
        self._abort = False

        if self._usb_dev is None and self._uart_dev is None:
            logging.info('TX-DATA: Disconnected')
            raise McuBootConnectionError('Disconnected')

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
            raise McuBootTimeOutError('USB Disconnected')

        # Parse and validate status flag
        status = self._parse_status(pkg)
        if status != StatusCode.SUCCESS:
            logging.info('TX-DATA: %s' % StatusCode[status])
            raise McuBootDataError(mode='write', errname=StatusCode[status], errval=status)

        logging.info('TX-DATA: Successfully Send %d Bytes', len(data))
        return start

    def set_handler(self, progressbar, start_val=0, end_val=100):
        self._pg_func = progressbar
        self._pg_start = start_val
        self._pg_end = end_val

    def abort(self):
        self._abort = True

    def is_open(self):
        """ MBoot: Check if device connected
        :rtype : bool
        """
        if self._usb_dev is not None:
            return True
        else:
            return False

    def open_usb(self, dev):
        """ MBoot: Connect by USB
        :rtype : bool
        """
        if dev is not None:
            logging.info('Connect: %s', dev.info())
            self._usb_dev = dev
            self._usb_dev.open()

            return True
        else:
            logging.info('USB Disconnected !')
            return False

    def open_uart(self, port, baudrate):
        """ MBoot: Connect by UART
        :rtype : bool
        """
        if port is not None:
            self._uart_dev = UART()
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
        """ MBoot: Disconnect device
        """
        if self._usb_dev:
            self._usb_dev.close()
            self._usb_dev = None
        elif self._uart_dev:
            self._uart_dev.close()
            self._uart_dev = None

    def get_mcu_info(self):
        """ MBoot: Get MCU info (available properties collection)
        :return List of {dict}
        """
        mcu_info = {}
        if self._usb_dev is None and self._uart_dev is None:
            logging.info('Disconnected !')
            return None

        for property_name, property_tag, _ in PropertyTag:
            try:
                raw_value = self.get_property(property_tag)
                str_value = decode_property_value(property_tag, raw_value)
            except McuBootCommandError:
                continue
            mcu_info.update({property_name: str_value})

        return mcu_info

    def flash_erase_all(self):
        """ MBoot: Erase complete flash memory without recovering flash security section
        """
        logging.info('TX-CMD: FlashEraseAll')
        # Prepare FlashEraseAll command
        cmd = pack('4B', CommandTag.FLASH_ERASE_ALL, 0x00, 0x00, 0x00)
        # Process FlashEraseAll command
        self._process_cmd(cmd)

    def flash_erase_region(self, start_address, length):
        """ MBoot: Erase specified range of flash
        :param start_address: Start address
        :param length: Count of bytes
        """
        logging.info('TX-CMD: FlashEraseRegion [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare FlashEraseRegion command
        cmd = pack('<4B2I', CommandTag.FLASH_ERASE_REGION, 0x00, 0x00, 0x02, start_address, length)
        # Process FlashEraseRegion command
        self._process_cmd(cmd, 5000)

    def read_memory(self, start_address, length):
        """ MBoot: Read data from MCU memory
        :param start_address: Start address
        :param length: Count of bytes
        :return List of bytes
        """
        if length == 0:
            raise ValueError('Data len is zero')
        logging.info('TX-CMD: ReadMemory [ StartAddr=0x%08X | len=%d  ]', start_address, length)
        # Prepare ReadMemory command
        cmd = pack('<4B2I', CommandTag.READ_MEMORY, 0x00, 0x00, 0x02, start_address, length)
        # Process ReadMemory command
        self._process_cmd(cmd)
        # Process Read Data
        return self._read_data(length)

    def write_memory(self, start_address, data):
        """ MBoot: Write data into MCU memory
        :param start_address: Start address
        :param data: List of bytes
        :return Count of wrote bytes
        """
        if len(data) == 0:
            raise ValueError('Data len is zero')
        logging.info('TX-CMD: WriteMemory [ StartAddr=0x%08X | len=%d  ]', start_address, len(data))
        # Prepare WriteMemory command
        cmd = pack('<4B2I', CommandTag.WRITE_MEMORY, 0x00, 0x00, 0x03, start_address, len(data))
        # Process WriteMemory command
        self._process_cmd(cmd)
        # Process Write Data
        return self._send_data(data)

    def fill_memory(self, start_address, length, pattern=0xFFFFFFFF):
        """ MBoot: Fill MCU memory with specified pattern
        :param start_address: Start address (must be word aligned)
        :param length: Count of words (must be word aligned)
        :param pattern: Count of wrote bytes
        """
        logging.info('TX-CMD: FillMemory [ address=0x%08X | len=%d  | patern=0x%08X ]', start_address, length, pattern)
        # Prepare FillMemory command
        cmd = pack('<4B3I', CommandTag.FILL_MEMORY, 0x00, 0x00, 0x03, start_address, length, pattern)
        # Process FillMemory command
        self._process_cmd(cmd)

    def flash_security_disable(self, backdoor_key):
        """ MBoot: Disable flash security by backdoor key
        :param backdoor_key:
        """
        logging.info('TX-CMD: FlashSecurityDisable [ backdoor_key [0x] = %s ]', atos(backdoor_key))
        # Prepare FlashSecurityDisable command
        cmd = pack('4B', CommandTag.FLASH_SECURITY_DISABLE, 0x00, 0x00, 0x02)
        if len(backdoor_key) < 8:
            raise ValueError('Short range of backdoor key')
        cmd += bytes(backdoor_key[3::-1])
        cmd += bytes(backdoor_key[:3:-1])
        # Process FlashSecurityDisable command
        self._process_cmd(cmd)

    def get_property(self, prop_tag, ext_mem_identifier=None):
        """ MBoot: Get value of specified property
        :param prop_tag: The property ID (see Property enumerator)
        :param ext_mem_identifier:
        :return {dict} with 'RAW' and 'STRING/LIST' value
        """
        if prop_tag in PropertyTag:
            logging.info('TX-CMD: GetProperty->%s', PropertyTag[prop_tag])
        else:
            logging.info('TX-CMD: GetProperty(%d)', prop_tag)
        # Prepare GetProperty command
        if ext_mem_identifier is None:
            cmd = pack('<4BI', CommandTag.GET_PROPERTY, 0x00, 0x00, 0x01, prop_tag)
        else:
            cmd = pack('<4B2I', CommandTag.GET_PROPERTY, 0x00, 0x00, 0x02, prop_tag, ext_mem_identifier)
        # Process GetProperty command
        rx_packet = self._process_cmd(cmd)
        # Parse property value
        raw_value = self._parse_value(rx_packet)
        logging.info('RX-CMD: %s = %s', PropertyTag[prop_tag], decode_property_value(prop_tag, raw_value))
        return raw_value

    def set_property(self, prop_tag, value):
        """ MBoot: Set value of specified property
        :param  prop_tag: The property ID (see Property enumerator)
        :param  value: The value of selected property
        """
        logging.info('TX-CMD: SetProperty->%s = %d', PropertyTag[prop_tag], value)
        # Prepare SetProperty command
        cmd = pack('<4B2I', CommandTag.SET_PROPERTY, 0x00, 0x00, 0x02, prop_tag, value)
        # Process SetProperty command
        self._process_cmd(cmd)

    def receive_sb_file(self, data):
        """ MBoot: Receive SB file
        :param  data: SB file data
        """
        if len(data) == 0:
            raise ValueError('Data len is zero')
        logging.info('TX-CMD: Receive SB file [ len=%d ]', len(data))
        # Prepare WriteMemory command
        cmd = pack('<4BI', CommandTag.RECEIVE_SB_FILE, 0x00, 0x00, 0x02, len(data))
        # Process WriteMemory command
        self._process_cmd(cmd)
        # Process Write Data
        return self._send_data(data)

    def execute(self, jump_address, argument, sp_address):
        """ MBoot: Fill MCU memory with specified pattern
        :param jump_address: Jump address (must be word aligned)
        :param argument: Function arguments address
        :param sp_address: Stack pointer address
        """
        logging.info('TX-CMD: Execute [ JumpAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', jump_address, argument,
                     sp_address)
        # Prepare Execute command
        cmd = pack('<4B3I', CommandTag.EXECUTE, 0x00, 0x00, 0x03, jump_address, argument, sp_address)
        # Process Execute command
        self._process_cmd(cmd)

    def call(self, call_address, argument, sp_address):
        """ MBoot: Fill MCU memory with specified pattern
        :param call_address: Call address (must be word aligned)
        :param argument: Function arguments address
        :param sp_address: Stack pointer address
        """
        logging.info('TX-CMD: Call [ CallAddr=0x%08X | ARG=0x%08X  | SP=0x%08X ]', call_address, argument, sp_address)
        # Prepare Call command
        cmd = pack('<4B3I', CommandTag.CALL, 0x00, 0x00, 0x03, call_address, argument, sp_address)
        # Process Call command
        self._process_cmd(cmd)

    def reset(self):
        """ MBoot: Reset MCU """
        logging.info('TX-CMD: Reset MCU')
        # Prepare Reset command
        cmd = pack('4B', CommandTag.RESET, 0x00, 0x00, 0x00)
        # Process Reset command
        try:
            self._process_cmd(cmd)
        except:
            pass

    def flash_erase_all_unsecure(self):
        """ MBoot: Erase complete flash memory and recover flash security section
        """
        logging.info('TX-CMD: FlashEraseAllUnsecure')
        # Prepare FlashEraseAllUnsecure command
        cmd = pack('4B', CommandTag.FLASH_ERASE_ALL_UNSECURE, 0x00, 0x00, 0x00)
        # Process FlashEraseAllUnsecure command
        self._process_cmd(cmd)

    def flash_read_once(self, index, length):
        """ MBoot: Read from MCU flash program once region (max 8 bytes)
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
        cmd = pack('<4B2I', CommandTag.FLASH_READ_ONCE, 0x00, 0x00, 0x02, index, length)
        # Process FlashReadOnce command
        self._process_cmd(cmd)
        # Process Read Data
        return self._read_data(length)

    def flash_program_once(self, index, data):
        """ MBoot: Write into MCU flash program once region (max 8 bytes)
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
        cmd = pack('<4B2I', CommandTag.FLASH_PROGRAM_ONCE, 0x00, 0x00, 0x03, index, length)
        cmd += bytes(data)
        # Process FlashProgramOnce command
        self._process_cmd(cmd)
        return length

    def flash_read_resource(self, start_address, length, option=1):
        """ MBoot: Read resource of flash module
        :param start_address:
        :param length:
        :param option:
        :return resource list
        """
        logging.info('TX-CMD: FlashReadResource [ StartAddr=0x%08X | len=%d ]', start_address, length)
        # Prepare FlashReadResource command
        cmd = pack('<4B3I', CommandTag.FLASH_READ_RESOURCE, 0x00, 0x00, 0x03, start_address, length, option)
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

    def key_provisioning(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"key_provisioning()\" not implemented yet')

    def load_image(self):
        # TODO: Write implementation
        raise NotImplementedError('Function \"load_image()\" not implemented yet')

