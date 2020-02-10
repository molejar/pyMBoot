# Copyright (c) 2017 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


from time import sleep
from typing import Optional
from logging import getLogger
from easy_enum import Enum

# internal
from .commands import CommandTag, CmdPacket, CmdResponse, GenericResponse
from .memories import ExtMemPropTags, ExtMemId
from .properties import PropertyTag, Version, parse_property_value
from .exceptions import McuBootError, McuBootCommandError, McuBootConnectionError
from .errorcodes import StatusCode
from .connection import DevConnBase

########################################################################################################################
# McuBoot Logger Name
########################################################################################################################

logger = getLogger('MBOOT')


########################################################################################################################
# McuBoot Tags for Key Provisioning Operations
########################################################################################################################

class KeyProvOperation(Enum):
    ENROLL = (0, 'Enroll', 'Enroll Operation')
    SET_USER_KEY = (1, 'SetUserKey', 'Set User Key Operation')
    SET_INTRINSIC_KEY = (2, 'SetIntrinsicKey', 'Set Intrinsic Key Operation')
    WRITE_NON_VOLATILE = (3, 'WriteNonVolatile', 'Write Non Volatile Operation')
    READ_NON_VOLATILE = (4, 'ReadNonVolatile', 'Read Non Volatile Operation')
    WRITE_KEY_STORE = (5, 'WriteKeyStore', 'Write Key Store Operation')
    READ_KEY_STORE = (6, 'ReadKeyStore', 'Read Key Store Operation')


########################################################################################################################
# McuBoot Main Class
########################################################################################################################

class McuBoot:

    @property
    def status_code(self):
        return self._status_code

    @property
    def status_info(self):
        return StatusCode.get(self.status_code, f'Unknown[0x{self.status_code:08X}]')

    @property
    def is_opened(self):
        return self._device.is_opened

    def __init__(self, device: DevConnBase, cmd_exception: bool = False):
        """
        Initialize the McuBoot object.

        :param device: The instance of communication interface class
        :param cmd_exception:
        """
        self._cmd_exception = cmd_exception
        self._status_code = StatusCode.SUCCESS
        self._device = device
        self.reopen = False

    def __enter__(self):
        self.reopen = True
        self.open()
        return self

    def __exit__(self, *args, **kwargs):
        self.close()

    def open(self):
        """ Connect to device """
        if not self._device.is_opened:
            self._device.open()

    def close(self):
        """ Disconnect device """
        self._device.close()

    def abort(self):
        """ Abort executed operation """
        self._device.abort()

    def _check_response(self, cmd_packet: CmdPacket, cmd_response: CmdResponse, logger_info: bool = True):

        cmd_name = CommandTag[cmd_packet.header.tag]

        if not isinstance(cmd_response, CmdResponse):
            raise McuBootError(f"CMD: {cmd_name} -> Unsupported response format")

        self._status_code = cmd_response.status_code

        if self._status_code == StatusCode.SUCCESS:
            if logger_info:
                logger.info("CMD: Done successfully")
            return True

        logger.info(f"CMD: {cmd_name} Error -> " + self.status_info)

        if self._cmd_exception:
            raise McuBootCommandError(cmd_name, self.status_code)

        return False

    def _process_cmd(self, cmd_packet: CmdPacket, timeout: int = 2000):
        """
        Process Command

        :param cmd_packet: Command Packet
        :param timeout: The maximal waiting time in [ms] for response packet
        :return: CmdResponse
        """
        if not self._device.is_opened:
            logger.info('TX: Device not opened')
            raise McuBootConnectionError('Device not opened')

        logger.debug('TX-PACKET: ' + str(cmd_packet))

        try:
            self._device.write(cmd_packet)
            cmd_response = self._device.read(timeout)
        except TimeoutError:
            self._status_code = StatusCode.NO_RESPONSE
            logger.debug('RX-PACKET: No Response, Timeout Error !')
            raise McuBootConnectionError("No Response from Device")

        logger.debug('RX-PACKET: ' + str(cmd_response))

        return cmd_response

    def _read_data(self, cmd_tag: int, length: int, timeout: int = 1000) -> bytes:
        """
        Read Data

        :param cmd_tag:
        :param length:
        :param timeout:
        """
        data = b''

        if not self._device.is_opened:
            logger.info('RX: Device not opened')
            raise McuBootConnectionError('Device not opened')

        while True:
            try:
                response = self._device.read(timeout)
            except TimeoutError:
                self._status_code = StatusCode.NO_RESPONSE
                logger.debug('RX: No Response, Timeout Error !')
                raise McuBootConnectionError("No Response from Device")

            if isinstance(response, bytes):
                data += response

            elif isinstance(response, GenericResponse):
                logger.debug('RX-PACKET: ' + str(response))
                self._status_code = response.status_code
                if response.cmd_tag == cmd_tag:
                    break

        if len(data) < length or self.status_code != StatusCode.SUCCESS:
            logger.debug(f"CMD: Received {len(data)} from {length} Bytes, {self.status_info}")
            if self._cmd_exception:
                raise McuBootCommandError(CommandTag[cmd_tag], self.status_code)
        else:
            logger.info(f"CMD: Successfully Received {len(data)} from {length} Bytes")

        return data[:length] if len(data) > length else data

    def _send_data(self, cmd_tag: int, data: bytes) -> bool:
        """
        Send Data part of specific command

        :param cmd_tag: The command tag
        :param data: Data in bytes
        """
        if not self._device.is_opened:
            logger.info('TX: Device Disconnected')
            raise McuBootConnectionError('Device Disconnected !')

        try:
            self._device.write(data)
            response = self._device.read()
        except TimeoutError:
            self._status_code = StatusCode.NO_RESPONSE
            logger.debug('RX: No Response, Timeout Error !')
            raise McuBootConnectionError("No Response from Device")

        # TODO: Check response type if needed
        # if not isinstance(response, GenericResponse):

        logger.debug('RX-PACKET: ' + str(response))
        self._status_code = response.status_code
        if response.status_code != StatusCode.SUCCESS:
            logger.debug("CMD: Send Error, " + self.status_info)
            if self._cmd_exception:
                raise McuBootCommandError(CommandTag[cmd_tag], self.status_code)
            return False

        logger.info(f"CMD: Successfully Send {len(data)} Bytes")
        return True

    def get_property_list(self) -> list:
        """
        Get list of available properties

        :return: list
        """
        property_list = []
        for _, tag, _ in PropertyTag:
            try:
                values = self.get_property(tag)
            except McuBootCommandError:
                continue

            if values:
                property_list.append(parse_property_value(tag, values))

        self._status_code = StatusCode.SUCCESS
        if not property_list:
            self._status_code = StatusCode.FAIL
            if self._cmd_exception:
                raise McuBootCommandError('GetPropertyList', self.status_code)

        return property_list

    def get_memory_list(self) -> dict:
        """
        Get list of embedded memories

        :return: dict
        """
        memory_list = {}
        # Internal FLASH
        index = 0
        mdata: dict = {}
        start_address = 0
        while True:
            try:
                values = self.get_property(PropertyTag.FLASH_START_ADDRESS, index)
                if not values:
                    break
                if index == 0:
                    start_address = values[0]
                elif start_address == values[0]:
                    break
                mdata[index] = {}
                mdata[index]['address'] = values[0]
                values = self.get_property(PropertyTag.FLASH_SIZE, index)
                if not values:
                    break
                mdata[index]['size'] = values[0]
                values = self.get_property(PropertyTag.FLASH_SECTOR_SIZE, index)
                if not values:
                    break
                mdata[index]['sector_size'] = values[0]
                index += 1
            except McuBootCommandError:
                break

        if mdata:
            memory_list['internal_flash'] = mdata

        # Internal RAM
        index = 0
        mdata = {}
        start_address = 0
        while True:
            try:
                values = self.get_property(PropertyTag.RAM_START_ADDRESS, index)
                if not values:
                    break
                if index == 0:
                    start_address = values[0]
                elif start_address == values[0]:
                    break
                mdata[index] = {}
                mdata[index]['address'] = values[0]
                values = self.get_property(PropertyTag.RAM_SIZE, index)
                if not values:
                    break
                mdata[index]['size'] = values[0]
                index += 1
            except McuBootCommandError:
                break
        if mdata:
            memory_list['internal_ram'] = mdata

        # External Memories
        ext_mem_list = []
        ext_mem_ids = [mem_id for _, mem_id, _ in ExtMemId]

        try:
            values = self.get_property(PropertyTag.CURRENT_VERSION)
        except McuBootCommandError:
            values = None

        if not values and self._status_code == StatusCode.UNKNOWN_PROPERTY:
            self._status_code = StatusCode.SUCCESS
            if not memory_list:
                self._status_code = StatusCode.FAIL
                if self._cmd_exception:
                    raise McuBootCommandError('GetMemoryList', self.status_code)
            return memory_list

        if Version(values[0]) <= Version("2.0.0"):
            # old versions mboot support only Quad SPI memory
            ext_mem_ids = [ExtMemId.QUAD_SPI0]

        for id in ext_mem_ids:
            mem_attrs = {}

            try:
                values = self.get_property(PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, id)
            except McuBootCommandError:
                values = None

            if not values:
                if self._status_code == StatusCode.UNKNOWN_PROPERTY:
                    # No external memories are supported by current device.
                    break
                elif self._status_code == StatusCode.INVALID_ARGUMENT:
                    # Current memory type is not supported by the device, skip to next external memory.
                    continue
                elif self._status_code == StatusCode.QSPI_NOT_CONFIGURED:
                    # QSPI0 is not supported, skip to next external memory.
                    continue
                elif self._status_code == StatusCode.MEMORY_NOT_CONFIGURED:
                    # Un-configured external memory, skip to next external memory.
                    continue
                elif self._status_code != StatusCode.SUCCESS:
                    # Other Error
                    break

            # memory ID and name
            mem_attrs['mem_id'] = id
            mem_attrs['mem_name'] = ExtMemId[id]
            # parse memory attributes
            if values[0] & ExtMemPropTags.START_ADDRESS:
                mem_attrs['address'] = values[1]
            if values[0] & ExtMemPropTags.SIZE_IN_KBYTES:
                mem_attrs['size'] = values[2] * 1024
            if values[0] & ExtMemPropTags.PAGE_SIZE:
                mem_attrs['page_size'] = values[3]
            if values[0] & ExtMemPropTags.SECTOR_SIZE:
                mem_attrs['sector_size'] = values[4]
            if values[0] & ExtMemPropTags.BLOCK_SIZE:
                mem_attrs['block_size'] = values[5]
            # store attributes
            ext_mem_list.append(mem_attrs)

        if ext_mem_list:
            memory_list['external'] = ext_mem_list

        self._status_code = StatusCode.SUCCESS
        if not memory_list:
            self._status_code = StatusCode.FAIL
            if self._cmd_exception:
                raise McuBootCommandError('GetMemoryList', self.status_code)

        return memory_list

    def flash_erase_all(self, mem_id: int = 0) -> bool:
        """
        Erase complete flash memory without recovering flash security section

        :param mem_id: Memory ID
        """
        logger.info(f"CMD: FlashEraseAll(mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.FLASH_ERASE_ALL, 0, mem_id)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def flash_erase_region(self, address: int, length: int, mem_id: int = 0) -> bool:
        """
        Erase specified range of flash

        :param address: Start address
        :param length: Count of bytes
        :param mem_id: Memory ID
        """
        logger.info(f"CMD: FlashEraseRegion(address=0x{address:08X}, length={length}, mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.FLASH_ERASE_REGION, 0, address, length, mem_id)
        cmd_response = self._process_cmd(cmd_packet, 5000)
        return self._check_response(cmd_packet, cmd_response)

    def read_memory(self, address: int, length: int, mem_id: int = 0) -> Optional[bytes]:
        """
        Read data from MCU memory

        :param address: Start address
        :param length: Count of bytes
        :param mem_id: Memory ID
        """
        logger.info(f"CMD: ReadMemory(address=0x{address:08X}, length={length}, mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.READ_MEMORY, 0, address, length, mem_id)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._read_data(CommandTag.READ_MEMORY, cmd_response.length)
        return None

    def write_memory(self, address: int, data: bytes, mem_id: int = 0) -> bool:
        """
        Write data into MCU memory

        :param address: Start address
        :param data: List of bytes
        :param mem_id: Memory ID
        """
        logger.info(f"CMD: WriteMemory(address=0x{address:08X}, length={len(data)}, mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.WRITE_MEMORY, 0, address, len(data), mem_id)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._send_data(CommandTag.WRITE_MEMORY, data)
        return False

    def fill_memory(self, address: int, length: int, pattern: int = 0xFFFFFFFF) -> bool:
        """
        Fill MCU memory with specified pattern

        :param address: Start address (must be word aligned)
        :param length: Count of words (must be word aligned)
        :param pattern: Count of wrote bytes
        """
        logger.info(f"CMD: FillMemory(address=0x{address:08X}, length={length}, pattern=0x{pattern:08X})")
        cmd_packet = CmdPacket(CommandTag.FILL_MEMORY, 0, address, length, pattern)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def flash_security_disable(self, backdoor_key: bytes) -> bool:
        """
        Disable flash security by using of backdoor key

        :param backdoor_key: The key value as array of 8 bytes
        """
        if len(backdoor_key) != 8:
            raise ValueError('Backdoor key must by 8 bytes long')
        logger.info(f"CMD: FlashSecurityDisable(backdoor_key={backdoor_key})")
        cmd_packet = CmdPacket(CommandTag.FLASH_SECURITY_DISABLE, 0, data=backdoor_key)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def get_property(self, prop_tag: int, index: int = 0) -> Optional[list]:
        """
        Get specified property value

        :param prop_tag: Property TAG (see Properties Enum)
        :param index: External memory ID or internal memory region index (depends on property type)
        """
        logger.info(f"CMD: GetProperty({PropertyTag[prop_tag]}, index={index})")
        cmd_packet = CmdPacket(CommandTag.GET_PROPERTY, 0, prop_tag, index)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response):
            return cmd_response.values
        return None

    def set_property(self, prop_tag: int, value: int) -> bool:
        """
        Set value of specified property

        :param  prop_tag: Property TAG (see Property enumerator)
        :param  value: The value of selected property
        """
        logger.info(f"CMD: SetProperty({PropertyTag[prop_tag]}, value=0x{value:08X})")
        cmd_packet = CmdPacket(CommandTag.SET_PROPERTY, 0, prop_tag, value)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def receive_sb_file(self, data: bytes) -> bool:
        """
        Receive SB file

        :param  data: SB file data
        """
        logger.info(f"CMD: ReceiveSBfile(data_length={len(data)})")
        cmd_packet = CmdPacket(CommandTag.RECEIVE_SB_FILE, 1, len(data))
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._send_data(CommandTag.RECEIVE_SB_FILE, data)
        return False

    def execute(self, address: int, argument: int, sp: int) -> bool:
        """
        Fill MCU memory with specified pattern

        :param address: Jump address (must be word aligned)
        :param argument: Function arguments address
        :param sp: Stack pointer address
        """
        logger.info(f"CMD: Execute(address=0x{address:08X}, argument=0x{argument:08X}, SP=0x{sp:08X})")
        cmd_packet = CmdPacket(CommandTag.EXECUTE, 0, address, argument, sp)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def call(self, address: int, argument: int) -> bool:
        """
        Fill MCU memory with specified pattern

        :param address: Call address (must be word aligned)
        :param argument: Function arguments address
        """
        logger.info(f"CMD: Call(address=0x{address:08X}, argument=0x{argument:08X})")
        cmd_packet = CmdPacket(CommandTag.CALL, 0, address, argument)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def reset(self, timeout: int = 2000, reopen: bool = True) -> bool:
        """
        Reset MCU and reconnect if enabled

        :param timeout: The maximal waiting time in [ms] for reopen connection
        :param reopen: True for reopen connection after HW reset else False
        """
        ret_val = False
        logger.info('CMD: Reset MCU')
        cmd_packet = CmdPacket(CommandTag.RESET, 0)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response):
            self._device.close()
            ret_val = True
            if self.reopen and reopen:
                sleep(timeout / 1000)
                try:
                    self._device.open()
                except:
                    ret_val = False
                    if self._cmd_exception:
                        raise McuBootConnectionError()
        return ret_val

    def flash_erase_all_unsecure(self) -> bool:
        """
        Erase complete flash memory and recover flash security section

        :return bool
        """
        logger.info('CMD: FlashEraseAllUnsecure')
        cmd_packet = CmdPacket(CommandTag.FLASH_ERASE_ALL_UNSECURE, 0)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def efuse_read_once(self, index: int) -> Optional[int]:
        """
        Read from MCU flash program once region (max 8 bytes)

        :param index: Start index
        """
        logger.info(f"CMD: FlashReadOnce(index={index})")
        cmd_packet = CmdPacket(CommandTag.FLASH_READ_ONCE, 0, index, 4)
        cmd_response = self._process_cmd(cmd_packet)
        return cmd_response.values[0] if self._check_response(cmd_packet, cmd_response) else None

    def efuse_program_once(self, index: int, value: int) -> bool:
        """
        Write into MCU once program region

        :param index: Start index
        :param value: Int value (4 bytes long)
        """
        logger.info(f"CMD: FlashProgramOnce(index={index}, value=0x{value:X})")
        cmd_packet = CmdPacket(CommandTag.FLASH_PROGRAM_ONCE, 0, index, 4, value)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def flash_read_once(self, index: int, count: int = 4) -> Optional[bytes]:
        """
        Read from MCU flash program once region (max 8 bytes)

        :param index: Start index
        :param count: Count of bytes
        """
        assert count in (4, 8)
        logger.info(f"CMD: FlashReadOnce(index={index}, bytes={count})")
        cmd_packet = CmdPacket(CommandTag.FLASH_READ_ONCE, 0, index, count)
        cmd_response = self._process_cmd(cmd_packet)
        return cmd_response.data if self._check_response(cmd_packet, cmd_response) else None

    def flash_program_once(self, index: int, data: bytes) -> bool:
        """
        Write into MCU flash program once region (max 8 bytes)

        :param index: Start index
        :param data: Input data aligned to 4 or 8 bytes
        """
        assert len(data) in (4, 8)
        logger.info(f"CMD: FlashProgramOnce(index={index}, data={data})")
        cmd_packet = CmdPacket(CommandTag.FLASH_PROGRAM_ONCE, 0, index, len(data), data=data)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def flash_read_resource(self, address: int, length: int, option: int = 1) -> Optional[bytes]:
        """
        Read resource of flash module

        :param address: Start address
        :param length: Number of bytes
        :param option:
        """
        logger.info(f"CMD: FlashReadResource(address=0x{address:08X}, length={length}, option={option})")
        cmd_packet = CmdPacket(CommandTag.FLASH_READ_RESOURCE, 0, address, length, option)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._read_data(CommandTag.FLASH_READ_RESOURCE, cmd_response.length)
        return None

    def configure_memory(self, address: int, mem_id: int) -> bool:
        """
        Configure memory

        :param address: The address in memory where are locating configuration data
        :param mem_id: External memory ID
        """
        logger.info(f"CMD: ConfigureMemory({ExtMemId[mem_id]}, address=0x{address:08X})")
        cmd_packet = CmdPacket(CommandTag.CONFIGURE_MEMORY, 0, mem_id, address)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def reliable_update(self, address: int) -> bool:
        """
        Reliable Update

        :param address:
        """
        logger.info(f"CMD: ReliableUpdate(address=0x{address:08X})")
        cmd_packet = CmdPacket(CommandTag.RELIABLE_UPDATE, 0, address)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def generate_key_blob(self, dek_data: bytes, count: int = 72) -> Optional[bytes]:
        """
        Generate Key Blob

        :param dek_data: Data Encryption Key as bytes
        :param count: Key blob count (default: 72 - AES128bit)
        """
        logger.info(f"CMD: GenerateKeyBlob(dek_len={len(dek_data)}, count={count})")
        cmd_packet = CmdPacket(CommandTag.GENERATE_KEY_BLOB, 1, 0, len(dek_data), 0)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return None
        if not self._send_data(CommandTag.GENERATE_KEY_BLOB, dek_data):
            return None
        cmd_packet = CmdPacket(CommandTag.GENERATE_KEY_BLOB, 0, 0, count, 1)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._read_data(CommandTag.GENERATE_KEY_BLOB, cmd_response.length)
        return None

    def kp_enroll(self) -> bool:
        """
        Key provisioning: Enroll Command (start PUF)
        """
        logger.info("CMD: [KeyProvisioning] Enroll")
        cmd_packet = CmdPacket(CommandTag.KEY_PROVISIONING, 0, KeyProvOperation.ENROLL)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def kp_set_intrinsic_key(self, key_type: int, key_size: int) -> bool:
        """
        Key provisioning: Generate Intrinsic Key

        :param key_type:
        :param key_size:
        """
        logger.info(f"CMD: [KeyProvisioning] SetIntrinsicKey(type={key_type}, key_size={key_size})")
        cmd_packet = CmdPacket(CommandTag.KEY_PROVISIONING, 0, KeyProvOperation.SET_INTRINSIC_KEY, key_type, key_size)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def kp_write_nonvolatile(self, mem_id: int = 0) -> bool:
        """
        Key provisioning: Write the key to a nonvolatile memory

        :param mem_id: The memory ID (default: 0)
        """
        logger.info(f"CMD: [KeyProvisioning] WriteNonVolatileMemory(mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.KEY_PROVISIONING, 0, KeyProvOperation.WRITE_NON_VOLATILE, mem_id)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def kp_read_nonvolatile(self, mem_id: int = 0) -> bool:
        """
        Key provisioning: Load the key from a nonvolatile memory to bootloader

        :param mem_id: The memory ID (default: 0)
        """
        logger.info(f"CMD: [KeyProvisioning] ReadNonVolatileMemory(mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.KEY_PROVISIONING, 0, KeyProvOperation.READ_NON_VOLATILE, mem_id)
        cmd_response = self._process_cmd(cmd_packet)
        return self._check_response(cmd_packet, cmd_response)

    def kp_set_user_key(self, key_type: int, key_data: bytes) -> bool:
        """
        Key provisioning: Send the user key specified by <key_type> to bootloader.

        :param key_type:
        :param key_data:
        """
        logger.info(f"CMD: [KeyProvisioning] SetUserKey(key_type={key_type}, key_len={len(key_data)})")
        cmd_packet = CmdPacket(CommandTag.KEY_PROVISIONING, 1, KeyProvOperation.SET_USER_KEY, key_type, len(key_data))
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._send_data(CommandTag.KEY_PROVISIONING, key_data)
        return False

    def kp_write_key_store(self, key_type: int, key_data: bytes) -> bool:
        """
        Key provisioning: Write key data into key store area.

        :param key_type:
        :param key_data:
        """
        key_len = len(key_data)
        logger.info(f"CMD: [KeyProvisioning] WriteKeyStore(key_type={key_type}, key_len={key_len})")
        cmd_packet = CmdPacket(CommandTag.KEY_PROVISIONING, 1, KeyProvOperation.WRITE_KEY_STORE, key_type, key_len)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._send_data(CommandTag.KEY_PROVISIONING, key_data)
        return False

    def kp_read_key_store(self) -> Optional[bytes]:
        """
        Key provisioning: Read key data from key store area.
        """
        logger.info(f"CMD: [KeyProvisioning] ReadKeyStore")
        cmd_packet = CmdPacket(CommandTag.KEY_PROVISIONING, 0, KeyProvOperation.READ_KEY_STORE)
        cmd_response = self._process_cmd(cmd_packet)
        if self._check_response(cmd_packet, cmd_response, False):
            return self._read_data(CommandTag.KEY_PROVISIONING, cmd_response.length)
        return None
