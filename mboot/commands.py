# Copyright (c) 2017 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


from easy_enum import Enum
from struct import pack, unpack_from
from .errorcodes import StatusCode
from .exceptions import McuBootError


########################################################################################################################
# McuBoot Commands and Responses Tags
########################################################################################################################

class CommandTag(Enum):
    """ McuBoot Commands """

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
    KEY_PROVISIONING = (0x15, 'KeyProvisioning', 'Key Provisioning')

    # reserved commands
    CONFIGURE_I2C = (0xC1, 'ConfigureI2c', 'Configure I2C')
    CONFIGURE_SPI = (0xC2, 'ConfigureSpi', 'Configure SPI')
    CONFIGURE_CAN = (0xC3, 'ConfigureCan', 'Configure CAN')


class ResponseTag(Enum):
    """ McuBoot Responses to Commands """

    GENERIC = (0xA0, 'GenericResponse', 'Generic Response')
    READ_MEMORY = (0xA3, 'ReadMemoryResponse', 'Read Memory Response')
    GET_PROPERTY = (0xA7, 'GetPropertyResponse', 'Get Property Response')
    FLASH_READ_ONCE = (0xAF, 'FlashReadOnceResponse', 'Flash Read Once Response')
    FLASH_READ_RESOURCE = (0xB0, 'FlashReadResourceResponse', 'Flash Read Resource Response')
    KEY_PROVISIONING_RESPONSE = (0xB5, 'KeyProvisioningResponse', 'Key Provisioning Response')


########################################################################################################################
# McuBoot Command and Response packet classes
########################################################################################################################

class PacketHeader:
    """ McuBoot command/response packet header """

    FORMAT = '4B'
    SIZE = 4

    def __init__(self, tag: int, flags: int, reserved: int, params_count: int):
        self.tag = tag
        self.flags = flags
        self.reserved = reserved
        self.params_count = params_count

    def __eq__(self, obj):
        return isinstance(obj, PacketHeader) and vars(self) == vars(obj)

    def __str__(self):
        return f"<Tag=0x{self.tag:02X}, Flags=0x{self.flags:02X}, ParamsCount={self.params_count}>"

    def to_bytes(self) -> bytes:
        """
        Serialize header into bytes
        """
        return pack(self.FORMAT, self.tag, self.flags, self.reserved, self.params_count)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0):
        """
        Deserialize header from bytes

        :param data: Input data in bytes
        :param offset: The offset of input data
        """
        if len(data) < 4:
            raise McuBootError(f"Invalid format of RX packet (data length is {len(data)} bytes)")
        return cls(*unpack_from(cls.FORMAT, data, offset))


class CmdPacket:
    """ McuBoot command packet format class """

    SIZE = 32
    EMPTY_VALUE = 0x00

    def __init__(self, tag: int, flags: int, *args, data=None):
        assert len(args) < 8
        self.header = PacketHeader(tag, flags, 0, len(args))
        self.params = list(args)
        if data is not None:
            if len(data) % 4:
                data += b'\0' * (4 - len(data) % 4)
            self.params.extend(unpack_from(f'<{len(data) // 4}I', data))
            self.header.params_count = len(self.params)

    def __eq__(self, obj):
        return isinstance(obj, CmdPacket) and self.header == obj.header and self.params == obj.params

    def __str__(self):
        tag = CommandTag.get(self.header.tag, f'0x{self.header.tag:02X}')
        return f"Tag={tag}, Flags=0x{self.header.flags:02X}" + \
               "".join(f", P[{n}]=0x{param:08X}" for n, param in enumerate(self.params))

    def to_bytes(self, padding: bool = True) -> bytes:
        """
        Serialize CmdPacket into bytes

        :param padding: If True, add padding to specific size
        """
        self.header.params_count = len(self.params)
        data = self.header.to_bytes()
        data += pack(f"<{self.header.params_count}I", *self.params)
        if padding and len(data) < self.SIZE:
            data += bytes([self.EMPTY_VALUE] * (self.SIZE - len(data)))
        return data


class CmdResponse:
    """ McuBoot response base class """

    @property
    def status_code(self):
        return self.params[0]

    def __init__(self, header: PacketHeader, params: tuple):
        self.header = header
        self.params = params

    def __bool__(self):
        return self.status_code == StatusCode.SUCCESS

    def __str__(self):
        return f"Tag={ResponseTag[self.header.tag]}" + \
               "".join(f", P[{n}]=0x{param:08X}" for n, param in enumerate(self.params))

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0):
        """
        Deserialize header from bytes

        :param data: Input data in bytes
        :param offset: The offset of input data
        """
        header = PacketHeader.from_bytes(data, offset)
        offset += PacketHeader.SIZE
        if header.params_count == 0:
            raise McuBootError("Invalid params count in header of cmd response packet")
        if (header.params_count * 4) > (len(data) - offset):
            raise McuBootError("Invalid params count in header of cmd response packet")
        return cls(header, unpack_from(f'<{header.params_count}L', data, offset))


class GenericResponse(CmdResponse):
    """ McuBoot generic response format class """

    @property
    def cmd_tag(self):
        return self.params[1]

    def __str__(self):
        cmd = CommandTag.get(self.cmd_tag, f'Unknown[0x{self.cmd_tag:02X}]')
        status = StatusCode.get(self.status_code, f'Unknown[0x{self.status_code:08X}]')
        return f"Tag={ResponseTag[self.header.tag]}, Status={status}, Cmd={cmd}"


class GetPropertyResponse(CmdResponse):
    """ McuBoot get property response format class """

    @property
    def values(self):
        return self.params[1:]

    def __str__(self):
        status = StatusCode.get(self.status_code, f'Unknown[0x{self.status_code:08X}]')
        return f"Tag={ResponseTag[self.header.tag]}, Status={status}" + \
               "".join(f", V[{n}]=0x{value:08X}" for n, value in enumerate(self.values))


class ReadMemoryResponse(CmdResponse):
    """ McuBoot read memory response format class """

    @property
    def length(self):
        return self.params[1]

    def __str__(self):
        status = StatusCode.get(self.status_code, f'Unknown[0x{self.status_code:08X}]')
        return f"Tag={ResponseTag[self.header.tag]}, Status={status}, Length={self.length}"


class FlashReadOnceResponse(ReadMemoryResponse):
    """ McuBoot flash read once response format class """

    @property
    def data(self):
        return pack(f'<{self.header.params_count - 2}L', *self.params[2:])


class FlashReadResourceResponse(ReadMemoryResponse):
    """ McuBoot flash read resource response format class """


class KeyProvisioningResponse(ReadMemoryResponse):
    """ McuBoot Key Provisioning response format class """


def parse_cmd_response(data: bytes, offset: int = 0) -> CmdResponse:
    """
    Parse command response

    :param data: Input data in bytes
    :param offset: The offset of input data
    """
    known_responses = {
        ResponseTag.GENERIC: GenericResponse,
        ResponseTag.GET_PROPERTY: GetPropertyResponse,
        ResponseTag.READ_MEMORY: ReadMemoryResponse,
        ResponseTag.FLASH_READ_RESOURCE: FlashReadResourceResponse,
        ResponseTag.FLASH_READ_ONCE: FlashReadOnceResponse,
        ResponseTag.KEY_PROVISIONING_RESPONSE: KeyProvisioningResponse
    }
    response_tag = data[offset]
    response_class = known_responses.get(response_tag, CmdResponse)
    return response_class.from_bytes(data, offset)
