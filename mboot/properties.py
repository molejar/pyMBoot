# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


from typing import Union, Any
from easy_enum import Enum

from .commands import CommandTag
from .memories import ExtMemPropTags, ExtMemId
from .errorcodes import StatusCode


########################################################################################################################
# McuBoot helper functions
########################################################################################################################
def size_fmt(value: Union[int, float], kibibyte: bool = True) -> str:
    """
    Convert size value into string format

    :param value: The raw value
    :param kibibyte: True if 1024 Bytes represent 1kB or False if 1000 Bytes represent 1kB
    """
    base, suffix = [(1000., 'B'), (1024., 'iB')][kibibyte]
    for x in ['B'] + [x + suffix for x in list('kMGTP')]:
        if -base < value < base:
            break
        value /= base

    return "{} {}".format(value, x) if x == 'B' else "{:3.1f} {}".format(value, x)


########################################################################################################################
# McuBoot helper classes
########################################################################################################################

class Version:
    """ McuBoot current and target version type """

    __slots__ = ('mark', 'major', 'minor', 'fixation')

    def __init__(self, *args, **kwargs):
        self.mark = kwargs.get('mark', None)
        self.major = kwargs.get('major', 0)
        self.minor = kwargs.get('minor', 0)
        self.fixation = kwargs.get('fixation', 0)
        if args:
            if isinstance(args[0], int):
                self.from_int(args[0])
            elif isinstance(args[0], str):
                self.from_str(args[0])
            else:
                raise TypeError("Value must be 'str' or 'int' type !")

    def __eq__(self, obj):
        return isinstance(obj, Version) and self.mark == obj.mark and self.major == obj.major and \
               self.minor == obj.minor and self.fixation == obj.fixation

    def __lt__(self, obj):
        return self.to_int(True) < obj.to_int(True)

    def __le__(self, obj):
        return self.to_int(True) <= obj.to_int(True)

    def __gt__(self, obj):
        return self.to_int(True) > obj.to_int(True)

    def __ge__(self, obj):
        return self.to_int(True) >= obj.to_int(True)

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        return f"<Version(mark={self.mark}, major={self.major}, minor={self.minor}, fixation={self.fixation})>"

    def from_int(self, value: int):
        """
        Parse version data from raw int value

        :param value: Raw integer input
        """
        mark = (value >> 24) & 0xFF
        self.mark = chr(mark) if 64 < mark < 91 else None
        self.major = (value >> 16) & 0xFF
        self.minor = (value >> 8) & 0xFF
        self.fixation = value & 0xFF

    def from_str(self, value: str):
        """
        Parse version data from string value

        :param value: String representation input
        """
        mark_major, minor, fixation = value.split('.')
        if len(mark_major) > 1 and mark_major[0] not in "0123456789":
            self.mark = mark_major[0]
            self.major = int(mark_major[1:])
        else:
            self.major = int(mark_major)
        self.minor = int(minor)
        self.fixation = int(fixation)

    def to_int(self, no_mark: bool = False) -> int:
        """
        Get version value in raw integer format

        :param no_mark: If True, return value without mark
        """
        value = self.major << 16 | self.minor << 8 | self.fixation
        return value if no_mark or self.mark is None else ord(self.mark) << 24 | value

    def to_str(self, no_mark: bool = False) -> str:
        """
        Get version value in readable string format

        :param no_mark: If True, return value without mark
        """
        value = f"{self.major}.{self.minor}.{self.fixation}"
        return value if no_mark or self.mark is None else self.mark + value


########################################################################################################################
# McuBoot Properties
########################################################################################################################

class PropertyTag(Enum):
    """ McuBoot Properties """

    # LIST_PROPERTIES = (0x00, 'ListProperties', 'List Properties')
    CURRENT_VERSION = (0x01, 'CurrentVersion', 'Current Version')
    AVAILABLE_PERIPHERALS = (0x02, 'AvailablePeripherals', 'Available Peripherals')
    FLASH_START_ADDRESS = (0x03, 'FlashStartAddress', 'Flash Start Address')
    FLASH_SIZE = (0x04, 'FlashSize', 'Flash Size')
    FLASH_SECTOR_SIZE = (0x05, 'FlashSectorSize', 'Flash Sector Size')
    FLASH_BLOCK_COUNT = (0x06, 'FlashBlockCount', 'Flash Block Count')
    AVAILABLE_COMMANDS = (0x07, 'AvailableCommands', 'Available Commands')
    CRC_CHECK_STATUS = (0x08, 'CrcCheckStatus', 'CRC Check Status')
    LAST_ERROR = (0x09, 'LastError', 'Last Error Value')
    VERIFY_WRITES = (0x0A, 'VerifyWrites', 'Verify Writes')
    MAX_PACKET_SIZE = (0x0B, 'MaxPacketSize', 'Max Packet Size')
    RESERVED_REGIONS = (0x0C, 'ReservedRegions', 'Reserved Regions')
    VALIDATE_REGIONS = (0x0D, 'ValidateRegions', 'Validate Regions')
    RAM_START_ADDRESS = (0x0E, 'RamStartAddress', 'RAM Start Address')
    RAM_SIZE = (0x0F, 'RamSize', 'RAM Size')
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


class PeripheryTag(Enum):
    UART = (0x01, 'UART', 'UART Interface')
    I2C_SLAVE = (0x02, 'I2C-Slave', 'I2C Slave Interface')
    SPI_SLAVE = (0x04, 'SPI-Slave', 'SPI Slave Interface')
    CAN = (0x08, 'CAN', 'CAN Interface')
    USB_HID = (0x10, 'USB-HID', 'USB HID-Class Interface')
    USB_CDC = (0x20, 'USB-CDC', 'USB CDC-Class Interface')
    USB_DFU = (0x40, 'USB-DFU', 'USB DFU-Class Interface')


class FlashReadMargin(Enum):
    NORMAL = (0, 'Normal')
    USER = (1, 'User')
    FACTORY = (2, 'Factory')


class PfrKeystoreUpdateOpt(Enum):
    KEY_PROVISIONING = (0, 'KeyProvisioning')
    WRITE_MEMORY = (1, 'WriteMemory')


########################################################################################################################
# McuBoot Properties Values
########################################################################################################################

class PropertyValueBase:
    """ Base class for property value """

    __slots__ = ('tag', 'name', 'desc')

    def __init__(self, tag, **kwargs):
        self.tag = tag
        self.name = kwargs.get('name', PropertyTag.get(tag, ''))
        self.desc = kwargs.get('desc', PropertyTag.desc(tag))

    def __str__(self):
        return f"{self.name} = {self.to_str()}"

    def to_str(self):
        raise NotImplementedError()


class IntValue(PropertyValueBase):
    """ Property integer value class """

    __slots__ = ('value', '_fmt',)

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self._fmt = kwargs.get('str_format', 'dec')
        self.value = raw_values[0]

    def to_int(self):
        return self.value

    def to_str(self):
        if self._fmt == 'size':
            str_value = size_fmt(self.value)
        elif self._fmt == 'hex':
            str_value = f"0x{self.value:08X}"
        elif self._fmt == 'dec':
            str_value = str(self.value)
        else:
            str_value = self._fmt.format(self.value)
        return str_value


class BoolValue(PropertyValueBase):
    """ Property bool value class """

    __slots__ = ('value', '_true_values', '_false_values', '_true_string', '_false_string')

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self._true_values = kwargs.get('true_values', (1,))
        self._true_string = kwargs.get('true_string', 'YES')
        self._false_values = kwargs.get('false_values', (0,))
        self._false_string = kwargs.get('false_string', 'NO')
        self.value = raw_values[0]

    def __bool__(self):
        return self.value in self._true_values

    def to_int(self):
        return self.value

    def to_str(self):
        return self._true_string if self.value in self._true_values else self._false_string


class EnumValue(PropertyValueBase):

    __slots__ = ('value', 'enum', '_na_msg')

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self._na_msg = kwargs.get('na_msg', 'Unknown Item')
        self.enum = kwargs['enum']
        self.value = raw_values[0]

    def to_int(self):
        return self.value

    def to_str(self):
        return self.enum[self.value] if self.value in self.enum else f"{self._na_msg}: {self.value}"


class VersionValue(PropertyValueBase):

    __slots__ = ('value',)

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self.value = Version(raw_values[0])

    def to_int(self):
        return self.value.to_int()

    def to_str(self):
        return self.value.to_str()


class DeviceUidValue(PropertyValueBase):

    __slots__ = ('value', '_count')

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self._count = len(raw_values)
        self.value = 0
        for i, v in enumerate(raw_values):
            self.value |= v << (i * 32)

    def to_int(self):
        return self.value

    def to_str(self):
        fmt = f"{{:0{self._count * 8}X}}"
        return fmt.format(self.value)


class ReservedRegionsValue(PropertyValueBase):

    __slots__ = ('regions',)

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self.regions = []
        for i in range(0, len(raw_values), 2):
            start = raw_values[i]
            end = raw_values[i + 1]
            if start == end:
                continue
            self.regions.append((start, end))

    def to_str(self):
        return [f"0x{r[0]:08X} - 0x{r[1]:08X}, {size_fmt(r[1] - r[0])}" for r in self.regions]


class AvailablePeripheralsValue(PropertyValueBase):

    __slots__ = ('value',)

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self.value = raw_values[0]

    def to_int(self):
        return self.value

    def to_str(self):
        return [key for key, value, _ in PeripheryTag if value & self.value]


class AvailableCommandsValue(PropertyValueBase):

    __slots__ = ('value',)

    @property
    def tags(self):
        return [tag_value for _, tag_value, _ in CommandTag if (1 << tag_value) & self.value]

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self.value = raw_values[0]

    def __contains__(self, item):
        return isinstance(item, int) and (1 << item) & self.value

    def to_str(self):
        return [name for name, value, _ in CommandTag if (1 << value) & self.value]


class IrqNotifierPinValue(PropertyValueBase):

    __slots__ = ('value',)

    @property
    def pin(self):
        return self.value & 0xFF

    @property
    def port(self):
        return (self.value >> 8) & 0xFF

    @property
    def enabled(self):
        return self.value & (1 << 32)

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self.value = raw_values[0]

    def __bool__(self):
        return self.enabled

    def to_str(self):
        return f"IRQ Port[{self.port}], Pin[{self.pin}] is {'enabled' if self.enabled else 'disabled'}"


class ExternalMemoryAttributesValue(PropertyValueBase):

    __slots__ = ('value', 'mem_id', 'start_address', 'total_size', 'page_size', 'sector_size', 'block_size')

    def __init__(self, tag, raw_values, **kwargs):
        super().__init__(tag, **kwargs)
        self.mem_id = kwargs.get('mem_id', 0)
        self.start_address = raw_values[1] if raw_values[0] & ExtMemPropTags.START_ADDRESS else None
        self.total_size = raw_values[2] * 1024 if raw_values[0] & ExtMemPropTags.SIZE_IN_KBYTES else None
        self.page_size = raw_values[3] if raw_values[0] & ExtMemPropTags.PAGE_SIZE else None
        self.sector_size = raw_values[4] if raw_values[0] & ExtMemPropTags.SECTOR_SIZE else None
        self.block_size = raw_values[5] if raw_values[0] & ExtMemPropTags.BLOCK_SIZE else None
        self.value = raw_values[0]

    def to_str(self):
        str_values = []
        if self.start_address is not None:
            str_values.append(f"Start Address: 0x{self.start_address:08X}")
        if self.total_size is not None:
            str_values.append(f"Total Size:    {size_fmt(self.total_size)}")
        if self.page_size is not None:
            str_values.append(f"Page Size:     {size_fmt(self.page_size)}")
        if self.sector_size is not None:
            str_values.append(f"Sector Size:   {size_fmt(self.sector_size)}")
        if self.block_size is not None:
            str_values.append(f"Block Size:    {size_fmt(self.block_size)}")
        return str_values


########################################################################################################################
# McuBoot property response parser
########################################################################################################################

PROPERTIES = {
    PropertyTag.CURRENT_VERSION: {
        'class': VersionValue,
        'kwargs': {}},
    PropertyTag.AVAILABLE_PERIPHERALS: {
        'class': AvailablePeripheralsValue,
        'kwargs': {}},
    PropertyTag.FLASH_START_ADDRESS: {
        'class': IntValue,
        'kwargs': {'str_format': 'hex'}},
    PropertyTag.FLASH_SIZE: {
        'class': IntValue,
        'kwargs': {'str_format': 'size'}},
    PropertyTag.FLASH_SECTOR_SIZE: {
        'class': IntValue,
        'kwargs': {'str_format': 'size'}},
    PropertyTag.FLASH_BLOCK_COUNT: {
        'class': IntValue,
        'kwargs': {'str_format': 'dec'}},
    PropertyTag.AVAILABLE_COMMANDS: {
        'class': AvailableCommandsValue,
        'kwargs': {}},
    PropertyTag.CRC_CHECK_STATUS: {
        'class': IntValue,
        'kwargs': {'str_format': 'hex'}},
    PropertyTag.VERIFY_WRITES: {
        'class': BoolValue,
        'kwargs': {'true_string': 'ON', 'false_string': 'OFF'}},
    PropertyTag.LAST_ERROR: {
        'class': EnumValue,
        'kwargs': {'enum': StatusCode, 'na_msg': 'Unknown Error'}},
    PropertyTag.MAX_PACKET_SIZE: {
        'class': IntValue,
        'kwargs': {'str_format': 'size'}},
    PropertyTag.RESERVED_REGIONS: {
        'class': ReservedRegionsValue,
        'kwargs': {}},
    PropertyTag.VALIDATE_REGIONS: {
        'class': BoolValue,
        'kwargs': {'true_string': 'ON', 'false_string': 'OFF'}},
    PropertyTag.RAM_START_ADDRESS: {
        'class': IntValue,
        'kwargs': {'str_format': 'hex'}},
    PropertyTag.RAM_SIZE: {
        'class': IntValue,
        'kwargs': {'str_format': 'size'}},
    PropertyTag.SYSTEM_DEVICE_IDENT: {
        'class': IntValue,
        'kwargs': {'str_format': 'hex'}},
    PropertyTag.FLASH_SECURITY_STATE: {
        'class': BoolValue,
        'kwargs': {'true_values': (0x00000000, 0x5AA55AA5), 'true_string': 'Unlocked',
                   'false_values': (0x00000001, 0xC33CC33C), 'false_string': 'Locked'}},
    PropertyTag.UNIQUE_DEVICE_IDENT: {
        'class': DeviceUidValue,
        'kwargs': {}},
    PropertyTag.FLASH_FAC_SUPPORT: {
        'class': BoolValue,
        'kwargs': {'true_string': 'ON', 'false_string': 'OFF'}},
    PropertyTag.FLASH_ACCESS_SEGMENT_SIZE: {
        'class': IntValue,
        'kwargs': {'str_format': 'size'}},
    PropertyTag.FLASH_ACCESS_SEGMENT_COUNT: {
        'class': IntValue,
        'kwargs': {'str_format': 'dec'}},
    PropertyTag.FLASH_READ_MARGIN: {
        'class': EnumValue,
        'kwargs': {'enum': FlashReadMargin, 'na_msg': 'Unknown Margin'}},
    PropertyTag.QSPI_INIT_STATUS: {
        'class': EnumValue,
        'kwargs': {'enum': StatusCode, 'na_msg': 'Unknown Error'}},
    PropertyTag.TARGET_VERSION: {
        'class': VersionValue,
        'kwargs': {}},
    PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES: {
        'class': ExternalMemoryAttributesValue,
        'kwargs': {}},
    PropertyTag.RELIABLE_UPDATE_STATUS: {
        'class': EnumValue,
        'kwargs': {'enum': StatusCode, 'na_msg': 'Unknown Error'}},
    PropertyTag.FLASH_PAGE_SIZE: {
        'class': IntValue,
        'kwargs': {'str_format': 'size'}},
    PropertyTag.IRQ_NOTIFIER_PIN: {
        'class': IrqNotifierPinValue,
        'kwargs': {}},
    PropertyTag.PFR_KEYSTORE_UPDATE_OPT: {
        'class': EnumValue,
        'kwargs': {'enum': PfrKeystoreUpdateOpt, 'na_msg': 'Unknown'}},
}


def parse_property_value(prop_tag: int, raw_values: list, mem_id: int = 0) -> Any:
    """
    Parse property raw values

    :param prop_tag: The property tag, see 'PropertyTag' enum
    :param raw_values: The property values
    :param mem_id: External memory ID (default: 0)
    """
    if prop_tag not in PROPERTIES.keys():
        return None

    cls = PROPERTIES[prop_tag]['class']         # type: ignore
    kwargs = PROPERTIES[prop_tag]['kwargs']     # type: ignore
    kwargs['mem_id'] = mem_id                   # type: ignore

    return cls(prop_tag, raw_values, **kwargs)  # type: ignore
