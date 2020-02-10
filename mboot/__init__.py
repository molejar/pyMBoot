# Copyright (c) 2017 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

from .mcuboot import McuBoot
from .commands import CommandTag
from .memories import ExtMemPropTags, ExtMemId
from .properties import PropertyTag, PeripheryTag, Version, parse_property_value
from .exceptions import McuBootError, McuBootCommandError, McuBootConnectionError
from .errorcodes import StatusCode
from .connection import scan_usb, scan_uart


__author__ = "Martin Olejar"
__contact__ = "martin.olejar@gmail.com"
__version__ = '0.3.0'
__license__ = "BSD3"
__status__ = 'Development'
__all__ = [
    # global methods
    'scan_usb',
    'parse_property_value',
    # classes
    'McuBoot',
    'Version',
    # enums
    'PropertyTag',
    'PeripheryTag',
    'CommandTag',
    'StatusCode',
    'ExtMemId',
    # exceptions
    'McuBootError',
    'McuBootCommandError',
    'McuBootConnectionError'
]
