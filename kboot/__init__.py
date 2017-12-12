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

from .srec import SRecFile, SRecError, SRecAlignError, SRecChecksumError, SRecCountError, SRecMarkError, SRecLengthError
from .ihex import IHexFile, IHexSegment, IHexError, IHexAlignError, IHexChecksumError, IHexCountError, IHexTypeError, \
                  IHexLengthError
from .kboot import KBoot, PropEnum, StatEnum, scan_usb, DEFAULT_USB_PID, DEFAULT_USB_VID, \
                   GenericError, CommandError, DataError, ConnError, TimeOutError

__author__ = 'Martin Olejar <martin.olejar@gmail.com>'
__version__ = '0.1.4'
__status__ = 'Development'

__all__ = [
    # const
    'DEFAULT_USB_PID',
    'DEFAULT_USB_VID',
    # global methods
    'scan_usb',
    # enums
    'PropEnum',
    'StatEnum',
    # classes
    'KBoot',
    'SRecFile',
    'IHexFile',
    'IHexSegment',
    # exceptions
    'GenericError',
    'CommandError',
    'DataError',
    'ConnError',
    'TimeOutError',
    # SRec exceptions
    'SRecError',
    'SRecAlignError',
    'SRecChecksumError',
    'SRecCountError',
    'SRecMarkError',
    'SRecLengthError',
    # IHex exceptions
    'IHexError',
    'IHexAlignError',
    'IHexChecksumError',
    'IHexCountError',
    'IHexTypeError',
    'IHexLengthError'
]
