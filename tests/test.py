
# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

import pytest
from mboot import decode_property_value, is_command_available, CommandTag, PropertyTag


def test_decode_property_value():

    assert decode_property_value(PropertyTag.CURRENT_VERSION, [0x010002]) == '1.0.2'
    assert decode_property_value(PropertyTag.FLASH_SECURITY_STATE, [0]) == 'Unlocked'
    assert decode_property_value(PropertyTag.MAX_PACKET_SIZE, [1280]) == '1.2 kiB'


def test_is_command_available():

    assert is_command_available(CommandTag.FLASH_ERASE_ALL, 2)
    assert not is_command_available(CommandTag.FLASH_ERASE_ALL, 0)
