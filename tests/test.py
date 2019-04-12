
# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

import pytest
import mboot


def test_helper_functions():

    assert mboot.is_available_command(mboot.EnumCommandTag.FLASH_ERASE_ALL, 2)
