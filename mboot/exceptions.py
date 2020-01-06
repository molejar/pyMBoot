# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


from .errorcodes import StatusCode


########################################################################################################################
# McuBoot Exceptions
########################################################################################################################

class McuBootError(Exception):
    """
    MBoot Module: Base Exception
    """
    fmt = 'MBoot ERROR: {description}'

    def __init__(self, desc=None):
        self.description = "Unknown Error" if desc is None else desc

    def __str__(self):
        return self.fmt.format(description=self.description)


class McuBootCommandError(McuBootError):
    """
    MBoot Module: Command Exception
    """
    fmt = 'MBoot ERROR: {cmd_name} interrupted -> {description}'

    def __init__(self, cmd, value):
        self.cmd_name = cmd
        self.error_value = value
        self.description = StatusCode.desc(value, f"Unknown Error 0x{value:08X}")

    def __str__(self):
        return self.fmt.format(cmd_name=self.cmd_name, description=self.description)


class McuBootConnectionError(McuBootError):
    """
    MBoot Module: Connection Exception
    """
    fmt = 'MBoot ERROR: Connection issue -> {description}'
