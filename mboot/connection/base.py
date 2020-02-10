# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


class DevConnBase:

    @property
    def is_opened(self):
        raise NotImplementedError()

    def __init__(self, **kwargs):
        self.reopen = kwargs.get('reopen', False)

    def open(self):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def abort(self):
        raise NotImplementedError()

    def read(self, timeout=1000):
        raise NotImplementedError()

    def write(self, packet):
        raise NotImplementedError()

    def info(self):
        raise NotImplementedError()
