# Copyright (c) 2017 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


import os
import logging
import collections
from time import time
from struct import pack, unpack_from

from fido2._pyu2f import hid

from .base import DevConnBase
from ..commands import CmdPacket, parse_cmd_response

logger = logging.getLogger('MBOOT:USB')

# os.environ['PYUSB_DEBUG'] = 'debug'
# os.environ['PYUSB_LOG_FILENAME'] = 'usb.log'

########################################################################################################################
# Devices
########################################################################################################################

USB_DEVICES = {
    # NAME   | VID   | PID
    'MKL27': (0x15A2, 0x0073),
    'LPC55': (0x1FC9, 0x0021),
    'IMXRT': (0x1FC9, 0x0135)
}


########################################################################################################################
# Scan USB method
########################################################################################################################

def scan_usb(device_name: str = None) -> list:
    """
    Scan connected USB devices

    :param device_name: The specific device name (MKL27, LPC55, ...) or VID:PID
    """
    devices = []

    if device_name is None:
        for name, value in USB_DEVICES.items():
            devices += RawHid.enumerate(value[0], value[1])
    else:
        if ':' in device_name:
            vid, pid = device_name.split(':')
            devices = RawHid.enumerate(int(vid, 0), int(pid, 0))
        else:
            if device_name in USB_DEVICES:
                vid = USB_DEVICES[device_name][0]
                pid = USB_DEVICES[device_name][1]
                devices = RawHid.enumerate(vid, pid)
    return devices


########################################################################################################################
# USB HID Interface Base Class
########################################################################################################################

REPORT_ID = {
    # USB HID Reports
    'CMD_OUT': 0x01,
    'CMD_IN': 0x03,
    'DATA_OUT': 0x02,
    'DATA_IN': 0x04
}


def _encode_report(report_id, report_size, data, offset=0):
    data_len = min(len(data) - offset, report_size - 4)
    raw_data = pack('<2BH', report_id, 0x00, data_len)
    logger.debug(f"report-id == {report_id}")
    logger.debug(f"HID-HEADER[{len(raw_data)}]: " + ' '.join(f"{b:02X}" for b in raw_data))
    raw_data += data[offset: offset + data_len]
    raw_data += bytes([0x00] * (report_size - len(raw_data)))
    logger.debug(f"OUT[{len(raw_data)}]: " + ' '.join(f"{b:02X}" for b in raw_data))
    return raw_data, offset + data_len

def _decode_report(raw_data):
    logger.debug(f"IN [{len(raw_data)}]: " + ' '.join(f"{b:02X}" for b in raw_data))
    report_id, _, plen = unpack_from('<2BH', raw_data)
    data = bytes(raw_data[4: 4 + plen])
    if report_id == REPORT_ID['CMD_IN']:
        return parse_cmd_response(data)
    return data


class RawHid(DevConnBase):
    """
    This class provides basic functions to access
    a USB HID device using pyusb:
        - write/read an endpoint
    """
    device_info = None
    is_opened = False

    def __init__(self, device_info):
        self.device_info = device_info

    def open(self):
        """ open the interface """
        self.dev = hid.Open(self.device_info['path'])
        self.is_opened = True

    def close(self):
        """ close the interface """


    def write(self, packet):
        """
        Write data on the OUT endpoint associated to the HID interface

        :param packet: HID packet data
        """
        if isinstance(packet, CmdPacket):
            report_id = REPORT_ID['CMD_OUT']
            data = packet.to_bytes()
        elif isinstance(packet, (bytes, bytearray)):
            report_id = REPORT_ID['DATA_OUT']
            data = packet
        else:
            raise Exception()

        data_index = 0
        report_size = self.dev.GetOutReportDataLength()
        while data_index < len(data):
            raw_data, data_index = _encode_report(report_id, report_size, data, data_index)
            self.dev.Write(raw_data)

    def read(self, timeout=1000):
        """
        Read data from IN endpoint associated to the HID interface

        :param timeout:
        """
        packet = self.dev.Read()
        return _decode_report(bytearray(packet))


    @staticmethod
    def enumerate(vid, pid):
        """
        Get list of all connected devices which matches PyUSB.vid and PyUSB.pid.

        :param vid: USB Vendor ID
        :param pid: USB Product ID
        """
        devs = hid.Enumerate()
        targets = []
        for x in devs:
            # print(x)
            if x['product_id'] == pid and x['vendor_id'] == vid:
                targets.append(RawHid(x))


        return targets

    def info(self):
        return f"{self.device_info['product_string']} - {self.device_info['path']}"
