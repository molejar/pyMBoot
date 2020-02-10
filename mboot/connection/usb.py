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


class RawHidBase(DevConnBase):

    @property
    def is_opened(self):
        return self._opened

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._opened = False
        self.vid = 0
        self.pid = 0
        self.vendor_name = ""
        self.product_name = ""

    @staticmethod
    def _encode_report(report_id, report_size, data, offset=0):
        data_len = min(len(data) - offset, report_size - 4)
        raw_data = pack('<2BH', report_id, 0x00, data_len)
        raw_data += data[offset: offset + data_len]
        raw_data += bytes([0x00] * (report_size - len(raw_data)))
        logger.debug(f"OUT[{len(raw_data)}]: " + ' '.join(f"{b:02X}" for b in raw_data))
        return raw_data, offset + data_len

    @staticmethod
    def _decode_report(raw_data):
        logger.debug(f"IN [{len(raw_data)}]: " + ' '.join(f"{b:02X}" for b in raw_data))
        report_id, _, plen = unpack_from('<2BH', raw_data)
        data = bytes(raw_data[4: 4 + plen])
        if report_id == REPORT_ID['CMD_IN']:
            return parse_cmd_response(data)
        return data

    def open(self):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def abort(self):
        pass

    def read(self, timeout=1000):
        raise NotImplementedError()

    def write(self, packet):
        raise NotImplementedError()

    def info(self):
        return f"{self.product_name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"


########################################################################################################################
# USB Interface Classes
########################################################################################################################
if os.name == "nt":
    try:
        import pywinusb.hid as hid
    except:
        raise Exception("PyWinUSB is required on a Windows Machine")


    class RawHid(RawHidBase):
        """
        This class provides basic functions to access
        a USB HID device using pywinusb:
            - write/read an endpoint
        """

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            # Vendor page and usage_id = 2
            self.report = []
            # deque used here instead of synchronized Queue
            # since read speeds are ~10-30% faster and are
            # comparable to a based list implementation.
            self.rcv_data = collections.deque()
            self.device = None
            return

        # handler called when a report is received
        def __rx_handler(self, data):
            # logging.debug("rcv: %s", data[1:])
            self.rcv_data.append(data)

        def open(self):
            """ open the interface """
            logger.debug(" Open Interface")
            self.device.set_raw_data_handler(self.__rx_handler)
            self.device.open(shared=False)
            self._opened = True

        def close(self):
            """ close the interface """
            logger.debug(" Close Interface")
            self.device.close()
            self._opened = False

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
            report_size = self.report[report_id - 1]._HidReport__raw_report_size
            while data_index < len(data):
                raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
                self.report[report_id - 1].send(raw_data)

        def read(self, timeout=2000):
            """
            Read data from IN endpoint associated to the HID interface

            :param timeout:
            """
            start = time()
            while len(self.rcv_data) == 0:
                if ((time() - start) * 1000) > timeout:
                    raise TimeoutError()

            raw_data = self.rcv_data.popleft()
            return self._decode_report(bytes(raw_data))

        @staticmethod
        def enumerate(vid, pid):
            """
            Get an array of all connected devices which matches PyWinUSB.vid/PyWinUSB.pid.

            :param vid: USB Vendor ID
            :param pid: USB Product ID
            """

            targets = []
            all_devices = hid.find_all_hid_devices()

            # find devices with good vid/pid
            for dev in all_devices:
                if (dev.vendor_id == vid) and (dev.product_id == pid):
                    try:
                        dev.open(shared=False)
                        report = dev.find_output_reports()

                        if report:
                            new_target = RawHid()
                            new_target.report = report
                            new_target.vendor_name = dev.vendor_name
                            new_target.product_name = dev.product_name
                            new_target.vid = dev.vendor_id
                            new_target.pid = dev.product_id
                            new_target.device = dev
                            new_target.device.set_raw_data_handler(new_target.__rx_handler)
                            targets.append(new_target)

                    except Exception as e:
                        logger.error("Receiving Exception: %s", str(e))
                    finally:
                        dev.close()

            return targets


else:
    try:
        import usb.core
        import usb.util
    except:
        raise Exception("PyUSB is required on a Linux Machine")


    class RawHid(RawHidBase, DevConnBase):
        """
        This class provides basic functions to access
        a USB HID device using pyusb:
            - write/read an endpoint
        """

        def __init__(self):
            super().__init__()
            self.ep_out = None
            self.ep_in = None
            self.device = None
            self.interface_number = -1

        def open(self):
            """ open the interface """
            logger.debug(" Open Interface")
            self._opened = True

        def close(self):
            """ close the interface """
            logger.debug(" Close Interface")
            self._opened = False
            try:
                if self.device:
                    usb.util.dispose_resources(self.device)
            except:
                pass

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
            if self.ep_out:
                report_size = self.ep_out.wMaxPacketSize
                while data_index < len(data):
                    raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
                    self.ep_out.write(raw_data)

            else:
                bmRequestType = 0x21            # Host to device request of type Class of Recipient Interface
                bmRequest = 0x09                # Set_REPORT (HID class-specific request for transferring data over EP0)
                wValue = 0x200 + report_id      # Issuing an OUT report with specified ID
                wIndex = self.interface_number  # Interface number for HID
                report_size = 36                # TODO: get the value from descriptor
                while data_index < len(data):
                    raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
                    self.device.ctrl_transfer(bmRequestType, bmRequest, wValue, wIndex, raw_data)

        def read(self, timeout=1000):
            """
            Read data from IN endpoint associated to the HID interface

            :param timeout:
            """
            # TODO: test if self.ep_in.wMaxPacketSize is accessible in all Linux distributions
            raw_data = self.ep_in.read(self.ep_in.wMaxPacketSize, timeout)
            return self._decode_report(raw_data)

        @staticmethod
        def enumerate(vid, pid):
            """
            Get list of all connected devices which matches PyUSB.vid and PyUSB.pid.

            :param vid: USB Vendor ID
            :param pid: USB Product ID
            """
            # find all devices matching the vid/pid specified
            all_devices = usb.core.find(find_all=True, idVendor=vid, idProduct=pid)

            if not all_devices:
                logger.debug("No device connected")
                return None

            targets = []

            # iterate on all devices found
            for dev in all_devices:
                interface = None
                interface_number = -1

                # get active config
                config = dev.get_active_configuration()

                # iterate on all interfaces:
                for interface in config:
                    if interface.bInterfaceClass == 0x03:  # HID Interface
                        interface_number = interface.bInterfaceNumber
                        break

                if interface is None or interface_number == -1:
                    continue

                try:
                    if dev.is_kernel_driver_active(interface_number):
                        dev.detach_kernel_driver(interface_number)
                except Exception as e:
                    print(str(e))

                try:
                    dev.set_configuration()
                    dev.reset()
                except usb.core.USBError as e:
                    logger.debug(f"Cannot set configuration for the device: {str(e)}")

                ep_in, ep_out = None, None
                for ep in interface:
                    if ep.bEndpointAddress & 0x80:
                        ep_in = ep
                    else:
                        ep_out = ep

                if not ep_in:
                    logger.error('Endpoints not found')
                    return None

                new_target = RawHid()
                new_target.ep_in = ep_in
                new_target.ep_out = ep_out
                new_target.device = dev
                new_target.vid = vid
                new_target.pid = pid
                new_target.interface_number = interface_number
                new_target.vendor_name = usb.util.get_string(dev, 1).strip('\0')
                new_target.product_name = usb.util.get_string(dev, 2).strip('\0')
                targets.append(new_target)

            return targets
