# Copyright 2015 Martin Olejar
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

import logging, os, collections
import threading
from time import time
from utils import *

#os.environ['PYUSB_DEBUG'] = 'debug'
#os.environ['PYUSB_LOG_FILENAME'] = 'usb.log'

usb_backend = None

if os.name == "nt":
    # Prefer hidapi over pyWinUSB for Windows, since pyWinUSB has known bug(s)
    try:
        import hid
        usb_backend = "hidapiusb"
    except:
        try:
            import pywinusb.hid as hid
            usb_backend = "pywinusb"
        except:
            logging.error("PyWinUSB is required on a Windows Machine")
elif os.name == "posix":
    # Select hidapi for OS X and pyUSB for Linux.
    if os.uname()[0] == 'Darwin':
        try:
            import hid
            usb_backend = "hidapiusb"
        except:
            logging.error("cython-hidapi is required on a Mac OS X Machine")
    else:
        try:
            import usb.core
            import usb.util
            usb_backend = "pyusb"
        except:
            logging.error("PyUSB is required on a Linux Machine")
else:
    raise Exception("No USB backend found")


class usbif(object):

    def __init__(self):
        self.vid = 0
        self.pid = 0
        self.vendor_name = ""
        self.product_name = ""

    def init(self):
        pass

    def encode_packet(self, report_id, data, pkglen=36):
        buf = []
        buf.append(report_id & 0xff)               # Set USB-HID Report ID
        buf.append(0x00)                           # Set padding
        buf.append((len(data) >> (8 * 0)) & 0xff)  # Set packet length LSB
        buf.append((len(data) >> (8 * 1)) & 0xff)  # Set packet length MSB
        buf += data                                # Set packet data
        for _ in range(pkglen - len(buf)):
            buf.append(0x00)                       # Align packet to 36 bytes in default
        return buf

    def decode_packet(self, data):
        buf = []
        report_id = data[0]                        # Get USB-HID Report ID
        plen = (data[1] << 8) | data[2]            # Get packet length
        for n in range(plen):
            buf.append(data[4 + n])                # Get packet data
        return report_id, buf

    def write(self, report_id, data):
        return

    def read(self, timeout):
        return

    def getInfo(self):
        return self.product_name + " (" + \
               str(hex(self.vid)) + ", " + \
               str(hex(self.pid)) + ")"

    def open(self):
        return

    def close(self):
        return


class HidApiUSB(usbif):
    """
    This class provides basic functions to access
    a USB HID device using cython-hidapi:
        - write/read an endpoint
    """
    vid = 0
    pid = 0

    def __init__(self):
        super(HidApiUSB, self).__init__()
        # Vendor page and usage_id = 2
        self.device = None

    def open(self):
        pass

    @staticmethod
    def getAllConnectedTargets(vid, pid):
        """
        returns all the connected devices which matches HidApiUSB.vid/HidApiUSB.pid.
        returns an array of HidApiUSB (Interface) objects
        """

        devices = hid.enumerate(vid, pid)

        if not devices:
            logging.debug("No USB device connected")
            return

        targets = []

        for deviceInfo in devices:
            try:
                dev = hid.device(vendor_id=vid, product_id=pid, path=deviceInfo['path'])
            except IOError:
                logging.debug("Failed to open USB device")
                return

            # Create the USB interface object for this device.
            new_target = HidApiUSB()
            new_target.vendor_name = deviceInfo['manufacturer_string']
            new_target.product_name = deviceInfo['product_string']
            new_target.vid = deviceInfo['vendor_id']
            new_target.pid = deviceInfo['product_id']
            new_target.device = dev

            targets.append(new_target)

        return targets

    def write(self, report_id, data):
        """
        write data on the OUT endpoint associated to the HID interface
        """
        buffer = []
        buffer.append(report_id & 0xff)              # USB-HID Report ID
        buffer.append(0x00)                          # padding
        buffer.append((len(data) >> (8 * 0)) & 0xff) # packet length LSB
        buffer.append((len(data) >> (8 * 1)) & 0xff) # packet length MSB
        buffer += data                               # data
        for _ in range(36 - len(buffer)):
            buffer.append(0x00)                      # Align packet to 36 bytes
        #logging.debug("send: %s", data)
        self.device.write(buffer)
        return


    def read(self, timeout=-1):
        """
        Read data on the IN endpoint associated to the HID interface
        :param timeout:
        """
        return self.device.read(64)

    def close(self):
        """
        close the interface
        """
        logging.debug("closing interface")
        self.device.close()


class PyWinUSB(usbif):
    """
    This class provides basic functions to access
    a USB HID device using pywinusb:
        - write/read an endpoint
    """
    vid = 0
    pid = 0

    def __init__(self):
        super(PyWinUSB, self).__init__()
        # Vendor page and usage_id = 2
        self.report = []
        # deque used here instead of synchronized Queue
        # since read speeds are ~10-30% faster and are
        # comprable to a based list implmentation.
        self.rcv_data = collections.deque()
        self.device = None
        return

    # handler called when a report is received
    def __rx_handler(self, data):
         #logging.debug("rcv: %s", data[1:])
         self.rcv_data.append(data)

    def open(self):
        self.device.set_raw_data_handler(self.__rx_handler)
        self.device.open(shared=False)

    @staticmethod
    def getAllConnectedTargets(vid, pid):
        """
        returns all the connected devices which matches PyWinUSB.vid/PyWinUSB.pid.
        returns an array of PyWinUSB (Interface) objects
        :param vid:
        :param pid:
        """
        all_devices = hid.find_all_hid_devices()

        # find devices with good vid/pid
        all_kboot_devices = []
        for d in all_devices:
            if (d.vendor_id == vid) and (d.product_id == pid):
                all_kboot_devices.append(d)

        targets = []
        for dev in all_kboot_devices:
            try:
                dev.open(shared=False)
                report = dev.find_output_reports()
                dev.close()

                if report:
                    new_target = PyWinUSB()
                    new_target.report = report
                    new_target.vendor_name = dev.vendor_name
                    new_target.product_name = dev.product_name
                    new_target.vid = dev.vendor_id
                    new_target.pid = dev.product_id
                    new_target.device = dev
                    new_target.device.set_raw_data_handler(new_target.__rx_handler)
                    targets.append(new_target)
            except Exception as e:
                logging.error("Receiving Exception: %s", e)
                dev.close()

        return targets

    def write(self, report_id, data):
        """
        write data on the OUT endpoint associated to the HID interface
        """
        rawdata = self.encode_packet(report_id, data)
        logging.debug('USB-OUT[0x]: %s', array_to_string(rawdata))
        self.report[report_id - 1].send(rawdata)
        return

    def read(self, timeout=2000):
        """
        Read data on the IN endpoint associated to the HID interface
        :param timeout:
        """
        start = time()
        while len(self.rcv_data) == 0:
            if ((time() - start) * 1000) > timeout:
                raise Exception("Read timed out")
        rawdata = self.rcv_data.popleft()
        logging.debug('USB-IN [0x]: %s', array_to_string(rawdata))
        return self.decode_packet(rawdata)

    def close(self):
        """
        close the interface
        """
        logging.debug("closing interface")
        self.device.close()


class PyUSB(usbif):
    """
    This class provides basic functions to access
    a USB HID device using pyusb:
        - write/read an endpoint
    """

    vid = 0
    pid = 0
    intf_number = 0

    def __init__(self):
        super(PyUSB, self).__init__()
        self.ep_out = None
        self.ep_in = None
        self.dev = None
        self.closed = False


    @staticmethod
    def getAllConnectedTargets(vid, pid):
        """
        returns all the connected devices which matches PyUSB.vid/PyUSB.pid.
        returns an array of PyUSB (Interface) objects
        :param vid:
        :param pid:
        """
        # find all devices matching the vid/pid specified
        all_devices = usb.core.find(find_all=True, idVendor=vid, idProduct=pid)

        if not all_devices:
            logging.debug("No device connected")
            return None

        targets = []

        # iterate on all devices found
        for dev in all_devices:
            interface_number = -1

            # get active config
            config = dev.get_active_configuration()

            # iterate on all interfaces:
            #    - if we found a HID interface -> KBOOT
            for interface in config:
                if interface.bInterfaceClass == 0x03:
                    interface_number = interface.bInterfaceNumber
                    break

            if interface_number == -1:
                continue

            try:
                if dev.is_kernel_driver_active(interface_number):
                    dev.detach_kernel_driver(interface_number)
            except Exception as e:
                print e

            ep_in, ep_out = None, None
            for ep in interface:
                if ep.bEndpointAddress & 0x80:
                    ep_in = ep
                else:
                    ep_out = ep

            if usb.__version__ == '1.0.0b1':
                product_name = usb.util.get_string(dev, 64, 2)
                vendor_name = usb.util.get_string(dev, 64, 1)
            else:
                vendor_name = usb.util.get_string(dev, 1)
                product_name = usb.util.get_string(dev, 2)

            if not ep_in:
                logging.error('Endpoints not found')
                return None

            new_target = PyUSB()
            new_target.ep_in = ep_in
            new_target.ep_out = ep_out
            new_target.dev = dev
            new_target.vid = vid
            new_target.pid = pid
            new_target.intf_number = interface_number
            new_target.vendor_name = vendor_name
            new_target.product_name = product_name
            targets.append(new_target)

        return targets

    def write(self, report_id, data):
        """
        write data on the OUT endpoint associated to the HID interface
        """
        report_size = 36
        #if self.ep_out:
        #    report_size = self.ep_out.wMaxPacketSize

        rawdata = self.encode_packet(report_id, data, report_size)

        if not self.ep_out:
            bmRequestType = 0x21       #Host to device request of type Class of Recipient Interface
            bmRequest = 0x09           #Set_REPORT (HID class-specific request for transferring data over EP0)
            wValue = 0x200             #Issuing an OUT report
            wIndex = self.intf_number  #KBoot interface number for HID
            self.dev.ctrl_transfer(bmRequestType, bmRequest, wValue, wIndex, rawdata)
            return
            #raise ValueError('EP_OUT endpoint is NULL')

        logging.debug('USB-OUT[0x]: %s', array_to_string(rawdata))
        self.ep_out.write(rawdata)
        return


    def read(self, timeout=1000):
        """
        read data on the IN endpoint associated to the HID interface
        """
        rawdata = self.ep_in.read(self.ep_in.wMaxPacketSize, timeout)
        logging.debug('USB-IN [0x]: %s', array_to_string(rawdata))
        return self.decode_packet(rawdata)

    def close(self):
        """
        close the interface
        """
        logging.debug("closing interface")
        self.closed = True
        try:
            if self.dev:
                usb.util.dispose_resources(self.dev)
        except:
            pass


def getAllConnectedTargets(vid, pid):
    if usb_backend == "hidapiusb":
        return HidApiUSB.getAllConnectedTargets(vid, pid)
    elif usb_backend == "pywinusb":
        return PyWinUSB.getAllConnectedTargets(vid, pid)
    elif usb_backend == "pyusb":
        return PyUSB.getAllConnectedTargets(vid, pid)
    else:
        return None

