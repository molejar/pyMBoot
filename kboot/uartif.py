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

from __future__ import print_function

import sys
import glob
import logging
import threading
import serial


class uartif(object):

    def __init__(self):
        self.ser = serial.Serial()

    def available_ports(self):
        if sys.platform.startswith('win'):
            ports = ['COM%s' % (i + 1) for i in range(256)]
        elif sys.platform.startswith('linux') or \
             sys.platform.startswith('cygwin'):
            # this excludes your current terminal "/dev/tty"
            ports = glob.glob('/dev/tty[A-Za-z]*')
        elif sys.platform.startswith('darwin'):
            ports = glob.glob('/dev/tty.*')
        else:
            raise EnvironmentError('Unsupported platform')

        result = []
        for port in ports:
            try:
                s = serial.Serial(port)
                s.close()
                result.append(port)
            except (OSError, serial.SerialException):
                pass

        return result

    def open(self, port, baudrate=9600):
        self.ser.port = port
        self.ser.baudrate = baudrate
        self.ser.bytesize = serial.EIGHTBITS     # number of bits per bytes
        self.ser.parity = serial.PARITY_NONE     # set parity check: no parity
        self.ser.stopbits = serial.STOPBITS_ONE  # number of stop bits
        #self.ser.timeout = None                  # block read
        self.ser.timeout = 1                     # non-block read
        self.ser.xonxoff = False                 # disable software flow control
        self.ser.rtscts = False                  # disable hardware (RTS/CTS) flow control
        self.ser.dsrdtr = False                  # disable hardware (DSR/DTR) flow control
        self.ser.writeTimeout = 2                # timeout for write
        try:
            self.ser.open()
            self.isopen = True
        except Exception as e:
            print("error open serial port: " + str(e))
            self.isopen = False

    def close(self):
        if self.ser.isOpen():
            self.ser.close()

    def read(self):
        if self.ser.isOpen():
            print(self.ser.read(1))

    def write(self):
        pass

