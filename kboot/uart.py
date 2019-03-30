# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

import sys
import glob
import serial
from time import time
from struct import pack, unpack_from
from .misc import crc16


########################################################################################################################
# UART Interface Class
########################################################################################################################
class UARTIF(object):

    def __init__(self):
        self.ser = serial.Serial()

    @staticmethod
    def available_ports():
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
        except Exception as e:
            print("error open serial port: " + str(e))

    def close(self):
        if self.ser.isOpen():
            self.ser.close()

    def get_supported_baudrates(self):
        if self.ser.isOpen():
            pass

    def send_ack(self, val=True):
        ack = [0x5A, 0xA1 if val == True else 0xA7]
        self.ser.flushOutput()
        self.ser.write(bytearray(ack))

    def ping(self):
        if not self.ser.isOpen():
            raise Exception("UART Disconnected")
        # Send Ping
        #self.ser.setTimeout(1)
        self.ser.flushInput()
        self.ser.flushOutput()
        self.ser.write(bytearray((0x5A, 0xA6)))
        # Read Status
        data = self.ser.read(10)
        if data == None or len(data) < 10:
            raise Exception("UART Disconnected")
        rx_crc = (data[9] << 8) | data[8]
        if rx_crc != crc16(data[:7]):
            raise Exception("CRC Error")
        else:
            return data[2:6]

    def read(self, timeout=5000):
        if not self.ser.isOpen():
            raise Exception("UART Disconnected")
        # ---
        repeat_count = 3
        while repeat_count > 0:
            start = time()
            while self.ser.inWaiting() < 4:
                if ((time() - start) * 1000) > timeout:
                    raise Exception("Read timed out 1")
            ret = self.ser.read(4)
            crc_calc = crc16(ret)
            if ret[0] != 0x5A:
                raise Exception("Packet Error")
            packet_type = ret[1]
            dlen = unpack_from('<I', ret, 2)[0]
            #self.ser.setTimeout(5)
            data = self.ser.read(dlen + 2)
            if len(data) < (dlen + 2):
                raise Exception("Read timed out 2")
            crc = unpack_from('<I', data[:2])[0]
            #crc = array_to_long(data[:2])
            crc_calc = crc16(data[2:], crc_calc)
            if crc != crc_calc:
                #self.ser.setTimeout(1)
                self.ser.flushInput()
                self.ser.flushOutput()
                self.send_ack(False)
                repeat_count -= 1
                continue
            else:
                self.send_ack()
                return (packet_type, data[2:])
        raise Exception("CRC Error")

    def write(self, packet_type, data, timeout=5000):
        if not self.ser.isOpen():
            raise Exception("UART Disconnected")
        # Preparing packet
        buf = bytearray([0x5A, packet_type])
        #buf.extend(long_to_array(len(data), 2))
        #buf.extend(long_to_array(crc16(data, crc16(buf)), 2))
        buf.extend(data)
        #logging.debug('UART-OUT[0x]: %s', array_to_string(buf))
        repeat_count = 3
        while repeat_count > 0:
            # send packet
            self.ser.flushInput()
            self.ser.flushOutput()
            self.ser.write(buf)
            # wait for ACK
            start = time()
            while self.ser.inWaiting() < 2:
                if ((time() - start) * 1000) > timeout:
                    raise Exception("ACK timed out")
            ret = self.ser.read(2)
            #logging.debug('UART-ACK[0x]: %s', array_to_string(ret))
            repeat_count -= 1
            if ret[0] == 0x5A and ret[1] == 0xA1:
                return True
        raise Exception("Unable to send data")


