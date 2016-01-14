#!/usr/bin/env python

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

import os
import sys
import click
import struct
import logging

from intelhex import IntelHex
from kboot import KBoot, Status, SRecFile


VERSION = '0.1.1 Beta'


def hexdump(data, saddr=0, length=16, sep='.'):
    """ Return string array in hex dump.format
    :param data:   {list} The data array of {Int}
    :param saddr:  {Int} Absolute Start Address
    :param length: {Int} Nb Bytes by row (max 16).
    :param sep:    {Char} For the text part, {sep} will be used for non ASCII char.
    """

    result = []

    # Python3 support
    try:
        xrange(0, 1)
    except NameError:
        xrange = range

    # The max line length is 16 bytes
    if length > 16:
        length = 16

    # Create header
    header = '  address | '
    for i in xrange(0, length):
        header += "{0:02X} ".format(i)
    header += '| '
    for i in xrange(0, length):
        header += "{0:X}".format(i)
    result.append(header)
    result.append((' ' + '-' * (13 + 4 * length)))

    # Check address align
    offset = saddr % length
    address = saddr - offset
    align = True if (offset > 0) else False

    # process data
    for i in xrange(0, len(data) + offset, length):

        hexa = ''
        if align:
            subSrc = data[0: length - offset]
        else:
            subSrc = data[i - offset: i + length - offset]

        if align:
            hexa += '   ' * offset

        for h in xrange(0, len(subSrc)):
            h = subSrc[h]
            if not isinstance(h, int):
                h = ord(h)
            hexa += "{0:02X} ".format(h)

        text = ''
        if align:
            text += ' ' * offset

        for c in subSrc:
            if not isinstance(c, int):
                c = ord(c)
            if 0x20 <= c < 0x7F:
                text += chr(c)
            else:
                text += sep

        result.append((' %08X | %-' + str(length * 3) + 's| %s') % (address + i, hexa, text))
        align = False

    result.append((' ' + '-' * (13 + 4 * length)))
    return '\n'.join(result)


# Create KBoot instance
kboot = KBoot()

# Set default VID, PID
KBOOT_VID = '0x{:04X}'.format(kboot.DEFAULT_VID)
KBOOT_PID = '0x{:04X}'.format(kboot.DEFAULT_PID)


# KBoot common options
@click.group(context_settings=dict(help_option_names=['-?', '--help']))
@click.option("--vid", type=click.STRING, default=KBOOT_VID, multiple=False,
              help='USB Vendor  ID (default: {})'.format(KBOOT_VID))
@click.option("--pid", type=click.STRING, default=KBOOT_PID, multiple=False,
              help='USB Product ID (default: {})'.format(KBOOT_PID))
@click.option("--debug", default=0, multiple=False,
              help='Set debug level (0-off, 1-info, 2-debug)')
@click.version_option(version=VERSION)
def cli(vid, pid, debug):
    if debug > 0:
        loglevel = [logging.NOTSET, logging.INFO, logging.DEBUG]
        logging.basicConfig(level=loglevel[debug])

    try:
        usb_vid = int(vid, 0)
    except ValueError:
        raise Exception('\n Invalid value \"%s\" for \"--vid\" argument !\n' % vid)

    try:
        usb_pid = int(pid, 0)
    except ValueError:
        raise Exception('\n Invalid value \"%s\" for \"--pid\" argument !\n' % pid)

    devs = kboot.scan_usb_devs(usb_vid, usb_pid)

    if devs:
        index = 0
        if len(devs) > 1:
            i = 0
            for dev in devs:
                click.secho("%d) %s" % (i, dev.getInfo()))
                i += 1
            #c = raw_input('Select: ')
            click.echo('\n Select one:')
            c = click.getchar()
            index = int(c, 10)
        kboot.connect(devs[index])
    else:
        raise Exception('\n No MCU with KBoot detected !\n')


# KBoot MCU Info Command
@cli.command("info", short_help="Get MCU info (kboot properties)")
def info():
    if kboot.is_connected():
        info = kboot.get_mcu_info()
        click.echo("-" * 50)
        click.echo(" Connected MCU KBoot Info")
        click.echo("-" * 50)
        for key, value in info.items():
            click.secho(" %-20s = 0x%08X (%s)" % (key, value['raw_value'], value['string']))
        click.echo("-" * 50)
        kboot.disconnect()


# KBoot MCU memory write command
@cli.command("write", short_help="Write data into MCU memory")
@click.option('-a', '--addr', type=click.STRING, default='0x00000000', help='Start Address (default: 0x00000000)')
@click.option('-o', '--offset', type=click.STRING, default='0x00000000',
              help='Offset of input data (default: 0x00000000)')
@click.option('-f', '--file', type=click.STRING, required=True,
              help='Input file name with extension: *.bin, *.hex, *.s19 or *.srec')
def write(addr, offset, file):
    if kboot.is_connected():
        try:
            saddr = int(addr, 0)
        except ValueError:
            raise Exception('\n Invalid value \"%s\" for \"--addr\" argument !\n' % addr)

        try:
            foffset = int(offset, 0)
        except ValueError:
            raise Exception('\n Invalid value \"%s\" for \"--offset\" argument !\n' % offset)

        if os.path.lexists(file):
            data = []
            if file.lower().endswith('.bin'):
                with open(file, "rb") as f:
                    raw_data = f.read()
                    f.close()
                data += struct.unpack("%iB" % len(raw_data), raw_data)
            elif file.lower().endswith('.hex'):
                ihex = IntelHex()
                try:
                    ihex.loadfile(file, format='hex')
                except Exception as e:
                    raise Exception('\n Could not read from file: %s \n\n %s \n' % (file, str(e)))
                else:
                    dhex = ihex.todict()
                    data = [0xFF]*(max(dhex.keys()) + 1)
                    for i, val in dhex.items():
                        data[i] = val
            elif file.lower().endswith(('.s19', '.srec', '.s')):
                srec = SRecFile()
                try:
                    srec.open(file)
                except Exception as e:
                    raise Exception('\n Could not read from file: %s \n\n %s \n' % (file, str(e)))
                else:
                    data = srec.data
                    if saddr ==  0:
                        saddr = srec.start_addr
            else:
                raise Exception('\n Not supported file type ! \n')


        if foffset < len(data):
            data = data[foffset:]
        dlen = len(data)

        click.echo('\n Writing into MCU memory, please wait !!! \n')

        #status = kboot.flash_erase_region(saddr, dlen)
        status = kboot.flash_erase_all_unsecure()
        if status == Status.Success:
            status = kboot.write_memory(saddr, data)

        # Print status info
        click.secho("\n Write Command Status: %s \n" % Status(status).name)
        kboot.disconnect()



# KBoot MCU memory read command
@cli.command("read", short_help="Read data from MCU memory")
@click.option('-a', '--addr', type=click.STRING, default='0x00000000', help='Start Address (default: 0x00000000)')
@click.option('-l', '--length', type=click.STRING, required=True, help='Count of bytes')
@click.option('-f', '--file', type=click.STRING, help='Output file name with extension: *.bin, *.hex or *.s19')
def read(addr, length, file):
    if kboot.is_connected():
        try:
            saddr = int(addr, 0)
        except ValueError:
            raise Exception('\n Invalid value \"%s\" for \"--addr\" argument !\n' % addr)

        try:
            dlen = int(length, 0)
        except ValueError:
            raise Exception('\n Invalid value \"%s\" for \"--length\" argument !\n' % length)

        if file and not file.lower().endswith(('.bin', '.hex', '.s19', '.srec')):
            raise Exception('\n Not supported file type ! \n')

        click.echo("\n Reading from MCU memory, please wait !!! \n")

        status, data = kboot.read_memory(saddr, dlen)
        kboot.disconnect()
        if status != Status.Success:
            raise Exception("\n ERROR: %s \n" % Status(status).name)

        if file is None:
            click.echo(hexdump(data, saddr))
        else:
            if file.lower().endswith('.bin'):
                with open(file, "wb") as f:
                    f.write(bytearray(data))
                    f.close()
            elif file.lower().endswith('.hex'):
                ihex = IntelHex()
                ihex.frombytes(data, 0)
                ihex.start_addr = saddr
                try:
                    ihex.tofile(file, format='hex')
                except Exception as e:
                    raise Exception('\n Could not write to file: %s \n\n %s \n' % (file, str(e)))
            else:
                srec = SRecFile()
                srec.header = "KBOOT"
                srec.start_addr = saddr
                srec.data = data
                try:
                    srec.save(file)
                except Exception as e:
                    raise Exception('\n Could not write to file: %s \n\n %s \n' % (file, str(e)))


# KBoot MCU memory erase command
@cli.command("erase", short_help="Erase MCU memory")
@click.option('-a', '--addr', type=click.STRING, default='0x00000000', help='Start Address (default: 0x00000000)')
@click.option('-l', '--length', type=click.STRING, help='Count of bytes (must be aligned by 4)')
@click.option('-m', '--mass', type=click.BOOL, default=False, help='Erase complete MCU memory')
def erase(addr, length, mass):
    if kboot.is_connected():
        if mass or not length:
            # Call KBoot flash erase all function
            status = kboot.flash_erase_all_unsecure()
        else:
            try:
                saddr = int(addr, 0)
            except ValueError:
                raise Exception('\n Invalid value \"%s\" for \"--addr\" argument !\n' % addr)

            try:
                dlen = int(length, 0)
            except ValueError:
                raise Exception('\n Invalid value \"%s\" for \"--length\" argument !\n' % length)

            # Call KBoot flash erase region function
            status = kboot.flash_erase_region(saddr, dlen)

        kboot.disconnect()
        if status != Status.Success:
            raise Exception("\n ERROR: %s \n" % Status(status).name)


# KBoot MCU unlock command
@cli.command("unlock", short_help="Unlock MCU")
@click.option('-k', '--key', type=click.STRING, help='Use backdoor key as ASCI = S:TEST...F or HEX = X:010203...0F')
def unlock(key):
    if kboot.is_connected():
        if key is None:
            # Call KBoot flash erase all and unsecure function
            status = kboot.flash_erase_all_unsecure()
        else:
            if key[0] == 'S':
                if len(key) < 18:
                    raise Exception('\n Short key, use 16 ASCII chars !\n')
                bdoor_key = [ord(k) for k in key[2:]]
            else:
                if len(key) < 34:
                    raise Exception('\n Short key, use 32 HEX chars !\n')
                key = key[2:]
                bdoor_key = []
                try:
                    for i in range(0, len(key), 2):
                        bdoor_key.append(int(key[i:i+2], 16))
                except ValueError:
                    raise Exception('\n Unsupported HEX char in Key !\n')

            # Call KBoot flash security disable function
            status = kboot.flash_security_disable(bdoor_key)

        kboot.disconnect()
        if status != Status.Success:
            raise Exception("\n ERROR: %s \n" % Status(status).name)


# KBoot MCU fill memory command
@cli.command("fill", short_help="Fill MCU memory with specified patern")
@click.option('-a', '--addr', type=click.STRING, default='0x00000000', help='Start Address (default: 0x00000000)')
@click.option('-l', '--length', type=click.STRING, required=True, help='Count of bytes')
@click.option('-p', '--pattern', type=click.STRING, default='0xFFFFFFFF', help='Pattern format')
def fill(addr, length, pattern):
    if kboot.is_connected():
        try:
            saddr = int(addr, 0)
        except ValueError:
            raise Exception('\n Invalid value \"%s\" for \"--addr\" argument !\n' % addr)

        try:
            slen = int(length, 0)
        except ValueError:
            raise Exception('\n Invalid value \"%s\" for \"--length\" argument !\n' % length)

        try:
            spat = int(pattern, 0)
        except ValueError:
            raise Exception('\n Invalid value \"%s\" for \"--length\" argument !\n' % pattern)

        # Call KBoot fill memory function
        status = kboot.fill_memory(saddr, slen, spat)
        kboot.disconnect()
        if status != Status.Success:
            raise Exception("\n ERROR: %s \n" % Status(status).name)


# KBoot MCU reset command
@cli.command("reset", short_help="Reset MCU")
def reset():
    if kboot.is_connected():
        # Call KBoot MCU reset function
        status = kboot.reset()
        if status != Status.Success:
            raise Exception("\n ERROR: %s \n" % Status(status).name)


def main():
    try:
        cli(obj={})
    except Exception as e:
        kboot.disconnect()
        click.echo(str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
