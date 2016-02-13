#!/usr/bin/env python

# Copyright 2016 Martin Olejar
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
import logging
import kboot
from intelhex import IntelHex


VERSION = kboot.__version__


def hexdump(data, saddr=0, compress=True, length=16, sep='.'):
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

    # Print flags
    prev_line = None
    print_mark = True

    # process data
    for i in xrange(0, len(data) + offset, length):

        hexa = ''
        if align:
            subSrc = data[0: length - offset]
        else:
            subSrc = data[i - offset: i + length - offset]
            if compress:
                # compress output string
                if subSrc == prev_line:
                    if print_mark:
                        print_mark = False
                        result.append(' *')
                    continue
                else:
                    prev_line = subSrc
                    print_mark = True

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


class UInt(click.ParamType):
    """ Custom argument type for UINT
    """
    name = 'unsigned int'

    def __repr__(self):
        return 'UINT'

    def convert(self, value, param, ctx):
        try:
            if isinstance(value, (int, long)):
                return value
            else:
                return int(value, 0)
        except:
            self.fail('%s is not a valid value' % value, param, ctx)


class BDKey(click.ParamType):
    """ Custom argument type for BackDoor Key
    """
    name = 'backdoor key'

    def __repr__(self):
        return 'BDKEY'

    def convert(self, value, param, ctx):
        if value[0] == 'S':
            if len(value) < 18:
                self.fail('Short key, use 16 ASCII chars !', param, ctx)
            bdoor_key = [ord(k) for k in value[2:]]
        else:
            if len(value) < 34:
                self.fail('Short key, use 32 HEX chars !', param, ctx)
            value = value[2:]
            bdoor_key = []
            try:
                for i in range(0, len(value), 2):
                    bdoor_key.append(int(value[i:i+2], 16))
            except ValueError:
                self.fail('Unsupported HEX char in Key !', param, ctx)

        return bdoor_key


class ImagePath(click.ParamType):
    """ Custom argument type for Image File
    """
    name = 'image path'

    def __init__(self, mode):
        self.mode = mode

    def __repr__(self):
        return 'IPATH'

    def convert(self, value, param, ctx):
        if not value.lower().endswith(('.bin', '.hex', '.s19', '.srec')):
            self.fail('Unsupported file type !', param, ctx)

        if self.mode == 'open' and not os.path.lexists(value):
            self.fail('File [%s] does not exist !' % value, param, ctx)

        return value


# Create instances of custom argument types
UINT    = UInt()
BDKEY   = BDKey()
INFILE  = ImagePath('open')
OUTFILE = ImagePath('save')

# Create KBoot instance
KBOOT = kboot.KBoot()


# KBoot base options
@click.group(context_settings=dict(help_option_names=['-?', '--help']))
@click.option("--vid", type=UINT, default=kboot.DEFAULT_USB_VID,
              help='USB Vendor  ID (default: 0x{:04X})'.format(kboot.DEFAULT_USB_VID))
@click.option("--pid", type=UINT, default=kboot.DEFAULT_USB_PID,
              help='USB Product ID (default: 0x{:04X})'.format(kboot.DEFAULT_USB_PID))
@click.option("--debug", type=click.IntRange(0, 2, True), default=0, help='Set debug level (0-off, 1-info, 2-debug)')
@click.version_option(version=VERSION)
def cli(vid, pid, debug):
    errmsg = 'No MCU with KBoot detected !'

    if debug > 0:
        loglevel = [logging.NOTSET, logging.INFO, logging.DEBUG]
        logging.basicConfig(level=loglevel[debug])

    devs = KBOOT.scan_usb_devs(vid, pid)

    if devs:
        index = 0
        if len(devs) > 1:
            i = 0
            click.echo('')
            for dev in devs:
                click.secho(" %d) %s" % (i, dev.getInfo()))
                i += 1
            click.echo('\n Select: ', nl=False)
            c = click.getchar(True)
            click.echo('')
            index = int(c, 10)

        # Connect KBoot USB device
        KBOOT.connect_usb(devs[index])
        return

    raise Exception(errmsg)


# KBoot MCU Info Command
@cli.command("info", short_help="Get MCU info (kboot properties)")
def info():
    # Read KBoot MCU Info (Properties collection)
    info = KBOOT.get_mcu_info()

    # Print KBoot MCU Info
    click.echo("-" * 50)
    click.echo(" Connected MCU KBoot Info")
    click.echo("-" * 50)
    for key, value in info.items():
        click.secho(" %-20s = 0x%08X (%s)" % (key, value['raw_value'], value['string']))
    click.echo("-" * 50)

    # Disconnect KBoot device
    KBOOT.disconnect()


# KBoot MCU memory write command
@cli.command("write", short_help="Write data into MCU memory")
@click.option('-a', '--addr', type=UINT, default=0, help='Start Address (default: 0x00000000)')
@click.option('-o', '--offset', type=UINT, default=0, help='Offset of input data (default: 0x00000000)')
@click.option('-f', '--file', type=INFILE, required=True,
              help='Input file name with extension: *.bin, *.hex, *.s19 or *.srec')
def write(addr, offset, file):

    if file.lower().endswith('.bin'):
        with open(file, "rb") as f:
            data = f.read()
            f.close()
    elif file.lower().endswith('.hex'):
        ihex = IntelHex()
        try:
            ihex.loadfile(file, format='hex')
        except Exception as e:
            raise Exception('Could not read from file: %s \n [%s]' % (file, str(e)))
        else:
            dhex = ihex.todict()
            data = bytearray([0xFF]*(max(dhex.keys()) + 1))
            for i, val in dhex.items():
                data[i] = val
    else:
        srec = kboot.SRecFile()
        try:
            srec.open(file)
        except Exception as e:
            raise Exception('Could not read from file: %s \n [%s]' % (file, str(e)))
        else:
            data = srec.data
            if addr ==  0:
                addr = srec.start_addr

    if offset < len(data):
        data = data[offset:]

    click.echo('\n Writing into MCU memory, please wait !\n')

    # Read Flash Sector Size of connected MCU
    flashSectorSize = KBOOT.get_property(kboot.Property.FlashSectorSize)['raw_value']

    # Align Erase Start Address and Len to Flash Sector Size
    saddr = (addr & ~(flashSectorSize - 1))
    slen = (len(data) & ~(flashSectorSize - 1))
    if (len(data) % flashSectorSize) > 0:
        slen += flashSectorSize

    # Erase specified region in MCU Flash memory
    KBOOT.flash_erase_region(saddr, slen)

    # Write data into MCU Flash memory
    KBOOT.write_memory(addr, data)

    # Disconnect KBoot device
    KBOOT.disconnect()

    click.secho(" Done Successfully. \n")


# KBoot MCU memory read command
@cli.command("read", short_help="Read data from MCU memory")
@click.option('-a', '--addr', type=UINT, default=0, help='Start Address (default: 0x00000000)')
@click.option('-l', '--length', type=UINT, required=True, help='Count of bytes')
@click.option('-c/', '--compress/', is_flag=True, default=False, help='Compress dump output')
@click.option('-f', '--file', type=OUTFILE, help='Output file name with extension: *.bin, *.hex or *.s19')
def read(addr, length, compress, file):

    click.echo("\n Reading from MCU memory, please wait !\n")

    # Call KBoot flash erase all function
    data = KBOOT.read_memory(addr, length)

    # Disconnect KBoot Device
    KBOOT.disconnect()

    if file is None:
        click.echo(hexdump(data, addr, compress))
    else:
        if file.lower().endswith('.bin'):
            with open(file, "wb") as f:
                f.write(data)
                f.close()
        elif file.lower().endswith('.hex'):
            ihex = IntelHex()
            ihex.frombytes(data, 0)
            ihex.start_addr = addr
            try:
                ihex.tofile(file, format='hex')
            except Exception as e:
                raise Exception('Could not write to file: %s \n [%s]' % (file, str(e)))
        else:
            srec = kboot.SRecFile()
            srec.header = "pyKBoot"
            srec.start_addr = addr
            srec.data = data
            try:
                srec.save(file)
            except Exception as e:
                raise Exception('Could not write to file: %s \n [%s]' % (file, str(e)))

        click.secho(" Successfully saved into: %s. \n" % file)


# KBoot MCU memory erase command
@cli.command("erase", short_help="Erase MCU memory")
@click.option('-a', '--addr', type=UINT, default=0, help='Start Address (default: 0x00000000)')
@click.option('-l', '--length', type=UINT, help='Count of bytes (must be aligned to flash block size)')
@click.option('-m', '--mass', type=click.BOOL, default=False, help='Erase complete MCU memory')
def erase(addr, length, mass):

    if mass or not length:
        # Call KBoot flash erase all function
        KBOOT.flash_erase_all_unsecure()
    else:
        # Call KBoot flash erase region function
        KBOOT.flash_erase_region(addr, length)

    # Disconnect KBoot Device
    KBOOT.disconnect()


# KBoot MCU unlock command
@cli.command("unlock", short_help="Unlock MCU")
@click.option('-k', '--key', type=BDKEY, help='Use backdoor key as ASCI = S:123...8 or HEX = X:010203...08')
def unlock(key):

    if key is None:
        # Call KBoot flash erase all and unsecure function
        KBOOT.flash_erase_all_unsecure()
    else:
        # Call KBoot flash security disable function
        KBOOT.flash_security_disable(key)

    # Disconnect KBoot Device
    KBOOT.disconnect()


# KBoot MCU fill memory command
@cli.command("fill", short_help="Fill MCU memory with specified patern")
@click.option('-a', '--addr', type=UINT, default=0, help='Start Address (default: 0x00000000)')
@click.option('-l', '--length', type=UINT, required=True, help='Count of bytes')
@click.option('-p', '--pattern', type=UINT, default=0xFFFFFFFF, help='Pattern format (default: 0xFFFFFFFF)')
def fill(addr, length, pattern):
    # Call KBoot fill memory function
    KBOOT.fill_memory(addr, length, pattern)
    # Disconnect KBoot Device
    KBOOT.disconnect()


# KBoot MCU reset command
@cli.command("reset", short_help="Reset MCU")
def reset():
    # Call KBoot MCU reset function
    KBOOT.reset()


def main():
    try:
        cli(obj={})
    except Exception as e:
        # Disconnect KBoot Device
        KBOOT.disconnect()
        # Print Error Info
        click.secho('\n<E> %s\n' % str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
