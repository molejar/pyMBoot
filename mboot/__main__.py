#!/usr/bin/env python

# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

import os
import sys
import click
import mboot
import bincopy
import traceback


########################################################################################################################
# Helper methods
########################################################################################################################
def hexdump(data, start_address=0, compress=True, length=16, sep='.'):
    """ Return string array in hex-dump format
    :param data:          {List} The data array of {Bytes}
    :param start_address: {Int}  Absolute Start Address
    :param compress:      {Bool} Compressed output (remove duplicated content, rows)
    :param length:        {Int}  Number of Bytes for row (max 16).
    :param sep:           {Char} For the text part, {sep} will be used for non ASCII char.
    """
    msg = []

    # The max line length is 16 bytes
    if length > 16:
        length = 16

    # Create header
    header = '  ADDRESS | '
    for i in range(0, length):
        header += "{:02X} ".format(i)
    header += '| '
    for i in range(0, length):
        header += "{:X}".format(i)
    msg.append(header)
    msg.append((' ' + '-' * (13 + 4 * length)))

    # Check address align
    offset = start_address % length
    address = start_address - offset
    align = True if (offset > 0) else False

    # Print flags
    prev_line = None
    print_mark = True

    # process data
    for i in range(0, len(data) + offset, length):

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
                        msg.append(' *')
                    continue
                else:
                    prev_line = subSrc
                    print_mark = True

        if align:
            hexa += '   ' * offset

        for h in range(0, len(subSrc)):
            h = subSrc[h]
            if not isinstance(h, int):
                h = ord(h)
            hexa += "{:02X} ".format(h)

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

        msg.append((' {:08X} | {:<' + str(length * 3) + 's}| {:s}').format(address + i, hexa, text))
        align = False

    msg.append((' ' + '-' * (13 + 4 * length)))
    return '\n'.join(msg)


class UInt(click.ParamType):
    """ Custom argument type for UINT """
    name = 'unsigned int'

    def __repr__(self):
        return 'UINT'

    def convert(self, value, param, ctx):
        try:
            if isinstance(value, int):
                return value
            else:
                return int(value, 0)
        except:
            self.fail('{} is not a valid value'.format(value), param, ctx)


class BDKey(click.ParamType):
    """ Custom argument type for BackDoor Key """
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
    """ Custom argument type for Image File """
    name = 'image path'

    def __init__(self, mode):
        self.mode = mode

    def __repr__(self):
        return 'IPATH'

    def convert(self, value, param, ctx):
        if not value.lower().endswith(('.bin', '.hex', '.ihex',  '.s19', '.srec')):
            self.fail('Unsupported file type: *.{} !'.format(value.split('.')[-1]), param, ctx)

        if self.mode == 'open' and not os.path.lexists(value):
            self.fail('File [{}] does not exist !'.format(value), param, ctx)

        return value


# Create instances of custom argument types
UINT    = UInt()
BDKEY   = BDKey()
INFILE  = ImagePath('open')
OUTFILE = ImagePath('save')


########################################################################################################################
# KBoot tool
########################################################################################################################

# Application error code
ERROR_CODE = 1

# Application version
VERSION = mboot.__version__

# Application description
DESCRIP = (
    "NXP MCU Bootloader Command Line Interface, version: " + VERSION + " \n\n"
    "NOTE: Development version, be carefully with it usage !\n"
)


# helper method
def scan_usb(device_name):
    # Scan for connected devices

    fsls = mboot.scan_usb(device_name)

    if fsls:
        index = 0

        if len(fsls) > 1:
            i = 0
            click.echo('')
            for fsl in fsls:
                click.secho(" %d) %s" % (i, fsl.info()))
                i += 1
            click.echo('\n Select: ', nl=False)
            c = input()
            click.echo()
            index = int(c, 10)

        click.secho(" DEVICE: %s\n" % fsls[index].info())
        return fsls[index]

    else:
        click.echo("\n - Target not detected !")
        sys.exit(ERROR_CODE)


# KBoot base options
@click.group(context_settings=dict(help_option_names=['-?', '--help']), help=DESCRIP)
@click.option('-t', '--target', type=click.STRING, default=None, help='Select target MKL27, LPC55, ... [optional]')
@click.option('-d', "--debug", type=click.IntRange(0, 2, True), default=0, help='Debug level: 0-off, 1-info, 2-debug')
@click.version_option(VERSION, '-v', '--version')
@click.pass_context
def cli(ctx, target, debug):

    if debug > 0:
        import logging
        log_level = [logging.NOTSET, logging.INFO, logging.DEBUG]
        logging.basicConfig(level=log_level[debug])

    ctx.obj['DEBUG'] = debug
    ctx.obj['TARGET'] = target

    click.echo()


# KBoot MCU Info Command
@cli.command(short_help="Get MCU info (mboot properties)")
@click.pass_context
def info(ctx):
    # Read KBoot MCU Info (Properties collection)

    nfo = []
    err_msg = ""

    # Scan USB
    hid_dev = scan_usb(ctx.obj['TARGET'])

    # Create KBoot instance
    kb = mboot.McuBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(hid_dev)
        # Get MCU info
        nfo = kb.get_mcu_info()
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' ERROR: {}'.format(str(e))

    # Disconnect KBoot device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if ctx.obj['DEBUG']:
        click.echo()

    # Print KBoot MCU Info
    for key, value in nfo.items():
        m = " {}:".format(key)
        if isinstance(value, list):
            m += "".join(["\n  - {}".format(s) for s in value])
        else:
            m += "\n  = {}".format(value)
        click.echo(m)


# KBoot MCU memory write command
@cli.command(short_help="Write data into MCU memory")
@click.option('-a', '--address', type=UINT, default=None, help='Start Address.')
@click.option('-o', '--offset', type=UINT, default=0, show_default=True, help='Offset of input data.')
@click.argument('file', nargs=1, type=INFILE)
@click.pass_context
def write(ctx, address, offset, file):

    err_msg = ""
    in_data = bincopy.BinFile()

    try:
        if file.lower().endswith(('.srec', '.s19')):
            in_data.add_srec_file(file)
            if address is None:
                address = in_data.minimum_address
        elif file.lower().endswith(('.hex', '.ihex')):
            in_data.add_ihex_file(file)
            if address is None:
                address = in_data.minimum_address
        else:
            in_data.add_binary_file(file)
            if address is None:
                address = 0

        data = in_data.as_binary()
    except Exception as e:
        raise Exception('Could not read from file: {} \n [{}]'.format(file, str(e)))

    if offset < len(data):
        data = data[offset:]

    # Scan USB
    hid_dev = scan_usb(ctx.obj['TARGET'])

    click.echo(' Writing into MCU memory, please wait !\n')

    # Create KBoot instance
    kb = mboot.McuBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(hid_dev)
        # Read Flash Sector Size of connected MCU
        flash_sector_size = kb.get_property(mboot.PropertyTag.FLASH_SECTOR_SIZE)

        # Align Erase Start Address and Len to Flash Sector Size
        start_address = (address & ~(flash_sector_size - 1))
        length = (len(data) & ~(flash_sector_size - 1))
        if (len(data) % flash_sector_size) > 0:
            length += flash_sector_size

        # Erase specified region in MCU Flash memory
        kb.flash_erase_region(start_address, length)

        # Write data into MCU Flash memory
        kb.write_memory(address, data)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if ctx.obj['DEBUG']:
        click.echo()

    click.echo(" Wrote Successfully.")


# KBoot MCU memory read command
@cli.command(short_help="Read data from MCU memory")
@click.option('-c', '--compress', is_flag=True, show_default=True, help='Compress dump output.')
@click.option('-f', '--file', type=OUTFILE, help='Output file name with ext.: *.bin, *.hex, *.ihex, *.srec or *.s19')
@click.argument('address', type=UINT)
@click.argument('length',  type=UINT, required=False)
@click.pass_context
def read(ctx, address, length, compress, file):

    data = None
    err_msg = ""

    # Scan USB
    hid_dev = scan_usb(ctx.obj['TARGET'])

    # Create KBoot instance
    kb = mboot.McuBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(hid_dev)
        if ctx.obj['DEBUG']: click.echo()
        if length is None:
            size = kb.get_property(mboot.PropertyTag.FLASH_SIZE)
            if address > (size - 1):
                raise Exception("LENGTH argument is required for non FLASH access !")
            length = size - address
        click.echo(" Reading from MCU memory, please wait ! \n")
        # Call KBoot flash erase all function
        data = kb.read_memory(address, length)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if file is None:
        if ctx.obj['DEBUG']: click.echo()
        click.echo(hexdump(data, address, compress))
    else:
        try:
            if file.lower().endswith(('.srec', '.s19')):
                srec = bincopy.BinFile()
                srec.add_binary(data, address)
                srec.header = 'mboot'
                with open(file, "w") as f:
                    f.write(srec.as_srec())
            elif file.lower().endswith(('.hex', '.ihex')):
                ihex = bincopy.BinFile()
                ihex.add_binary(data, address)
                with open(file, "w") as f:
                    f.write(ihex.as_ihex())
            else:
                with open(file, "wb") as f:
                    f.write(data)
        except Exception as e:
            raise Exception('Could not write to file: {} \n [{}]'.format(file, str(e)))

        click.echo("\n Successfully saved into: {}".format(file))


# KBoot MCU memory erase command
@cli.command(short_help="Erase MCU memory")
@click.option('-m/', '--mass/', is_flag=True, default=False, help='Erase complete MCU memory.')
@click.option('-a', '--address', type=UINT, help='Start Address.')
@click.option('-l', '--length',  type=UINT, help='Count of bytes aligned to flash block size.')
@click.pass_context
def erase(ctx, address, length, mass):

    err_msg = ""

    # Scan USB
    hid_dev = scan_usb(ctx.obj['TARGET'])

    # Create KBoot instance
    kb = mboot.McuBoot()

    try:
        if mass:
            # Connect KBoot USB device
            kb.open_usb(hid_dev)
            # Get available commands
            commands = kb.get_property(mboot.PropertyTag.AVAILABLE_COMMANDS)
            # Call KBoot flash erase all function
            if mboot.is_command_available(mboot.CommandTag.FLASH_ERASE_ALL_UNSECURE, commands):
                kb.flash_erase_all_unsecure()
            elif mboot.is_command_available(mboot.CommandTag.FLASH_ERASE_ALL, commands):
                kb.flash_erase_all()
            else:
                raise Exception('Not Supported Command')
        else:
            if address is None or length is None:
                raise Exception("Argument \"-a, --address\" and \"-l, --length\" must be defined !")
            # Connect KBoot USB device
            kb.open_usb(hid_dev)
            # Call KBoot flash erase region function
            kb.flash_erase_region(address, length)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(" Erased Successfully.")


# KBoot MCU unlock command
@cli.command(short_help="Unlock MCU")
@click.option('-k', '--key', type=BDKEY, help='Use backdoor key as ASCI = S:123...8 or HEX = X:010203...08')
@click.pass_context
def unlock(ctx, key):

    err_msg = ""

    # Scan USB
    hid_dev = scan_usb(ctx.obj['TARGET'])

    # Create KBoot instance
    kb = mboot.McuBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(hid_dev)

        if key is None:
            # Call KBoot flash erase all and unsecure function
            kb.flash_erase_all_unsecure()
        else:
            # Call KBoot flash security disable function
            kb.flash_security_disable(key)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if ctx.obj['DEBUG']:
        click.echo()

    click.echo(" Unlocked Successfully.")


# KBoot MCU fill memory command
@cli.command(short_help="Fill MCU memory with specified pattern")
@click.option('-p', '--pattern', type=UINT, default=0xFFFFFFFF, help='Pattern format (default: 0xFFFFFFFF).')
@click.argument('address', type=UINT)
@click.argument('length',  type=UINT)
@click.pass_context
def fill(ctx, address, length, pattern):

    err_msg = ""

    # Scan USB
    hid_dev = scan_usb(ctx.obj['TARGET'])

    # Create KBoot instance
    kb = mboot.McuBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(hid_dev)

        # Call KBoot fill memory function
        kb.fill_memory(address, length, pattern)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(" Filled Successfully.")


# KBoot MCU reset command
@cli.command(short_help="Reset MCU")
@click.pass_context
def reset(ctx):

    err_msg = ""

    # Scan USB
    hid_dev = scan_usb(ctx.obj['TARGET'])

    # Create KBoot instance
    kb = mboot.McuBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(hid_dev)

        # Call KBoot MCU reset function
        kb.reset()
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(" Reset OK")


def main():
    cli(obj={})


if __name__ == '__main__':
    main()
