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

import os
import sys
import click
import kboot
import traceback


########################################################################################################################
# Helper methods
########################################################################################################################
def hexdump(data, saddr=0, compress=True, length=16, sep='.'):
    """ Return string array in hex dump.format
    :param data:     {List} The data array of {Bytes}
    :param saddr:    {Int}  Absolute Start Address
    :param compress: {Bool} Compressed output (remove duplicated content, rows)
    :param length:   {Int}  Number of Bytes for row (max 16).
    :param sep:      {Char} For the text part, {sep} will be used for non ASCII char.
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
    offset = saddr % length
    address = saddr - offset
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
        if not value.lower().endswith(('.bin', '.hex', '.s19', '.srec')):
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
VERSION = kboot.__version__

# Application description
DESCRIP = (
    "Kinetis Bootloader Command Line Interface, version: " + VERSION + " \n\n"
    "NOTE: Development version, be carefully with it usage !\n"
)


# KBoot base options
@click.group(context_settings=dict(help_option_names=['-?', '--help']), help=DESCRIP)
@click.option("--vid", type=UINT, default=kboot.DEFAULT_USB_VID,
              help='USB Vendor  ID (default: 0x{:04X})'.format(kboot.DEFAULT_USB_VID))
@click.option("--pid", type=UINT, default=kboot.DEFAULT_USB_PID,
              help='USB Product ID (default: 0x{:04X})'.format(kboot.DEFAULT_USB_PID))
@click.option('-d', "--debug", type=click.IntRange(0, 2, True), default=0, help='Debug level: 0-off, 1-info, 2-debug')
@click.version_option(VERSION, '-v', '--version')
@click.pass_context
def cli(ctx, vid, pid, debug):

    if debug > 0:
        import logging
        loglevel = [logging.NOTSET, logging.INFO, logging.DEBUG]
        logging.basicConfig(level=loglevel[debug])

    ctx.obj['DEBUG'] = debug
    ctx.obj['DEVICE'] = None

    devs = kboot.scan_usb(vid, pid)
    if devs:
        index = 0
        if len(devs) > 1:
            i = 0
            click.echo('')
            for dev in devs:
                click.secho(" {}) {}".format(i, dev.getInfo()))
                i += 1
            click.echo('\n Select: ', nl=False)
            c = click.getchar(True)
            click.echo('')
            index = int(c, 10)

        ctx.obj['DEVICE'] = devs[index]


# KBoot MCU Info Command
@cli.command(short_help="Get MCU info (kboot properties)")
@click.pass_context
def info(ctx):
    # Read KBoot MCU Info (Properties collection)

    nfo = []
    err_msg = ""

    if ctx.obj['DEVICE'] is None:
        click.echo("\n - No MCU with KBoot detected !")
        sys.exit(ERROR_CODE)

    # Create KBoot instance
    kb = kboot.KBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(ctx.obj['DEVICE'])
        # Get MCU info
        nfo = kb.get_mcu_info()
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    # Print KBoot MCU Info
    click.echo()
    for key, value in nfo.items():
        m = " {}:".format(key)
        if isinstance(value['string'], list):
            m += "".join(["\n  - {}".format(s) for s in value['string']])
        else:
            m += "\n  = {}".format(value['string'])
        click.secho(m)


# KBoot MCU memory write command
@cli.command(short_help="Write data into MCU memory")
@click.option('-a', '--addr',   type=UINT, default=0, show_default=True, help='Start Address.')
@click.option('-o', '--offset', type=UINT, default=0, show_default=True, help='Offset of input data.')
@click.argument('file', nargs=1, type=INFILE)
@click.pass_context
def write(ctx, addr, offset, file):

    err_msg = ""

    if file.lower().endswith('.bin'):
        with open(file, "rb") as f:
            data = f.read()
            f.close()
    elif file.lower().endswith('.hex'):
        ihex = kboot.IHexFile()
        try:
            ihex.open(file)
        except Exception as e:
            raise Exception('Could not read from file: {} \n [{}]'.format(file, str(e)))
        else:
            data = ihex.data
            if addr == 0:
                addr = ihex.start_address
    else:
        srec = kboot.SRecFile()
        try:
            srec.open(file)
        except Exception as e:
            raise Exception('Could not read from file: {} \n [{}]'.format(file, str(e)))
        else:
            data = srec.data
            if addr == 0:
                addr = srec.start_address

    if offset < len(data):
        data = data[offset:]

    click.echo('\n Writing into MCU memory, please wait !\n')

    if ctx.obj['DEVICE'] is None:
        click.echo("\n - No MCU with KBoot detected !")
        sys.exit(ERROR_CODE)

    # Create KBoot instance
    kb = kboot.KBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(ctx.obj['DEVICE'])
        # Read Flash Sector Size of connected MCU
        flashSectorSize = kb.get_property(kboot.PropEnum.FlashSectorSize)['raw_value']

        # Align Erase Start Address and Len to Flash Sector Size
        saddr = (addr & ~(flashSectorSize - 1))
        slen = (len(data) & ~(flashSectorSize - 1))
        if (len(data) % flashSectorSize) > 0:
            slen += flashSectorSize

        # Erase specified region in MCU Flash memory
        kb.flash_erase_region(saddr, slen)

        # Write data into MCU Flash memory
        kb.write_memory(addr, data)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    click.secho(" Done Successfully. \n")


# KBoot MCU memory read command
@cli.command(short_help="Read data from MCU memory")
@click.option('-c', '--compress', is_flag=True, show_default=True, help='Compress dump output.')
@click.option('-f', '--file', type=OUTFILE, help='Output file name with extension: *.bin, *.hex, *.srec or *.s19')
@click.argument('address', type=UINT)
@click.argument('length',  type=UINT)
@click.pass_context
def read(ctx, address, length, compress, file):

    data = None
    err_msg = ""

    if ctx.obj['DEVICE'] is None:
        click.echo("\n - No MCU with KBoot detected !")
        sys.exit(ERROR_CODE)

    # Create KBoot instance
    kb = kboot.KBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(ctx.obj['DEVICE'])

        click.echo("\n Reading from MCU memory, please wait !\n")
        # Call KBoot flash erase all function
        data = kb.read_memory(address, length)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)

    if file is None:
        click.echo(hexdump(data, address, compress))
    else:
        if file.lower().endswith('.bin'):
            with open(file, "wb") as f:
                f.write(data)
                f.close()
        elif file.lower().endswith('.hex'):
            ihex = kboot.IHexFile()
            ihex.append(kboot.IHexSegment(address, data))
            try:
                ihex.save(file)
            except Exception as e:
                raise Exception('Could not write to file: {} \n [{}]'.format(file, str(e)))
        else:
            srec = kboot.SRecFile()
            srec.header = "pyKBoot"
            srec.start_address = address
            srec.data = data
            try:
                srec.save(file)
            except Exception as e:
                raise Exception('Could not write to file: {} \n [{}]'.format(file, str(e)))

        click.secho(" Successfully saved into: {}".format(file))


# KBoot MCU memory erase command
@cli.command(short_help="Erase MCU memory")
@click.option('-m', '--mass', type=click.BOOL, default=False, help='Erase complete MCU memory.')
@click.option('-a', '--address', type=UINT, help='Start Address.')
@click.option('-l', '--length',  type=UINT, help='Count of bytes aligned to flash block size.')
@click.pass_context
def erase(ctx, address, length, mass):

    err_msg = ""

    if ctx.obj['DEVICE'] is None:
        click.echo("\n - No MCU with KBoot detected !")
        sys.exit(ERROR_CODE)

    # Create KBoot instance
    kb = kboot.KBoot()

    try:
        if mass:
            # Connect KBoot USB device
            kb.open_usb(ctx.obj['DEVICE'])
            # Call KBoot flash erase all function
            kb.flash_erase_all_unsecure()
        else:
            if address is None or length is None:
                raise Exception("Argument \"-a, --address\" and \"-l, --length\" must be defined !")
            # Connect KBoot USB device
            kb.open_usb(ctx.obj['DEVICE'])
            # Call KBoot flash erase region function
            kb.flash_erase_region(address, length)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)


# KBoot MCU unlock command
@cli.command(short_help="Unlock MCU")
@click.option('-k', '--key', type=BDKEY, help='Use backdoor key as ASCI = S:123...8 or HEX = X:010203...08')
@click.pass_context
def unlock(ctx, key):

    err_msg = ""

    if ctx.obj['DEVICE'] is None:
        click.echo("\n - No MCU with KBoot detected !")
        sys.exit(ERROR_CODE)

    # Create KBoot instance
    kb = kboot.KBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(ctx.obj['DEVICE'])

        if key is None:
            # Call KBoot flash erase all and unsecure function
            kb.flash_erase_all_unsecure()
        else:
            # Call KBoot flash security disable function
            kb.flash_security_disable(key)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)


# KBoot MCU fill memory command
@cli.command(short_help="Fill MCU memory with specified patern")
@click.option('-p', '--pattern', type=UINT, default=0xFFFFFFFF, help='Pattern format (default: 0xFFFFFFFF).')
@click.argument('address', type=UINT)
@click.argument('length',  type=UINT)
@click.pass_context
def fill(ctx, addr, length, pattern):

    err_msg = ""

    if ctx.obj['DEVICE'] is None:
        click.echo("\n - No MCU with KBoot detected !")
        sys.exit(ERROR_CODE)

    # Create KBoot instance
    kb = kboot.KBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(ctx.obj['DEVICE'])

        # Call KBoot fill memory function
        kb.fill_memory(addr, length, pattern)
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)


# KBoot MCU reset command
@cli.command(short_help="Reset MCU")
@click.pass_context
def reset(ctx):

    err_msg = ""

    if ctx.obj['DEVICE'] is None:
        click.echo("\n - No MCU with KBoot detected !")
        sys.exit(ERROR_CODE)

    # Create KBoot instance
    kb = kboot.KBoot()

    try:
        # Connect KBoot USB device
        kb.open_usb(ctx.obj['DEVICE'])

        # Call KBoot MCU reset function
        kb.reset()
    except Exception as e:
        err_msg = '\n' + traceback.format_exc() if ctx.obj['DEBUG'] else ' - ERROR: {}'.format(str(e))

    # Disconnect KBoot Device
    kb.close()

    if err_msg:
        click.echo(err_msg)
        sys.exit(ERROR_CODE)


def main():
    cli(obj={})
