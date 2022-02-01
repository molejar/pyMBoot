# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

import os
import sys
import click
import bincopy
import traceback

from mboot import McuBoot, scan_usb, ExtMemId, CommandTag, PropertyTag, parse_property_value


########################################################################################################################
# Helper methods
########################################################################################################################
def hexdump(data, start_address=0, compress=True, length=16, sep='.'):
    """ Return string array in hex-dump format
    :param data:          The data array of bytes
    :param start_address: Absolute Start Address
    :param compress:      Compressed output (remove duplicated content, rows)
    :param length:        Number of Bytes for row (max 16)
    :param sep:           Is used for non ASCII char
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
            substr = data[0: length - offset]
        else:
            substr = data[i - offset: i + length - offset]
            if compress:
                # compress output string
                if substr == prev_line:
                    if print_mark:
                        print_mark = False
                        msg.append(' *')
                    continue
                else:
                    prev_line = substr
                    print_mark = True

        if align:
            hexa += '   ' * offset

        for h in range(0, len(substr)):
            h = substr[h]
            if not isinstance(h, int):
                h = ord(h)
            hexa += "{:02X} ".format(h)

        text = ''
        if align:
            text += ' ' * offset

        for c in substr:
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


def size_fmt(num, kibibyte=True):
    base, suffix = [(1000., 'B'), (1024., 'iB')][kibibyte]
    for x in ['B'] + [x + suffix for x in list('kMGTP')]:
        if -base < num < base:
            break
        num /= base

    return "{} {}".format(num, x) if x == 'B' else "{:3.1f} {}".format(num, x)


class UInt(click.ParamType):
    """ Custom argument type for unsigned integer """

    name = 'uint'

    def __init__(self, min=None, max=None, clamp=False):
        self.min = min
        self.max = max
        self.clamp = clamp

    def __repr__(self):
        return 'UINT'

    def convert(self, value, param, ctx):
        try:
            if not isinstance(value, int):
                value = int(value, 0)
        except:
            self.fail('{} is not a valid value format.'.format(value), param, ctx)

        if self.clamp:
            if self.min is not None and value < self.min:
                return self.min
            if self.max is not None and value > self.max:
                return self.max

        if self.min is not None and value < self.min or self.max is not None and value > self.max:
            if self.min is None:
                self.fail('{} is bigger than the maximum valid value {}.'.format(value, self.max), param, ctx)
            elif self.max is None:
                self.fail('{} is smaller than the minimum valid value {}.'.format(value, self.min), param, ctx)
            else:
                self.fail('{} is not in the valid range of {} to {}.'.format(value, self.min, self.max), param, ctx)

        return value


class BDKey(click.ParamType):
    """ Custom argument type for BackDoor Key """

    name = 'backdoor key'

    def __repr__(self):
        return 'BDKEY'

    def convert(self, value, param, ctx):
        if value[0] == 'S':
            if len(value) < 18:
                self.fail('Short key, use 16 ASCII chars !', param, ctx)
            backdoor_key = [ord(k) for k in value[2:]]
        else:
            if len(value) < 34:
                self.fail('Short key, use 32 HEX chars !', param, ctx)
            value = value[2:]
            backdoor_key = []
            try:
                for i in range(0, len(value), 2):
                    backdoor_key.append(int(value[i:i+2], 16))
            except ValueError:
                self.fail('Unsupported HEX char in Key !', param, ctx)

        return backdoor_key


class ImgFile(click.ParamType):
    """ Custom argument type for Image File """

    name = 'file'

    def __init__(self, *extensions, exists=False):
        self.exists = exists
        self.valid_extensions = extensions

    def __repr__(self):
        return 'FILE'

    def convert(self, value, param, ctx):
        if not value.lower().endswith(self.valid_extensions):
            self.fail('Unsupported file type: *.{} !'.format(value.split('.')[-1]), param, ctx)

        if self.exists and not os.path.lexists(value):
            self.fail('File "{}" does not exist !'.format(value), param, ctx)

        return value


########################################################################################################################
# McuBoot CLI
########################################################################################################################

# Application error code
ERROR_CODE = 1

# Application version
VERSION = '0.3'

# Application description
DESCRIP = (
    "NXP MCU Bootloader Command Line Interface, version: " + VERSION + " \n\n"
    "NOTE: Development version, be carefully with it usage !\n"
)

# List of supported memories
MEMS = ['INTERNAL'] + [name for name, _, _ in ExtMemId]


# helper method
def print_error(message, debug=False):
    click.echo('\n' + traceback.format_exc() if debug else ' ' + message)
    sys.exit(ERROR_CODE)


# helper method
def scan_interface(device_name):
    # Scan for connected devices
    devs = scan_usb(device_name)

    if devs:
        index = 0

        if len(devs) > 1:
            click.echo('')
            for i, dev in enumerate(devs):
                click.secho("{}) {}".format(i, dev.info()))
            click.echo('\n Select: ', nl=False)
            c = input()
            click.echo()
            index = int(c, 10)

        click.secho(" DEVICE: {}\n".format(devs[index].info()))
        return devs[index]

    else:
        print_error("Device not connected !\n")


# McuBoot: base options
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


# McuBoot: MCU info command
@cli.command(short_help="Get MCU info (mboot properties)")
@click.pass_context
def info(ctx):

    properties = []
    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            properties = mb.get_property_list()

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    for p in properties:
        v = p.to_str()
        if isinstance(v, list):
            click.echo(f" {p.name}:" + "".join([f"\n  - {s}" for s in v]))
        else:
            click.echo(f" {p.name}: {v}")


# McuBoot: print memories list command
@cli.command(short_help="Get list of available memories")
@click.pass_context
def mlist(ctx):

    mem_list = {}
    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mem_list = mb.get_memory_list()

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    message = ''
    for key, values in mem_list.items():
        message += " {}:\n".format(key.title().replace('_', ' '))
        if key in ('internal_ram', 'internal_flash'):
            for i, item in values.items():
                message += "  {}) 0x{:08X} - 0x{:08X}, Size: {}".format(
                    i, item['address'], item['address'] + item['size'], size_fmt(item['size']))
                if 'sector_size' in item:
                    message += ", Sector Size: {}".format(size_fmt(item['sector_size']))
                message += '\n'
        else:
            for i, attr in enumerate(values):
                message += "  {}) {}:\n".format(i, attr['mem_name'])
                if 'address' in attr:
                    message += "     Start Address: 0x{:08X}\n".format(attr['address'])
                if 'size' in attr:
                    message += "     Memory Size:   {} ({} B)\n".format(size_fmt(attr['size']), attr['size'])
                if 'page_size' in attr:
                    message += "     Page Size:     {}\n".format(attr['page_size'])
                if 'sector_size' in attr:
                    message += "     Sector Size:   {}\n".format(attr['sector_size'])
                if 'block_size' in attr:
                    message += "     Block Size:    {}\n".format(attr['block_size'])
        message += '\n'

    click.echo(message)


# McuBoot: configure external memory command
@cli.command(short_help="Configure external memory")
@click.option('-a', '--address', type=UInt(), default=None, help='Location inside RAM for storing config data')
@click.option('-w', '--word', type=UInt(), multiple=True, default=None, help='Configuration word')
@click.option('-t', '--mtype', type=click.Choice(MEMS[1:]), default='QSPI', show_default=True, help='Memory Type')
@click.option('-f', '--file', type=ImgFile('.conf', exists=True), help='Memory configuration file')
@click.pass_context
def mconf(ctx, address, word, mtype, file):

    memory_id = ExtMemId[mtype]
    memory_data = bytes()

    if word:
        for w in word:
            memory_data += w.to_bytes(4, 'little')

    if file is not None:
        print_error("Not implemented yet load memory configuration from file")
        # load memory configuration fom file
        with open(file, 'r') as f:
            # TODO: add file parser into memory_data
            pass

    if not memory_data:
        print_error('The argument -w/--word or -f/--file must be specified !')

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            if address is None:
                # get internal memory start address and size
                memory_address = mb.get_property(PropertyTag.RAM_START_ADDRESS)[0]
                memory_size = mb.get_property(PropertyTag.RAM_SIZE)[0]
                # calculate address
                address = memory_address + memory_size - len(memory_data)
                # add additional offset 1024 Bytes
                address -= 1024

            mb.write_memory(address, memory_data)
            mb.configure_memory(memory_id, address)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: receive SB file command
@cli.command(short_help="Receive SB file")
@click.argument('file', nargs=1, type=ImgFile('.bin', '.sb', '.sb2', exists=True))
@click.pass_context
def sbfile(ctx, file):

    device = scan_interface(ctx.obj['TARGET'])

    with open(file, 'rb') as f:
        sb_data = f.read()

    try:
        with McuBoot(device, True) as mb:
            mb.receive_sb_file(sb_data)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: memory write command
@cli.command(short_help="Write data into MCU internal or external memory")
@click.option('-a', '--address', type=UInt(), default=None, help='Start Address.')
@click.option('-o', '--offset', type=UInt(), default=0, show_default=True, help='Offset of input data.')
@click.option('-t', '--mtype', type=click.Choice(MEMS), default='INTERNAL', show_default=True, help='Memory Type')
@click.option('-e', '--erase', is_flag=True, default=False, help='Erase')
@click.option('-v', '--verify', is_flag=True, default=False, help='Verify')
@click.argument('file', nargs=1, type=ImgFile('.bin', '.hex', '.ihex',  '.s19', '.srec', exists=True))
@click.pass_context
def write(ctx, address, offset, mtype, erase, verify, file):

    mem_id = 0 if mtype == 'INTERNAL' else ExtMemId[mtype]
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
        print_error(f"Could not read from file: {file} \n [{str(e)}]")
        raise

    if offset < len(data):
        data = data[offset:]

    device = scan_interface(ctx.obj['TARGET'])
    click.echo(' Writing into MCU memory, please wait !\n')

    try:
        with McuBoot(device, True) as mb:
            # Read Flash Sector Size of connected MCU
            flash_sector_size = mb.get_property(PropertyTag.FLASH_SECTOR_SIZE, mem_id)[0]
            # Align Erase Start Address and Len to Flash Sector Size
            start_address = (address & ~(flash_sector_size - 1))
            length = (len(data) & ~(flash_sector_size - 1))
            if (len(data) % flash_sector_size) > 0:
                length += flash_sector_size
            # Erase specified region in MCU Flash memory
            mb.flash_erase_region(start_address, length, mem_id)
            # Write data into MCU Flash memory
            mb.write_memory(address, data, mem_id)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.echo(" Writen Successfully.")


# McuBoot: memory read command
@cli.command(short_help="Read data from MCU internal or external memory")
@click.option('-t', '--mtype', type=click.Choice(MEMS), default='INTERNAL', show_default=True, help='Memory Type')
@click.option('-c', '--compress', is_flag=True, show_default=True, help='Compress dump output.')
@click.option('-f', '--file', type=ImgFile('.bin', '.hex', '.ihex',  '.s19', '.srec'),
              help='Output file name with ext.: *.bin, *.hex, *.ihex, *.srec or *.s19')
@click.argument('address', type=UInt())
@click.argument('length',  type=UInt())
@click.pass_context
def read(ctx, address, length, mtype, compress, file):

    mem_id = 0 if mtype == 'INTERNAL' else ExtMemId[mtype]
    device = scan_interface(ctx.obj['TARGET'])

    click.echo(" Reading from MCU memory, please wait ! \n")

    try:
        with McuBoot(device, True) as mb:
            data = mb.read_memory(address, length, mem_id)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    if file is None:
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
            print_error(f"Could not write to file: {file} \n [{str(e)}]")

        click.echo(f"\n Successfully saved into: {file}")


# McuBoot: memory erase command
@cli.command(short_help="Erase MCU internal or external memory")
@click.option('-m/', '--mass/', is_flag=True, default=False, help='Erase complete memory')
@click.option('-a', '--address', type=UInt(), help='Start Address.')
@click.option('-l', '--length',  type=UInt(), help='Count of bytes aligned to flash block size')
@click.option('-t', '--mtype', type=click.Choice(MEMS), default='INTERNAL', show_default=True, help='Memory Type')
@click.pass_context
def erase(ctx, address, length, mass, mtype):

    mem_id = 0 if mtype == 'INTERNAL' else ExtMemId[mtype]
    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            if mass:
                values = mb.get_property(PropertyTag.AVAILABLE_COMMANDS)
                commands = parse_property_value(PropertyTag.AVAILABLE_COMMANDS, values)
                if CommandTag.FLASH_ERASE_ALL_UNSECURE in commands:
                    mb.flash_erase_all_unsecure()
                elif CommandTag.FLASH_ERASE_ALL in commands:
                    mb.flash_erase_all(mem_id)
                else:
                    raise Exception('Not Supported Command')
            else:
                if address is None or length is None:
                    raise Exception("Argument \"-a, --address\" and \"-l, --length\" must be defined !")
                mb.flash_erase_region(address, length, mem_id)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(" Erased Successfully.")


# McuBoot: eFuse read/write command
@cli.command(short_help="Read/Write eFuse from MCU")
@click.argument('index', type=UInt())
@click.argument('value',  type=UInt(), required=False)
@click.pass_context
def efuse(ctx, index, value):

    read_value = 0
    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            if value is not None:
                mb.efuse_program_once(index, value)
            read_value = mb.efuse_read_once(index)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.echo(f" eFuse[{index}] = 0x{read_value:08X}")


# McuBoot: OTP read/write command
@cli.command(short_help="Read/Write internal OTP segment")
@click.option('-l', '--length', type=UInt(), default=4, show_default=True, help='Bytes count')
@click.argument('address', type=UInt())
@click.argument('data',  type=UInt(), required=False)
@click.pass_context
def otp(ctx, length, address, data):

    print_error("ERROR: 'otp' command is not implemented yet")

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            # TODO: write implementation
            pass

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: read resource command
@cli.command(short_help="Flash read resource")
@click.option('-o', '--option', type=UInt(), default=0, show_default=True, help='Option')
@click.option('-c', '--compress', is_flag=True, show_default=True, help='Compress dump output.')
@click.option('-f', '--file', type=ImgFile('.bin', '.hex', '.ihex',  '.s19', '.srec'),
              help='Output file name with ext.: *.bin, *.hex, *.ihex, *.srec or *.s19')
@click.argument('address', type=UInt())
@click.argument('length',  type=UInt())
@click.pass_context
def resource(ctx, address, length, option, compress, file):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            data = mb.flash_read_resource(address, length, option)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    if file is None:
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
            print_error(f'Could not write to file: {file} \n [{str(e)}]')

        click.echo(f" Successfully saved into: {file}")


# McuBoot: unlock command
@cli.command(short_help="Unlock MCU")
@click.option('-k', '--key', type=BDKey(), help='Use backdoor key as ASCI = S:123...8 or HEX = X:010203...08')
@click.pass_context
def unlock(ctx, key):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            if key is None:
                mb.flash_erase_all_unsecure()
            else:
                mb.flash_security_disable(key)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.echo(" Device unlocked successfully.")


# McuBoot: fill memory command
@cli.command(short_help="Fill MCU memory with specified pattern")
@click.option('-p', '--pattern', type=UInt(), default=0xFFFFFFFF, help='Pattern format (default: 0xFFFFFFFF).')
@click.argument('address', type=UInt())
@click.argument('length',  type=UInt())
@click.pass_context
def fill(ctx, address, length, pattern):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.fill_memory(address, length, pattern)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(f" Memory filled successfully with pattern: 0x{pattern:X}")


# McuBoot: reliable update command
@cli.command(short_help="Copy backup app from address to main app region")
@click.argument('address', type=UInt())
@click.pass_context
def update(ctx, address):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.reliable_update(address)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: call command
@cli.command(short_help="Call code from specified address")
@click.argument('address', type=UInt())
@click.argument('argument', type=UInt())
@click.pass_context
def call(ctx, address, argument):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.call(address, argument)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(" Code executed")


# McuBoot: execute command
@cli.command(short_help="Execute code from specified address")
@click.argument('address', type=UInt())
@click.argument('argument', type=UInt())
@click.argument('stackpointer', type=UInt())
@click.pass_context
def execute(ctx, address, argument, stackpointer):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.execute(address, argument, stackpointer)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(" Code executed")


# McuBoot: reset command
@cli.command(short_help="Reset MCU")
@click.pass_context
def reset(ctx):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.reset(reopen=False)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    click.secho(" Reset success")


# McuBoot: Generate key blob command
@cli.command(short_help="Generate the Blob for given DEK Key")
@click.option('-c', '--count', type=UInt(), default=72, show_default=True, help='Key blob count')
@click.argument('dekfile', nargs=1, type=ImgFile('.dek', exists=True))
@click.argument('blobfile', nargs=1, type=ImgFile('.bin'))
@click.pass_context
def keyblob(ctx, count, dekfile, blobfile):

    device = scan_interface(ctx.obj['TARGET'])

    with open(dekfile, "rb") as f:
        dek_data = f.read()

    try:
        with McuBoot(device, True) as mb:
            blob_data = mb.generate_key_blob(dek_data, count)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    with open(blobfile, "wb") as f:
        f.write(blob_data)

    click.echo(f" Successfully saved into: {blobfile}")

# McuBoot: Key provisioning command -> Enroll
@cli.command(short_help="Key provisioning: Enroll")
@click.pass_context
def kp_enroll(ctx):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.kp_enroll()

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: Key provisioning command -> Generate Intrinsic Key
@cli.command(short_help="Key provisioning: Generate Intrinsic Key")
@click.argument('key_type', type=UInt())
@click.argument('key_size', type=UInt())
@click.pass_context
def kp_gen_key(ctx, key_type, key_size):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.kp_set_intrinsic_key(key_type, key_size)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: Key provisioning command -> Send the user key to a bootloader
@cli.command(short_help="Key provisioning: Send the user key to a bootloader")
@click.argument('key_type', type=UInt())
@click.argument('file', nargs=1, type=ImgFile('.bin', exists=True))
@click.pass_context
def kp_user_key(ctx, key_type, file):

    device = scan_interface(ctx.obj['TARGET'])

    with open(file, "rb") as f:
        key_data = f.read()

    try:
        with McuBoot(device, True) as mb:
            mb.kp_set_user_key(key_type, key_data)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: Key provisioning command -> Write the key into nonvolatile memory
@cli.command(short_help="Key provisioning: Write the key into nonvolatile memory")
@click.argument('memid', type=UInt())
@click.pass_context
def kp_write_nvm(ctx, memid):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.kp_write_nonvolatile(memid)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: Key provisioning command -> Read the key from nonvolatile memory
@cli.command(short_help="Key provisioning: Read the key from nonvolatile memory")
@click.argument('memid', type=UInt())
@click.pass_context
def kp_read_nvm(ctx, memid):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            mb.kp_read_nonvolatile(memid)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: Key provisioning command -> Write the key into key store area
@cli.command(short_help="Key provisioning: Write the key into key store area")
@click.argument('key_type', type=UInt())
@click.argument('file', nargs=1, type=ImgFile('.bin', exists=True))
@click.pass_context
def kp_write_kstore(ctx, key_type, file):

    device = scan_interface(ctx.obj['TARGET'])

    with open(file, "rb") as f:
        key_data = f.read()

    try:
        with McuBoot(device, True) as mb:
            mb.kp_write_key_store(key_type, key_data)

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()


# McuBoot: Key provisioning command -> Read the key from key store area
@cli.command(short_help="Key provisioning: Read the key from key store area")
@click.option('-f', '--file', type=ImgFile('.bin'), help='Output file name with ext.: *.bin')
@click.pass_context
def kp_read_kstore(ctx, file):

    device = scan_interface(ctx.obj['TARGET'])

    try:
        with McuBoot(device, True) as mb:
            key_data = mb.kp_read_key_store()

    except Exception as e:
        print_error(str(e), ctx.obj['DEBUG'])

    if ctx.obj['DEBUG']:
        click.echo()

    if file is None:
        click.echo(hexdump(key_data))
    else:
        with open(file, "wb") as f:
            f.write(key_data)

        click.echo(f" Successfully saved into: {file}")


def main():
    cli(obj={})


if __name__ == '__main__':
    main()
