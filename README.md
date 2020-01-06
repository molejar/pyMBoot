pyMBoot
=======

[![Build Status](https://travis-ci.org/molejar/pyMBoot.svg?branch=master)](https://travis-ci.org/molejar/pyMBoot)
[![PyPI Status](https://img.shields.io/pypi/v/mboot.svg)](https://pypi.python.org/pypi/mboot)
[![Python Version](https://img.shields.io/pypi/pyversions/mboot.svg)](https://www.python.org)

pyMBoot is an Open Source python based library for configuring and upgrading the firmware in NXP Microcontrolers via
embedded [MCUBOOT](https://www.nxp.com/support/developer-resources/software-development-tools/mcuxpresso-software-and-tools/mcuboot-mcu-bootloader-for-nxp-microcontrollers:MCUBOOT)
(MCU Bootloader). Detailed description of `MCUBOOT / KBOOT` key features and functionality is located [here](https://freescale.jiveon.com/docs/DOC-104512).

> This project is still in developing phase. Please, test it and report founded issues.

Dependencies
------------

- [Python >3.6](https://www.python.org) - The interpreter for Python programing language
- [Click](http://click.pocoo.org) - Python package for creating beautiful command line interface.
- [bincopy](https://github.com/eerimoq/bincopy) - Python package for parsing S-Record, Intel HEX and TI-TXT files.
- [easy_enum](https://github.com/molejar/pyEnum) - User friendly implementation of documented Enum type for Python language.
- [PyUSB](https://walac.github.io/pyusb/) - Python package to access USB devices in Linux OS.
- [PyWinUSB](https://github.com/rene-aguirre/pywinusb) - Python package that simplifies USB-HID communications on Windows OS.
- [pyserial](https://github.com/pyserial/pyserial) - Python package for communication over Serial port in Linux and Windows OS.

Installation
------------

```bash
 $ pip install mboot
```

To install the latest version from master branch execute in shell following command:

```bash
 $ pip install -U https://github.com/molejar/pyMBoot/archive/master.zip
```

In case of development, install it from cloned sources:

```bash
 $ git clone https://github.com/molejar/pyMBoot.git
 $ cd pyMBoot
 $ pip install -U -e .
```

**NOTE:** You may run into a permissions issues running these commands. Here are a few options how to fix it:

1. Run with `sudo` to install pyMBoot and dependencies globally
2. Specify the `--user` option to install locally into your home directory (export "~/.local/bin" into PATH variable if haven't).
3. Run the command in a [virtualenv](https://virtualenv.pypa.io/en/latest/) local to a specific project working set.

> For running `mboot` module or CLI without root privileges in Linux OS copy following udev rules
[90-imx-sdp.rules](https://github.com/molejar/pyIMX/blob/master/udev/90-imx-sdp.rules)
into `/etc/udev/rules.d` directory and reload it with command: `sudo udevadm control --reload-rules`.

Usage
-----

The API of `mboot` module is intuitive and fully reflecting the functionality described in reference manual of any 
supported device. It's basic usage is presented in following example.

```python
import mboot

devices = mboot.scan_usb()

if devices:
    mb = mboot.McuBoot(devices[0])
    mb.open()
    # read 100 bytes from address 0
    data = mb.read_memory(0, 100)
    if data is None:
        print(mb.status_info)
        mb.close()
        exit()

    # other commands ...

    mb.close()
```

`McuBoot` class is supporting `with` statement what is eliminating the explicit call of `open` and `close` methods. The 
code then looks more cleaner as you can see in following example.

```python
from mboot import scan_usb, McuBoot

devices = scan_usb()

if devices:
    with McuBoot(devices[0]) as mb:
        # read 100 bytes from address 0
        data = mb.read_memory(0, 100)
        if data is None:
            print(mb.status_info)
            exit()

        # other commands ...
```

> If you call `reset()` command inside `with` block, the device is automatically reopened. You can skip this with 
explicit argument `reset(reopen=False)`

By default is command error propagated by return value and must be processed individually for every command. In many 
use-cases is code execution interrupted if any command finish with error. Therefore you have the option to enable the 
exception also for command error. The code is then much more readable as you can see in flowing example.

```python
from mboot import scan_usb, McuBoot, McuBootError

devices = scan_usb()

if devices:
    try:
        with McuBoot(devices[0], True) as mb:
            # read 100 bytes from address 0
            data = mb.read_memory(0, 100)
            # other commands ...

    except McuBootError as e:
        print(str(e))
```

`mboot` module is implementing also logging functionality for easy debugging all communication interfaces. To get it
working you need only import `logging` module and set the logging level (`DEBUG` or `INFO`) with following line of code: 
`logging.basicConfig(level=logging.DEBUG)`

```python
import logging

logging.basicConfig(level=logging.DEBUG)
```

**The example of terminal output with enabled logging functionality:**

```text
INFO:MBOOT:Connect: USB COMPOSITE DEVICE (0x15A2, 0x0073)
DEBUG:MBOOT:USB:Open Interface
INFO:MBOOT:CMD: ReadMemory(address=0x00000000, length=100, mem_id=0)
DEBUG:MBOOT:TX-PACKET: Tag=ReadMemory, Flags=0x00, p0=0x00000000, p1=0x00000064, p2=0x00000000
DEBUG:MBOOT:USB:OUT[64]: 01 00 20 00 03 00 00 03 00 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 00 ...
DEBUG:MBOOT:USB:IN [36]: 03 00 0C 00 A3 01 00 02 00 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 00 ...
INFO:MBOOT:RX-PACKET: Tag=ReadMemoryResponse, Status=Success, Length=100
DEBUG:MBOOT:USB:IN [36]: 04 00 20 00 00 60 00 20 C1 00 00 00 0D 85 00 00 09 01 00 00 00 00 00 00 00 ...
DEBUG:MBOOT:USB:IN [36]: 04 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00 00 ...
DEBUG:MBOOT:USB:IN [36]: 04 00 20 00 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 09 ...
DEBUG:MBOOT:USB:IN [36]: 04 00 04 00 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 09 ...
DEBUG:MBOOT:USB:IN [36]: 03 00 0C 00 A0 00 00 02 00 00 00 00 03 00 00 00 09 01 00 00 09 01 00 00 09 ...
DEBUG:MBOOT:RX-PACKET: Tag=GenericResponse, Status=Success, Cmd=ReadMemory
INFO:MBOOT:CMD: Successfully Received 100 from 100 Bytes
DEBUG:MBOOT:USB:Close Interface
```

[ mboot ] Tool
--------------

The `mboot` module is distributed with command-line utility, which demonstrate the complete functionality of this library 
and can be used as replacement of `blhos` tool. If you write `mboot` into shell and click enter, then you get the description 
of its usage. For getting the help of individual commands just use `mboot <command name> -?`.

``` bash
  $ mboot --help
  
    Usage: mboot [OPTIONS] COMMAND [ARGS]...
    
      NXP MCU Bootloader Command Line Interface, version: 0.3.0
      
      NOTE: Development version, be carefully with it usage !
      
    Options:
      -t, --target TEXT          Select target MKL27, LPC55, ... [optional]
      -d, --debug INTEGER RANGE  Debug level: 0-off, 1-info, 2-debug
      -v, --version              Show the version and exit.
      -?, --help                 Show this message and exit.
    
    Commands:
      call             Call code from specified address
      efuse            Read/Write eFuse from MCU
      erase            Erase MCU internal or external memory
      execute          Execute code from specified address
      fill             Fill MCU memory with specified pattern
      info             Get MCU info (mboot properties)
      keyblob          Generate the Blob for given DEK Key
      kp-enroll        Key provisioning: Enroll
      kp-gen-key       Key provisioning: Generate Intrinsic Key
      kp-read-kstore   Key provisioning: Read the key from key store area
      kp-read-nvm      Key provisioning: Read the key from nonvolatile memory
      kp-user-key      Key provisioning: Send the user key to a bootloader
      kp-write-kstore  Key provisioning: Write the key into key store area
      kp-write-nvm     Key provisioning: Write the key into nonvolatile memory
      mconf            Configure external memory
      mlist            Get list of available memories
      otp              Read/Write internal OTP segment
      read             Read data from MCU internal or external memory
      reset            Reset MCU
      resource         Flash read resource
      sbfile           Receive SB file
      unlock           Unlock MCU
      update           Copy backup app from address to main app region
      write            Write data into MCU internal or external memory

```

> If USB device is not in known devices list, then use `-t or --target` argument and directly specify the device VID:PID. Example: **-t 0x15A2:0x0073**

<br>

#### $ mboot info

Read bootloader properties from connected MCU.

```bash
 $ mboot info

 DEVICE: Kinetis Bootloader (0x15A2, 0x0073)

 CurrentVersion: K1.0.0
 AvailablePeripherals:
  - UART
  - I2C-Slave
  - SPI-Slave
  - USB-HID
 FlashStartAddress: 0x00000000
 FlashSize: 256.0 kiB
 FlashSectorSize: 1.0 kiB
 FlashBlockCount: 2
 AvailableCommands:
  - FlashEraseAll
  - FlashEraseRegion
  - ReadMemory
  - FillMemory
  - FlashSecurityDisable
  - ReceiveSBFile
  - Call
  - Reset
  - SetProperty
 VerifyWrites: ON
 MaxPacketSize: 32 B
 ReservedRegions:
  - 0x1FFFF800 - 0x20000687, 3.6 kiB
 ValidateRegions: ON
 RamStartAddress: 0x1FFFE000
 RamSize: 32.0 kiB
 SystemDeviceIdent: 0x23160D82
 FlashSecurityState: Unlocked

```

<br>

#### $ mboot mlist

Get list of available memories (internal and external)

```bash
 $ mboot info

 DEVICE: Kinetis Bootloader (0x15A2, 0x0073)

 Internal Flash:
  0) 0x00000000 - 0x00040000, Size: 256.0 kiB, Sector Size: 1.0 kiB

 Internal Ram:
  0) 0x1FFFE000 - 0x20006000, Size: 32.0 kiB

```

<br>

#### $ mboot read [OPTIONS] ADDRESS [LENGTH]

Read data from MCU memory and store it into file as binary (*.bin), intel-hex (*.hex, *.ihex) or s-record (*.srec, *.s19) 
format. If output file is not specified, the data are dumped into stdout in readable format. 

> LENGTH argument is optional and as default will be used the size to end of memory

##### options:
* **-c, --compress** - Compress dump output. (default: False)
* **-f, --file** -  Output file name with extension: *.bin, *.hex, *.ihex, *.srec or *.s19
* **-?, --help** - Show help message and exit.

``` bash
 $ mboot read 0 200
 
 Reading from MCU memory, please wait !

  ADDRESS | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | 0123456789ABCDEF
 -----------------------------------------------------------------------------
 00000000 | 00 60 00 20 C1 00 00 00 D9 08 00 00 09 01 00 00 | .`. ............
 00000010 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
 00000020 | 00 00 00 00 00 00 00 00 00 00 00 00 09 01 00 00 | ................
 00000030 | 00 00 00 00 00 00 00 00 09 01 00 00 09 01 00 00 | ................
 00000040 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 00000050 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 00000060 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 00000070 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 00000080 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 00000090 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 000000A0 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 000000B0 | 09 01 00 00 09 01 00 00 09 01 00 00 09 01 00 00 | ................
 000000C0 | 0A 49 0B 4A 0B 4B 9B 1A                         | .I.J.K..
 -----------------------------------------------------------------------------
```

<br>

#### $ mboot write [OPTIONS] FILE

Write data from attached FILE into MCU memory.

##### options:
* **-a, --address** - Start Address. (default: 0)
* **-o, --offset** - Offset of input data. (default: 0)
* **-?, --help** - Show help message and exit.

``` bash
 $ mboot write blink.srec

 Wrote Successfully.
```

<br>

#### $ mboot erase [OPTIONS]

Erase MCU memory from specified address and length or complete chip. 

##### options:
* **-m, --mass** - Erase complete MCU memory.
* **-a, --address** - Start Address.
* **-l, --length** - Count of bytes aligned to flash block size.
* **-?, --help** - Show help message and exit.

``` bash
 $ mboot erase -m

 Chip Erased Successfully.
```

<br>

#### $ mboot unlock [OPTIONS]

Unlock MCU memory. 

##### options:
* **-k, --key** - Use backdoor key as ASCII = S:123...8 or HEX = X:010203...08
* **-?, --help** - Show help message and exit.

``` bash
 $ mboot unlock

 Chip Unlocked Successfully.
```

<br>

#### $ mboot fill [OPTIONS] ADDRESS LENGTH

Fill MCU memory with specified pattern

##### options:
* **-p, --pattern** - Pattern format (default: 0xFFFFFFFF).
* **-?, --help** - Show help message and exit.

``` bash
 $ mboot fill -p 0x11111111 0x1FFFE000 10

 Filled Successfully.
```

<br>

#### $ mboot reset

MCU SW reset

``` bash
 $ mboot reset
```

TODO
----

- Implement support for UART interface



