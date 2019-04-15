pyMBoot
=======

[![Build Status](https://travis-ci.org/molejar/pyMBoot.svg?branch=master)](https://travis-ci.org/molejar/pyMBoot)
[![PyPI Status](https://img.shields.io/pypi/v/mboot.svg)](https://pypi.python.org/pypi/mboot)
[![Python Version](https://img.shields.io/pypi/pyversions/mboot.svg)](https://www.python.org)

pyMBoot is an Open Source python based library for configuring and upgrading the firmware in NXP Microcontrolers with
embedded [MCUBOOT](https://www.nxp.com/support/developer-resources/software-development-tools/mcuxpresso-software-and-tools/mcuboot-mcu-bootloader-for-nxp-microcontrollers:MCUBOOT)
(MCU Bootloader). Detailed description of `MCUBOOT / KBOOT` key features and functionality is located [here](https://freescale.jiveon.com/docs/DOC-104512).

> The pyMBoot project is still in beta phase. Please, check issues for the ongoing tasks or todo tasks.

Dependencies
------------

- [Python 3.x](https://www.python.org) - The interpreter
- [Click](http://click.pocoo.org) - Python package for creating beautiful command line interface.
- [bincopy](https://github.com/eerimoq/bincopy) - Python package for parsing S-Record, Intel HEX and TI-TXT files.
- [easy_enum](https://github.com/molejar/pyEnum) - User friendly implementation of documented Enum type for Python language.
- [PyUSB](https://walac.github.io/pyusb/) - Python package to access USB devices in Linux OS.
- [PyWinUSB](https://github.com/rene-aguirre/pywinusb) - Python package that simplifies USB-HID communications on Windows OS.
- [pyserial](https://github.com/pyserial/pyserial) - Python package for communication over Serial port in Linux and Windows OS.

Installation
------------

``` bash
    $ pip install mboot
```

To install the latest version from master branch execute in shell following command:

``` bash
    $ pip install -U https://github.com/molejar/pyMBoot/archive/master.zip
```

In case of development, install it from cloned sources:

``` bash
    $ git clone https://github.com/molejar/pyMBoot.git
    $ cd pyMBoot
    $ pip install -U -e .
```

**NOTE:** You may run into a permissions issues running these commands. Here are a few options how to fix it:

1. Run with `sudo` to install pyMBoot and dependencies globally
2. Specify the `--user` option to install locally into your home directory (export "~/.local/bin" into PATH variable if haven't).
3. Run the command in a [virtualenv](https://virtualenv.pypa.io/en/latest/) local to a specific project working set.

Usage
-----

The following example is showing how to use `mboot` module in your code.

``` python

    import mboot

    # Create mboot instance
    mb = mboot.McuBoot()

    try:
        # Scan for connected MCU's
        devs = mboot.scan_usb()

        if devs
            if len(devs) > 1:
                # Print list of connected devices
                for i, dev in enumerate(devs):
                    print("{}) {}".format(i, dev.info()))
                    
            # Connect to first USB device from all founded
            mb.open_usb(devs[0])

            # Read MCU memory: 100 bytes from address 0
            data = mb.read_memory(start_address=0, length=100)

            # Other commands
            # ...

            # Close USB port if finish
            mb.close()
            
        else:
            print("Connect device to PC !")

    # Handle exception
    except Exception as e:
        print(str(e))

```

[ mboot ] Tool
--------------

pyMBoot is distributed with command-line utility `mboot`, which presents the complete functionality of this library.
If you write `mboot` into shell and click enter, then you get the description of its usage. For getting the help of
individual commands just use `mboot <command name> -?`.

``` bash
  $ mboot --help
  
    Usage: mboot [OPTIONS] COMMAND [ARGS]...
    
      NXP MCU Bootloader Command Line Interface, version: 0.2.0
      
      NOTE: Development version, be carefully with it usage !
      
    Options:
      -t, --target TEXT          Select target MKL27, LPC55, ... [optional]
      -d, --debug INTEGER RANGE  Debug level: 0-off, 1-info, 2-debug
      -v, --version              Show the version and exit.
      -?, --help                 Show this message and exit.
    
    Commands:
      erase   Erase MCU memory
      fill    Fill MCU memory with specified patern
      info    Get MCU info (mboot properties)
      read    Read data from MCU memory
      reset   Reset MCU
      unlock  Unlock MCU
      write   Write data into MCU memory
```

> If USB device is not in known devices list, then use `-t or --target` argument and directly specify the device VID:PID. Example: **-t 0x15A2:0x0073**

<br>

#### $ mboot info

Read bootloader properties from connected MCU.

``` bash
 $ mboot info

 DEVICE: Kinetis Bootloader (0x15A2, 0x0073)

 CurrentVersion:
  = 1.0.0
 AvailablePeripherals:
  - UART
  - I2C-Slave
  - SPI-Slave
  - USB-HID
 FlashStartAddress:
  = 0x00000000
 FlashSize:
  = 256kB
 FlashSectorSize:
  = 1kB
 FlashBlockCount:
  = 2
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
 VerifyWrites:
  = 1
 MaxPacketSize:
  = 32B
 ReservedRegions:
  = 0
 ValidateRegions:
  = 1
 RAMStartAddress:
  = 0x1FFFE000
 RAMSize:
  = 32kB
 SystemDeviceIdent:
  = 0x23161D82
 FlashSecurityState:
  = Unlocked
```

<br>

#### $ mboot read [OPTIONS] ADDRESS [LENGTH]

Read data from MCU memory and store it into file as binary (*.bin), intel-hex (*.ihex) or s-record (*.srec or *.s19) 
format. If output file is not specified, the data are dumped into stdout in readable format. 

> LENGTH argument is optional and as default will be used the size to end of memory

##### options:
* **-c, --compress** - Compress dump output. (default: False)
* **-f, --file** -  Output file name with extension: *.bin, *.ihex, *.srec or *.s19
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



