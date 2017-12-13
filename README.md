pyKBoot
=======

pyKBoot is an Open Source python based library for configuring and upgrading the firmware in Kinetis Microcontrolers with preloaded [KBOOT](http://www.nxp.com/products/microcontrollers-and-processors/arm-processors/kinetis-cortex-m/kinetis-symbols-footprints-and-models/kinetis-bootloader:KBOOT) (Kinetis Bootloader). Detailed description of KBOOT key features and functionality is located [here](https://freescale.jiveon.com/docs/DOC-104512).

<p align="center">
  <img src="https://github.com/molejar/pyKBoot/blob/master/doc/connection.png?raw=true" alt="KBoot: HW Connection"/>
</p>

> The pyKBoot project is still in alpha phase. Please, check issues for the ongoing tasks or todo tasks.

Dependencies
------------

- [Python 3.x](https://www.python.org) - The interpreter
- [Click](http://click.pocoo.org/6) - Python package for creating beautiful command line interface.
- [PyWinUSB](https://github.com/rene-aguirre/pywinusb) - Python package that simplifies USB-HID communications on Windows OS.
- [PyUSB](https://walac.github.io/pyusb/) - Python package to access USB devices in Linux OS.
- [pyserial](https://github.com/pyserial/pyserial) - Python package for communication over Serial port in Linux and Windows OS.

Installation
------------

To install the latest version from master branch execute in shell following command:

``` bash
    $ pip3 install -U https://github.com/molejar/pyKBoot/archive/master.zip
```

In case of development, install it from cloned sources:

``` bash
    $ git clone https://github.com/molejar/pyKBoot.git
    $ cd pyKBoot
    $ pip3 install -U -e .
```

**NOTE:** You may run into a permissions issues running these commands. Here are a few options how to fix it:

1. Run with `sudo` to install pyIMX and dependencies globally
2. Specify the `--user` option to install locally into your home directory (export "~/.local/bin" into PATH variable if haven't).
3. Run the command in a [virtualenv](https://virtualenv.pypa.io/en/latest/) local to a specific project working set.

Usage
-----

The following example is showing how to use `kboot` module in your code.

``` python

    import kboot

    kb = kboot.KBoot() # Create KBoot instance

    try:
        devs = kboot.scan_usb()    # Get connected MCU's with KBOOT.
        if devs:
            kb.open_usb(devs[0])  # Connect to first USB device from all founded

            info = kb.get_mcu_info() # Get MCU info (All KBoot parameters)
            for key, value in info.items():
                m = " {}:".format(key)
                if isinstance(value['string'], list):
                    m += "".join(["\n  - {}".format(s) for s in value['string']])
                else:
                    m += "\n  = {}".format(value['string'])
                print(m)
            
            # Read MCU memory: 100 bytes from address 0
            data = kb.read_memory(start_address=0, length=100)

            ... # other commands

            kb.close()
    except Exception as e:     # Handle exception
        print(str(e))

```

[ kboot ] Tool
--------------

pyKBoot is distributed with command-line utility `kboot`, which presents the complete functionality of this library. 
If you write `kboot` into shell and click enter, then you get the description of its usage. For getting the help of 
individual commands just use `kboot <command name> -?`.

``` bash
  $ kboot --help
  
    Usage: kboot [OPTIONS] COMMAND [ARGS]...
    
      Kinetis Bootloader Command Line Interface, version: 0.1.4
      
      NOTE: Development version, be carefully with it usage !
      
    Options:
      --vid UNSIGNED INT         USB Vendor  ID (default: 0x15A2)
      --pid UNSIGNED INT         USB Product ID (default: 0x0073)
      -d, --debug INTEGER RANGE  Debug level: 0-off, 1-info, 2-debug
      -v, --version              Show the version and exit.
      -?, --help                 Show this message and exit.
    
    Commands:
      erase   Erase MCU memory
      fill    Fill MCU memory with specified patern
      info    Get MCU info (kboot properties)
      read    Read data from MCU memory
      reset   Reset MCU
      unlock  Unlock MCU
      write   Write data into MCU memory
```

<br>

#### $ kboot info

Read kboot properties fro connected MCU.

``` bash
 $ kboot info

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

#### $ kboot read [OPTIONS] ADDRESS LENGTH

Read data from MCU memory and store it into file as binary (*.bin), intel-hex (*.hex) or s-record (*.srec or *.s19) 
format. If output file is not specified, the data are dumped into stdout. 

##### options:
* **-c, --compress** - Compress dump output. (default: False)
* **-f, --file** -  Output file name with extension: *.bin, *.hex, *.srec or *.s19
* **-?, --help** - Show help message and exit.

``` bash
 $ kboot read 0 200                                                                                                                                                    

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

#### $ kboot write [OPTIONS] FILE

Write data from attached FILE into MCU memory.

##### options:
* **-a, --address** - Start Address. (default: 0)
* **-o, --offset** - Offset of input data. (default: 0)
* **-?, --help** - Show help message and exit.

``` bash
 $ kboot write blink.srec

 Wrote Successfully.
```

<br>

#### $ kboot erase [OPTIONS]

Erase MCU memory from specified address and length or complete chip. 

##### options:
* **-m, --mass** - Erase complete MCU memory.
* **-a, --address** - Start Address.
* **-l, --length** - Count of bytes aligned to flash block size.
* **-?, --help** - Show help message and exit.

``` bash
 $ kboot erase -m

 Chip Erased Successfully.
```

<br>

#### $ kboot unlock [OPTIONS]

Unlock MCU memory. 

##### options:
* **-k, --key** - Use backdoor key as ASCI = S:123...8 or HEX = X:010203...08
* **-?, --help** - Show help message and exit.

``` bash
 $ kboot unlock

 Chip Unlocked Successfully.
```

<br>

#### $ kboot fill [OPTIONS] ADDRESS LENGTH

Fill MCU memory with specified pattern

##### options:
* **-p, --pattern** - Pattern format (default: 0xFFFFFFFF).
* **-?, --help** - Show help message and exit.

``` bash
 $ kboot fill -p 0x11111111 0x1FFFE000 10

 Filled Successfully.
```

<br>

#### $ kboot reset

MCU SW reset

``` bash
 $ kboot reset
```

TODO
----

- Implement support for UART interface



