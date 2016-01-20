pyKBoot
=======

pyKBoot is an Open Source python based library for configuring and upgrading the firmware in Kinetis Microcontrolers with preloaded [KBOOT](http://www.nxp.com/products/microcontrollers-and-processors/arm-processors/kinetis-cortex-m/kinetis-symbols-footprints-and-models/kinetis-bootloader:KBOOT) (Kinetis Bootloader). 

<p align="center">
  <img src="https://github.com/molejar/pyKBoot/blob/master/doc/connection.png?raw=true" alt="KBoot: HW Connection"/>
</p>

KBOOT provides two ways for implementing, ROM bootloader and Flash bootloader, ROM bootloader is only applicable to the Kinetis MCUs which already integrate the ROM and the KBOOT application reside in it. So the ROM bootloader is available during the entire product life cycle.  The opposite side, the Kinetis MCUs without ROM can be programmed through the Flash bootloader. For the Flash bootloader, it runs into RAM and receive the application image, after it program the image into the Flash completely, then it Flash bootloader will go to die, in another word, it will no longer be available again. More details you canh found [here][KBOOT](http://www.nxp.com/products/microcontrollers-and-processors/arm-processors/kinetis-cortex-m/kinetis-symbols-footprints-and-models/kinetis-bootloader:KBOOT) and [here](https://freescale.jiveon.com/docs/DOC-104512)

Installation
------------

To install the latest development version (master branch) execute in shell the following command:

``` bash
    $ pip install --pre -U https://github.com/molejar/pyKBoot/archive/master.zip
```

Note that you may run into permissions issues running these commands.
You have a few options here:

1. Run with `sudo -H` to install pyKBoot and dependencies globally
2. Specify the `--user` option to install local to your user
3. Run the command in a [virtualenv](https://virtualenv.pypa.io/en/latest/) local to a specific project working set.

You can also install from source by executing in shell the following commands:

``` bash
    $ git clone https://github.com/molejar/pyKBoot.git
    $ cd pyKBoot
    $ python setup.py install
```

With pyKBoot will be automatically installed the following packages:

  - [flufl.enum](https://pypi.python.org/pypi/flufl.enum) - A Python enumeration extension for easy to read syntax
  - [click](http://click.pocoo.org/6) - A Python "Command Line Interface Creation Kit"
  - [intelhex](https://pypi.python.org/pypi/IntelHex) - Python library for Intel HEX files manipulations
  - [pyusb](https://pypi.python.org/pypi/pyusb) - Python USB communications module for Linux OS
  - [pywinusb](https://pypi.python.org/pypi/pywinusb) - Python USB/HID communications module for Windows OS
  - [hidapi](https://pypi.python.org/pypi/hidapi/0.7.99.post9) - Python USB/HID communications module for OS X


Usage
-----

The following example is showing how to use `kboot` module in your code.

``` python

    from kboot import KBoot

    kboot = KBoot() # Create KBoot instance

    try:
        devs = kboot.scan_usb_devs()    # Get connected MCU's with KBOOT.
        if devs:
            kboot.connect(devs[0])      # Connect to first USB device from all founded

            info = kboot.get_mcu_info() # Get MCU info (All KBoot parameters)
            for key, value in info.items():
                print(" %-20s = 0x%08X (%s)" % (key, value['raw_value'], value['string']))
            
            # Read MCU memory: 100 bytes from address 0
            data = kboot.read_memory(start_address=0, length=100)

            ... # other commands

            kboot.disconnect()
    except Exception as e:              # Handle exception
        print(str(e))

```

pyKBoot is distributed with command-line utility `kboot`, which presents the complete functionality of this library. If you write `kboot` into shell and click enter, then you get the description of its usage. For getting the help of individual commands just use `kboot <command name> -?`.

``` bash
    $ kboot 
    $
    $ Usage: kboot [OPTIONS] COMMAND [ARGS]...
    $ 
    $ Options:
    $   --vid TEXT       USB Vendor  ID (default: 0x15A2)
    $   --pid TEXT       USB Product ID (default: 0x0073)
    $   --debug INTEGER  Set debug level (0-off, 1-info, 2-debug)
    $   --version        Show the version and exit.
    $   -?, --help       Show this message and exit.
    $
    $ Commands:
    $   erase   Erase MCU memory
    $   fill    Fill MCU memory with specified patern
    $   info    Get MCU info (kboot properties)
    $   read    Read data from MCU memory
    $   reset   Reset MCU
    $   unlock  Unlock MCU
    $   write   Write data into MCU memory
```

TODO
----

- Add UART interface support



