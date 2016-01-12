pyKBoot
=======

pyKBoot is an Open Source python based library for configuring and upgrading the firmware in Kinetis Microcontrolers.

...


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

pyKBoot is distributed with command-line utility, which presents the complete functionality of this library. For its execution put `kboot` into shell and click enter. You will get the following output, witch is describing its usage (for getting the description of individual commands use `kboot COMMAND -?`).

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

API
---

