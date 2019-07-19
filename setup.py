#!/usr/bin/env python

# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText

from os import path
from setuptools import setup
from mboot import __version__, __license__, __author__, __contact__


def long_description():
    try:
        import pypandoc

        readme_path = path.join(path.dirname(__file__), 'README.md')
        return pypandoc.convert(readme_path, 'rst').replace('\r', '')
    except (IOError, ImportError):
        return (
            "More on: https://github.com/molejar/pyMBoot"
        )

setup(
    name='mboot',
    version=__version__,
    license=__license__,
    author=__author__,
    author_email=__contact__,
    url="https://github.com/molejar/pyMBoot",
    description='Python module for communication with NXP MCU Bootloader',
    long_description=long_description(),
    keywords="NXP MCU Bootloader",
    platforms="Windows, Linux",
    python_requires=">=3.5",
    setup_requires=[
        'setuptools>=40.0'
    ],
    install_requires=[
        'click==7.0',
        'pyserial==3.4',
        'bincopy==16.0.0',
        'easy_enum==0.2.0',
        'pyusb==1.0.0;platform_system!="Windows"',
        'pywinusb==0.4.2;platform_system=="Windows"'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Topic :: Scientific/Engineering',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: Utilities',
    ],
    packages=['mboot'],
    entry_points={
        'console_scripts': [
            'mboot = mboot.__main__:main',
        ],
    }
)
