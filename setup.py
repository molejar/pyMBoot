#!/usr/bin/env python

# Copyright (c) 2019 Martin Olejar
#
# SPDX-License-Identifier: BSD-3-Clause
# The BSD-3-Clause license for this file can be found in the LICENSE file included with this distribution
# or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText


from os import path
from setuptools import setup, find_packages
from mboot import __version__, __license__, __author__, __contact__


def get_long_description():
    with open(path.join(path.dirname(path.abspath(__file__)), 'README.md'), encoding='utf8') as fp:
        return fp.read()


setup(
    name='mboot',
    version=__version__,
    license=__license__,
    author=__author__,
    author_email=__contact__,
    url="https://github.com/molejar/pyMBoot",
    description='Python module for communication with NXP MCU Bootloader',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    python_requires='>=3.6',
    setup_requires=[
        'setuptools>=40.0'
    ],
    install_requires=[
        'click==7.0',
        'pyserial==3.4',
        'bincopy==16.0.0',
        'easy_enum==0.3.0',
        'pyusb==1.0.2',
        'pywinusb==0.4.2;platform_system=="Windows"',
    ],
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'License :: OSI Approved :: BSD License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
        'Topic :: Scientific/Engineering',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: Utilities',
    ],
    packages=find_packages('.'),
    entry_points={
        'console_scripts': [
            'mboot = mboot.__main__:main',
        ],
    }
)
