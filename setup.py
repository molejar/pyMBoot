#!/usr/bin/env python

# Copyright 2015 Martin Olejar
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import pip

from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

requirements = ['flufl.enum>=4.1', 'click>=6.0', 'intelhex>=2.0']

if sys.platform.startswith('linux'):
    requirements.extend([
        'pyusb>=1.0.0b2',
    ])
elif sys.platform.startswith('win'):
    requirements.extend([
        'pywinusb>=0.4.0',
    ])
elif sys.platform.startswith('darwin'):
    requirements.extend([
        'hidapi',
    ])

setup(
    name='kboot',
    version='0.1.1',
    description='Python module for Kinetis Bootloader',
    author='Martin Olejar',
    author_email='martin.olejar@gmail.com',
    keywords="kinetis bootloader",
    url="https://github.com/molejar/pyKBoot",
    license="Apache 2.0",
    classifiers = [
        'Programming Language :: Python',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Scientific/Engineering',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: Utilities',
    ],
    long_description=read('pypi_readme.rst'),
    entry_points = {
        'console_scripts': [
            'kboot = kboot_cli.main:main',
        ],
    },
    packages=['kboot', 'kboot_cli'], 
    install_requires = requirements,
    include_package_data = True,
)
