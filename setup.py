#!/usr/bin/env python3
#
# Python setup for Qiling framework



from setuptools import setup, find_packages

VERSION = '0.9'

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name = 'qiling',
    version = VERSION,

    description = 'Qiling is an advanced binary emulation framework that cross-platform-architecture.',
    url = 'http://qiling.io',

    maintainer = 'Nguyen Anh Quynh, KaiJern Lau, Tianze Ding, BoWen Sun, Huitao Chen, TongYu',
    maintainer_email = 'info@qiling.io',

    license = 'GPLv2',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers = [
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Production/Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
    ],

    keywords = 'qiling binary emulator framework',

    packages = find_packages(),

    install_requires = required,
)
