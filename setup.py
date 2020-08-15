#!/usr/bin/env python3
#
# Python setup for Qiling framework

import sys, os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
gb = {}
with open(os.path.join(here, "qiling", "__version__.py"), "r+") as f:
    exec(f.read(), gb)

VERSION = gb['__version__']

requirements = [
    "capstone>=4.0.1",
    "unicorn>=1.0.2rc4",
    "pefile>=2019.4.18",
    "python-registry>=1.3.1",
    "keystone-engine>=0.9.2"
]

with open("README.md", "r", encoding="utf-8") as ld:
    long_description = ld.read()

if "linux"  in sys.platform:
    requirements += ["python-magic>=0.4.16"]
else:
    requirements += ["python-magic-bin>=0.4.14"]


setup(
    name='qiling',
    version=VERSION,

    description='Qiling is an advanced binary emulation framework that cross-platform-architecture',
    url='http://qiling.io',
    long_description=long_description,
    long_description_content_type="text/markdown",
    maintainer='KaiJern Lau (xwings)',
    maintainer_email='info@qiling.io',

    license='GPLv2',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
    ],

    keywords='qiling binary emulator framework malware analysis UEFI IoT',

    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
)
