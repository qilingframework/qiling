#!/usr/bin/env python3
#
# Python setup for Qiling framework

from setuptools import setup, find_packages

# NOTE: use "-dev" for dev branch
VERSION = "1.4.7" + "-dev"
#VERSION = "1.4.6"

requirements = [
    "capstone>=4.0.1",
    "unicorn>=2.0.1",
    "pefile>=2022.5.30",
    "python-registry>=1.3.1",
    "keystone-engine>=0.9.2",
    "pyelftools>=0.28",
    "gevent>=20.9.0",
    "multiprocess>=0.70.12.2",
    "windows-curses>=2.1.0;platform_system=='Windows'",
    "pyyaml>=6.0",
    "python-fx",
    "questionary",
    "termcolor",
]

extras = {
    "fuzz" : [
        "unicornafl>=2.0.0;platform_system!='Windows'",
        "fuzzercorn>=0.0.1;platform_system=='Linux'"
    ],
    "RE": [
       "r2libr>=5.7.4",
    ]
}

with open("README.md", "r", encoding="utf-8") as ld:
    long_description = ld.read()

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
        #   5 - Production/Stable
        #'Development Status :: 5 - Production/Stable',
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
    scripts=['qltool', 'qltui.py'],
    package_data={
        'qiling': ['profiles/*.ql'],
        'qiling.debugger.gdb': ['xml/*/*'],
        'qiling.os.uefi': ['guids.csv']
    },
    install_requires=requirements,
    extras_require=extras,
)
