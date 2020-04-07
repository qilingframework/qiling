#!/bin/bash
cp /usr/lib/dyld examples/rootfs/x8664_macos/usr/lib/;
find /usr/lib -type d -exec mkdir -p examples/rootfs/x8664_macos{} \;
find /usr/lib -type f -name "*.dylib" -not -name "libobjc.A.dylib" -exec install -v {} examples/rootfs/x8664_macos{} \;
