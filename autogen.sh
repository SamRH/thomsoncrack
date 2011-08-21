#!/bin/sh
set -e
autoreconf -i --force
"`pwd`/configure" $@
echo " "
echo "run \`make\` to compile"
