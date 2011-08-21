#!/bin/sh

autoreconf -i --force
"`pwd`/configure" $@
echo " "
echo "run \`make\` to compile"
