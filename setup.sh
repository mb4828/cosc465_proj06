#!/bin/bash

args=`getopt c $*`

if [ $? != 0 ]; then
    echo "Usage: $0 [-c]"
    exit
fi

if [[ $args == " -c --" ]]; then
    echo "Doing cleanup."
    rm -rf pox
    rm -rf srpy
    rm -f *.pyc
    exit
fi
echo "Doing setup."

if [[ ! -d pox ]]; then
    git clone git://github.com/noxrepo/pox pox
else
    cd pox
    git pull
    cd ..
fi

if [[ ! -d srpy ]]; then
    git clone git://github.com/jsommers/srpy srpy
else
    cd srpy
    git pull
    cd ..
fi
