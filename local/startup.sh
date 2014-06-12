#!/bin/bash

if [ -L "$0" ]; then
	DIR=`readlink "$0"`
else
	DIR=$0
fi
DIR=`dirname "$DIR"`
SID=`ps -p $$ -o sid --no-headers`
if [ "$SID" = "$$" ]; then
	python2 "$DIR/startup.py" &
	cat <&0 >/dev/null
else
	python2 "$DIR/startup.py"
fi
