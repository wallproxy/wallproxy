#!/bin/sh

(cd $HOME ; [ ! -d env ] && virtualenv env)

. $HOME/env/bin/activate

pip install -r requirements.txt
cp -Rf * $HOME/
