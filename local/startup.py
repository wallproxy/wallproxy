#!/usr/bin/env python
import sys, os
dir = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(os.path.join(dir, 'src.zip'))
del sys, os, dir
from proxy import main
main()
