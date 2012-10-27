#!/usr/bin/env python
import sys, os.path as ospath
dir = ospath.dirname(sys.argv[0])
sys.argv[1:1] = [ospath.join(dir, 'uploader')]
sys.path.insert(0, ospath.abspath(ospath.join(dir, '../local/src.zip')))
del sys, ospath, dir
from proxy import main
main()
