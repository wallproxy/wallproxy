#!/usr/bin/env python
import sys, os.path as ospath
dir = ospath.dirname(sys.argv[0])
sys.argv[1:] = [ospath.join(dir, 'uploader')]
sys.path.append(ospath.abspath(ospath.join(dir, '../local/src.zip')))
del sys, ospath, dir
from proxy import main
main()
