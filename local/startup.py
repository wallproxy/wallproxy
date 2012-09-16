#!/usr/bin/env python
import sys, os, os.path as ospath
#os.environ['DISABLE_GEVENT'] = '1'
dir = ospath.dirname(sys.argv[0])
sys.path.insert(0, ospath.abspath(ospath.join(dir, 'src.zip')))
del sys, os, ospath, dir
from proxy import main
main()
