# -*- coding: utf-8 -*-
# Module for compatibility with python 2.7 and 3.x

from __future__ import print_function

import sys
import io

IS_PYTHON_3 = sys.hexversion >= 0x3000000


# Python 2 BytesIO has no getbuffer method
if not hasattr(io.BytesIO(), 'getbuffer'):
    class BytesIO(io.BytesIO):
        def getbuffer(self):
            return memoryview(self.getvalue())
    io.BytesIO = BytesIO
