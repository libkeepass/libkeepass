
import os
import sys
import unittest

testdir = os.path.dirname(__file__)
projectdir = os.path.dirname(testdir)
sys.path.insert(0, os.path.abspath(projectdir))

from tests.tests import *
from tests.tests_merge import *
from tests.tests_check import *

if __name__ == '__main__':
    unittest.main()
