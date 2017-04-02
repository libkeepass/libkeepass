import unittest
import doctest

def suite():
    suite = unittest.TestSuite()
    suite.addTests(doctest.DocTestSuite(helloworld))
    suite.addTests(test_helloworld.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())