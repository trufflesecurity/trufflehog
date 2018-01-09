import sys

import unittest2

if sys.version_info[:2] >= (2, 5):
    from unittest2.test._test_unittest2_with import *
else:

    class TestWith(unittest2.TestCase):

        @unittest2.skip('tests using with statement skipped on Python 2.4')
        def testWith(self):
            pass


if __name__ == '__main__':
    unittest2.main()