from __future__ import with_statement

import inspect
import sys
import warnings

from six import u

import unittest2
from unittest2.test.support import OldTestResult
from unittest2.compatibility import catch_warnings

# needed to enable the deprecation warnings
warnings.simplefilter('default')

class TestWith(unittest2.TestCase):
    """Tests that use the with statement live in this
    module so that all other tests can be run with Python 2.4.
    """
    def setUp(self):
        self.foo = False

    def testAssertRaisesExcValue(self):
        class ExceptionMock(Exception):
            pass

        def Stub(foo):
            raise ExceptionMock(foo)
        v = "particular value"

        ctx = self.assertRaises(ExceptionMock)
        with ctx:
            Stub(v)
        e = ctx.exception
        self.assertIsInstance(e, ExceptionMock)
        self.assertEqual(e.args[0], v)


    def test_assertRaises(self):
        def _raise(e):
            raise e
        self.assertRaises(KeyError, _raise, KeyError)
        self.assertRaises(KeyError, _raise, KeyError("key"))
        try:
            self.assertRaises(KeyError, lambda: None)
        except self.failureException:
            e = sys.exc_info()[1]
            self.assertIn("KeyError not raised by <lambda>", e.args)
        else:
            self.fail("assertRaises() didn't fail")
        try:
            self.assertRaises(KeyError, _raise, ValueError)
        except ValueError:
            pass
        else:
            self.fail("assertRaises() didn't let exception pass through")
        with self.assertRaises(KeyError) as cm:
            try:
                raise KeyError
            except Exception:
                e = sys.exc_info()[1]
                raise
        self.assertIs(cm.exception, e)

        with self.assertRaises(KeyError):
            raise KeyError("key")
        try:
            with self.assertRaises(KeyError):
                pass
        except self.failureException:
            e = sys.exc_info()[1]
            self.assertIn("KeyError not raised", e.args)
        else:
            self.fail("assertRaises() didn't fail")
        try:
            with self.assertRaises(KeyError):
                raise ValueError
        except ValueError:
            pass
        else:
            self.fail("assertRaises() didn't let exception pass through")

    def test_assert_dict_unicode_error(self):
        with catch_warnings(record=True):
            # This causes a UnicodeWarning due to its craziness
            one = ''.join(chr(i) for i in range(255))
            # this used to cause a UnicodeDecodeError constructing the failure msg
            with self.assertRaises(self.failureException):
                self.assertDictContainsSubset({'foo': one}, {'foo': u('\uFFFD')})

    def test_formatMessage_unicode_error(self):
        with catch_warnings(record=True):
            # This causes a UnicodeWarning due to its craziness
            one = ''.join(chr(i) for i in range(255))
            # this used to cause a UnicodeDecodeError constructing msg
            self._formatMessage(one, u('\uFFFD'))

    def assertOldResultWarning(self, test, failures):
        with self.assertWarns(RuntimeWarning):
            result = OldTestResult()
            test.run(result)
            self.assertEqual(len(result.failures), failures)

    def test_old_testresult(self):
        class Test(unittest2.TestCase):
            def testSkip(self):
                self.skipTest('foobar')
            @unittest2.expectedFailure
            def testExpectedFail(self):
                raise TypeError
            @unittest2.expectedFailure
            def testUnexpectedSuccess(self):
                pass

        for test_name, should_pass in (('testSkip', True),
                                       ('testExpectedFail', True),
                                       ('testUnexpectedSuccess', False)):
            test = Test(test_name)
            self.assertOldResultWarning(test, int(not should_pass))


    def test_old_testresult_setup(self):
        class Test(unittest2.TestCase):
            def setUp(self):
                self.skipTest('no reason')
            def testFoo(self):
                pass
        self.foo = True
        self.assertOldResultWarning(Test('testFoo'), 0)

    def test_old_testresult_class(self):
        class Test(unittest2.TestCase):
            def testFoo(self):
                pass
        Test = unittest2.skip('no reason')(Test)
        self.assertOldResultWarning(Test('testFoo'), 0)

    def testDeprecatedMethodNames(self):
        """Test that the deprecated methods raise a DeprecationWarning.

        The fail* methods have been removed in 3.3. The assert* methods will
        have to stay around for a few more versions.  See #9424.
        """
        old = (
            (self.failIfEqual, (3, 5)),
            (self.assertNotEquals, (3, 5)),
            (self.failUnlessEqual, (3, 3)),
            (self.assertEquals, (3, 3)),
            (self.failUnlessAlmostEqual, (2.0, 2.0)),
            (self.assertAlmostEquals, (2.0, 2.0)),
            (self.failIfAlmostEqual, (3.0, 5.0)),
            (self.assertNotAlmostEquals, (3.0, 5.0)),
            (self.failUnless, (True,)),
            (self.assert_, (True,)),
            (self.failUnlessRaises, (TypeError, lambda _: 3.14 + 'spam')),
            (self.failIf, (False,)),
            (self.assertRaisesRegexp, (KeyError, 'foo', lambda: {}['foo'])),
            (self.assertRegexpMatches, ('bar', 'bar')),
            (self.assertNotRegexpMatches, ('xxx', 'yyy')),
        )
        for meth, args in old:
            with self.assertWarns(PendingDeprecationWarning):
                meth(*args)

    def testAssertWarnsCallable(self):
        def _runtime_warn():
            warnings.warn("foo", RuntimeWarning)
        # Success when the right warning is triggered, even several times
        self.assertWarns(RuntimeWarning, _runtime_warn)
        self.assertWarns(RuntimeWarning, _runtime_warn)
        # A tuple of warning classes is accepted
        self.assertWarns((DeprecationWarning, RuntimeWarning), _runtime_warn)
        # *args and **kwargs also work
        self.assertWarns(RuntimeWarning,
                         warnings.warn, "foo", category=RuntimeWarning)
        # Failure when no warning is triggered
        with self.assertRaises(self.failureException):
            self.assertWarns(RuntimeWarning, lambda: 0)
        # Failure when another warning is triggered
        with catch_warnings():
            # Force default filter (in case tests are run with -We)
            warnings.simplefilter("default", RuntimeWarning)
            with self.assertRaises(self.failureException):
                self.assertWarns(DeprecationWarning, _runtime_warn)
        # Filters for other warnings are not modified
        with catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            with self.assertRaises(RuntimeWarning):
                self.assertWarns(DeprecationWarning, _runtime_warn)

    def testAssertWarnsContext(self):
        # Believe it or not, it is preferrable to duplicate all tests above,
        # to make sure the __warningregistry__ $@ is circumvented correctly.
        def _runtime_warn():
            warnings.warn("foo", RuntimeWarning)
        _runtime_warn_lineno = inspect.getsourcelines(_runtime_warn)[1]
        with self.assertWarns(RuntimeWarning) as cm:
            _runtime_warn()
        # A tuple of warning classes is accepted
        with self.assertWarns((DeprecationWarning, RuntimeWarning)) as cm:
            _runtime_warn()
        # The context manager exposes various useful attributes
        self.assertIsInstance(cm.warning, RuntimeWarning)
        self.assertEqual(cm.warning.args[0], "foo")
        self.assertIn("_test_unittest2_with.py", cm.filename)
        self.assertEqual(cm.lineno, _runtime_warn_lineno + 1)
        # Same with several warnings
        with self.assertWarns(RuntimeWarning):
            _runtime_warn()
            _runtime_warn()
        with self.assertWarns(RuntimeWarning):
            warnings.warn("foo", category=RuntimeWarning)
        # Failure when no warning is triggered
        with self.assertRaises(self.failureException):
            with self.assertWarns(RuntimeWarning):
                pass
        # Failure when another warning is triggered
        with catch_warnings():
            # Force default filter (in case tests are run with -We)
            warnings.simplefilter("default", RuntimeWarning)
            with self.assertRaises(self.failureException):
                with self.assertWarns(DeprecationWarning):
                    _runtime_warn()
        # Filters for other warnings are not modified
        with catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            with self.assertRaises(RuntimeWarning):
                with self.assertWarns(DeprecationWarning):
                    _runtime_warn()

    def testAssertWarnsRegexCallable(self):
        def _runtime_warn(msg):
            warnings.warn(msg, RuntimeWarning)
        self.assertWarnsRegex(RuntimeWarning, "o+",
                              _runtime_warn, "foox")
        # Failure when no warning is triggered
        with self.assertRaises(self.failureException):
            self.assertWarnsRegex(RuntimeWarning, "o+",
                                  lambda: 0)
        # Failure when another warning is triggered
        with catch_warnings():
            # Force default filter (in case tests are run with -We)
            warnings.simplefilter("default", RuntimeWarning)
            with self.assertRaises(self.failureException):
                self.assertWarnsRegex(DeprecationWarning, "o+",
                                      _runtime_warn, "foox")
        # Failure when message doesn't match
        with self.assertRaises(self.failureException):
            self.assertWarnsRegex(RuntimeWarning, "o+",
                                  _runtime_warn, "barz")
        # A little trickier: we ask RuntimeWarnings to be raised, and then
        # check for some of them.  It is implementation-defined whether
        # non-matching RuntimeWarnings are simply re-raised, or produce a
        # failureException.
        with catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            with self.assertRaises((RuntimeWarning, self.failureException)):
                self.assertWarnsRegex(RuntimeWarning, "o+",
                                      _runtime_warn, "barz")

    def testAssertWarnsRegexContext(self):
        # Same as above, but with assertWarnsRegex as a context manager
        def _runtime_warn(msg):
            warnings.warn(msg, RuntimeWarning)
        _runtime_warn_lineno = inspect.getsourcelines(_runtime_warn)[1]
        with self.assertWarnsRegex(RuntimeWarning, "o+") as cm:
            _runtime_warn("foox")
        self.assertIsInstance(cm.warning, RuntimeWarning)
        self.assertEqual(cm.warning.args[0], "foox")
        self.assertIn("_test_unittest2_with.py", cm.filename)
        self.assertEqual(cm.lineno, _runtime_warn_lineno + 1)
        # Failure when no warning is triggered
        with self.assertRaises(self.failureException):
            with self.assertWarnsRegex(RuntimeWarning, "o+"):
                pass
        # Failure when another warning is triggered
        with catch_warnings():
            # Force default filter (in case tests are run with -We)
            warnings.simplefilter("default", RuntimeWarning)
            with self.assertRaises(self.failureException):
                with self.assertWarnsRegex(DeprecationWarning, "o+"):
                    _runtime_warn("foox")
        # Failure when message doesn't match
        with self.assertRaises(self.failureException):
            with self.assertWarnsRegex(RuntimeWarning, "o+"):
                _runtime_warn("barz")
        # A little trickier: we ask RuntimeWarnings to be raised, and then
        # check for some of them.  It is implementation-defined whether
        # non-matching RuntimeWarnings are simply re-raised, or produce a
        # failureException.
        with catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            with self.assertRaises((RuntimeWarning, self.failureException)):
                with self.assertWarnsRegex(RuntimeWarning, "o+"):
                    _runtime_warn("barz")


if __name__ == '__main__':
    unittest2.main()
