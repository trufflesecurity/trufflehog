import contextlib
from copy import deepcopy
import difflib
import gc
import pickle
import pprint
import re
import sys
import logging

import six
from six import b, u

import unittest2
import unittest2 as unittest

from unittest2.test.support import (
    OldTestResult, EqualityMixin, HashingMixin, LoggingResult,
    LegacyLoggingResult
)
from .support import captured_stderr


log_foo = logging.getLogger('foo')
log_foobar = logging.getLogger('foo.bar')
log_quux = logging.getLogger('quux')


class MyException(Exception):
    pass


class Test(object):
    "Keep these TestCase classes out of the main namespace"

    class Foo(unittest2.TestCase):
        def runTest(self): pass
        def test1(self): pass

    class Bar(Foo):
        def test2(self): pass

    class LoggingTestCase(unittest2.TestCase):
        """A test case which logs its calls."""

        def __init__(self, events):
            super(Test.LoggingTestCase, self).__init__('test')
            self.events = events

        def setUp(self):
            self.events.append('setUp')

        def test(self):
            self.events.append('test')

        def tearDown(self):
            self.events.append('tearDown')


class Test_TestCase(unittest2.TestCase, EqualityMixin, HashingMixin):

    ### Set up attributes used by inherited tests
    ################################################################

    # Used by HashingMixin.test_hash and EqualityMixin.test_eq
    eq_pairs = [(Test.Foo('test1'), Test.Foo('test1'))]

    # Used by EqualityMixin.test_ne
    ne_pairs = [(Test.Foo('test1'), Test.Foo('runTest')),
                (Test.Foo('test1'), Test.Bar('test1')),
                (Test.Foo('test1'), Test.Bar('test2'))]

    ################################################################
    ### /Set up attributes used by inherited tests


    # "class TestCase([methodName])"
    # ...
    # "Each instance of TestCase will run a single test method: the
    # method named methodName."
    # ...
    # "methodName defaults to "runTest"."
    #
    # Make sure it really is optional, and that it defaults to the proper
    # thing.
    def test_init__no_test_name(self):
        class Test(unittest2.TestCase):
            def runTest(self): raise MyException()
            def test(self): pass

        self.assertEqual(Test().id()[-13:], '.Test.runTest')

    # "class TestCase([methodName])"
    # ...
    # "Each instance of TestCase will run a single test method: the
    # method named methodName."
    def test_init__test_name__valid(self):
        class Test(unittest2.TestCase):
            def runTest(self): raise MyException()
            def test(self): pass

        self.assertEqual(Test('test').id()[-10:], '.Test.test')

    # "class unittest2.TestCase([methodName])"
    # ...
    # "Each instance of TestCase will run a single test method: the
    # method named methodName."
    def test_init__test_name__invalid(self):
        class Test(unittest2.TestCase):
            def runTest(self): raise MyException()
            def test(self): pass

        try:
            Test('testfoo')
        except ValueError:
            pass
        else:
            self.fail("Failed to raise ValueError")

    # "Return the number of tests represented by the this test object. For
    # TestCase instances, this will always be 1"
    def test_countTestCases(self):
        class Foo(unittest2.TestCase):
            def test(self): pass

        self.assertEqual(Foo('test').countTestCases(), 1)

    # "Return the default type of test result object to be used to run this
    # test. For TestCase instances, this will always be
    # unittest2.TestResult;  subclasses of TestCase should
    # override this as necessary."
    def test_defaultTestResult(self):
        class Foo(unittest2.TestCase):
            def runTest(self):
                pass

        result = Foo().defaultTestResult()
        self.assertEqual(type(result), unittest2.TestResult)

    # "When a setUp() method is defined, the test runner will run that method
    # prior to each test. Likewise, if a tearDown() method is defined, the
    # test runner will invoke that method after each test. In the example,
    # setUp() was used to create a fresh sequence for each test."
    #
    # Make sure the proper call order is maintained, even if setUp() raises
    # an exception.
    def test_run_call_order__error_in_setUp(self):
        events = []
        result = LoggingResult(events)

        class Foo(Test.LoggingTestCase):
            def setUp(self):
                super(Foo, self).setUp()
                raise RuntimeError('raised by Foo.setUp')

        Foo(events).run(result)
        expected = ['startTest', 'setUp', 'addError', 'stopTest']
        self.assertEqual(events, expected)

    # "With a temporary result stopTestRun is called when setUp errors.
    def test_run_call_order__error_in_setUp_default_result(self):
        events = []

        class Foo(Test.LoggingTestCase):
            def defaultTestResult(self):
                return LoggingResult(self.events)

            def setUp(self):
                super(Foo, self).setUp()
                raise RuntimeError('raised by Foo.setUp')

        Foo(events).run()
        expected = ['startTestRun', 'startTest', 'setUp', 'addError',
                    'stopTest', 'stopTestRun']
        self.assertEqual(events, expected)

    # "When a setUp() method is defined, the test runner will run that method
    # prior to each test. Likewise, if a tearDown() method is defined, the
    # test runner will invoke that method after each test. In the example,
    # setUp() was used to create a fresh sequence for each test."
    #
    # Make sure the proper call order is maintained, even if the test raises
    # an error (as opposed to a failure).
    def test_run_call_order__error_in_test(self):
        events = []
        result = LoggingResult(events)

        class Foo(Test.LoggingTestCase):
            def test(self):
                super(Foo, self).test()
                raise RuntimeError('raised by Foo.test')

        expected = ['startTest', 'setUp', 'test', 'tearDown', 'addError',
                    'stopTest']
        Foo(events).run(result)
        self.assertEqual(events, expected)

    # "With a default result, an error in the test still results in stopTestRun
    # being called."
    def test_run_call_order__error_in_test_default_result(self):
        events = []

        class Foo(Test.LoggingTestCase):
            def defaultTestResult(self):
                return LoggingResult(self.events)

            def test(self):
                super(Foo, self).test()
                raise RuntimeError('raised by Foo.test')

        expected = ['startTestRun', 'startTest', 'setUp', 'test',
                    'tearDown', 'addError', 'stopTest', 'stopTestRun']
        Foo(events).run()
        self.assertEqual(events, expected)

    # "When a setUp() method is defined, the test runner will run that method
    # prior to each test. Likewise, if a tearDown() method is defined, the
    # test runner will invoke that method after each test. In the example,
    # setUp() was used to create a fresh sequence for each test."
    #
    # Make sure the proper call order is maintained, even if the test signals
    # a failure (as opposed to an error).
    def test_run_call_order__failure_in_test(self):
        events = []
        result = LoggingResult(events)

        class Foo(Test.LoggingTestCase):
            def test(self):
                super(Foo, self).test()
                self.fail('raised by Foo.test')

        expected = ['startTest', 'setUp', 'test', 'tearDown', 'addFailure',
                    'stopTest']
        Foo(events).run(result)
        self.assertEqual(events, expected)

    # "When a test fails with a default result stopTestRun is still called."
    def test_run_call_order__failure_in_test_default_result(self):

        class Foo(Test.LoggingTestCase):
            def defaultTestResult(self):
                return LoggingResult(self.events)
            def test(self):
                super(Foo, self).test()
                self.fail('raised by Foo.test')

        expected = ['startTestRun', 'startTest', 'setUp', 'test',
                    'tearDown', 'addFailure', 'stopTest', 'stopTestRun']
        events = []
        Foo(events).run()
        self.assertEqual(events, expected)

    # "When a setUp() method is defined, the test runner will run that method
    # prior to each test. Likewise, if a tearDown() method is defined, the
    # test runner will invoke that method after each test. In the example,
    # setUp() was used to create a fresh sequence for each test."
    #
    # Make sure the proper call order is maintained, even if tearDown() raises
    # an exception.
    def test_run_call_order__error_in_tearDown(self):
        events = []
        result = LoggingResult(events)

        class Foo(Test.LoggingTestCase):
            def tearDown(self):
                super(Foo, self).tearDown()
                raise RuntimeError('raised by Foo.tearDown')

        Foo(events).run(result)
        expected = ['startTest', 'setUp', 'test', 'tearDown', 'addError',
                    'stopTest']
        self.assertEqual(events, expected)

    # "When tearDown errors with a default result stopTestRun is still called."
    def test_run_call_order__error_in_tearDown_default_result(self):

        class Foo(Test.LoggingTestCase):
            def defaultTestResult(self):
                return LoggingResult(self.events)
            def tearDown(self):
                super(Foo, self).tearDown()
                raise RuntimeError('raised by Foo.tearDown')

        events = []
        Foo(events).run()
        expected = ['startTestRun', 'startTest', 'setUp', 'test', 'tearDown',
                    'addError', 'stopTest', 'stopTestRun']
        self.assertEqual(events, expected)

    # "TestCase.run() still works when the defaultTestResult is a TestResult
    # that does not support startTestRun and stopTestRun.
    def test_run_call_order_default_result(self):

        class Foo(unittest2.TestCase):
            def defaultTestResult(self):
                return OldTestResult()
            def test(self):
                pass

        Foo('test').run()

    def _check_call_order__subtests(self, result, events, expected_events):
        class Foo(Test.LoggingTestCase):
            def test(self):
                super(Foo, self).test()
                for i in [1, 2, 3]:
                    with self.subTest(i=i):
                        if i == 1:
                            self.fail('failure')
                        for j in [2, 3]:
                            with self.subTest(j=j):
                                if i * j == 6:
                                    raise RuntimeError('raised by Foo.test')
                1 / 0

        # Order is the following:
        # i=1 => subtest failure
        # i=2, j=2 => subtest success
        # i=2, j=3 => subtest error
        # i=3, j=2 => subtest error
        # i=3, j=3 => subtest success
        # toplevel => error
        Foo(events).run(result)
        self.assertEqual(events, expected_events)

    def test_run_call_order__subtests(self):
        events = []
        result = LoggingResult(events)
        expected = ['startTest', 'setUp', 'test', 'tearDown',
                    'addSubTestFailure', 'addSubTestSuccess',
                    'addSubTestFailure', 'addSubTestFailure',
                    'addSubTestSuccess', 'addError', 'stopTest']
        self._check_call_order__subtests(result, events, expected)

    def test_run_call_order__subtests_legacy(self):
        # With a legacy result object (without a addSubTest method),
        # text execution stops after the first subtest failure.
        events = []
        result = LegacyLoggingResult(events)
        expected = ['startTest', 'setUp', 'test', 'tearDown',
                    'addFailure', 'stopTest']
        self._check_call_order__subtests(result, events, expected)

    def _check_call_order__subtests_success(self, result, events, expected_events):
        class Foo(Test.LoggingTestCase):
            def test(self):
                super(Foo, self).test()
                for i in [1, 2]:
                    with self.subTest(i=i):
                        for j in [2, 3]:
                            with self.subTest(j=j):
                                pass

        Foo(events).run(result)
        self.assertEqual(events, expected_events)

    def test_run_call_order__subtests_success(self):
        events = []
        result = LoggingResult(events)
        # The 6 subtest successes are individually recorded, in addition
        # to the whole test success.
        expected = (['startTest', 'setUp', 'test', 'tearDown']
                    + 6 * ['addSubTestSuccess']
                    + ['addSuccess', 'stopTest'])
        self._check_call_order__subtests_success(result, events, expected)

    def test_run_call_order__subtests_success_legacy(self):
        # With a legacy result, only the whole test success is recorded.
        events = []
        result = LegacyLoggingResult(events)
        expected = ['startTest', 'setUp', 'test', 'tearDown',
                    'addSuccess', 'stopTest']
        self._check_call_order__subtests_success(result, events, expected)

    def test_run_call_order__subtests_failfast(self):
        events = []
        result = LoggingResult(events)
        result.failfast = True

        class Foo(Test.LoggingTestCase):
            def test(self):
                super(Foo, self).test()
                with self.subTest(i=1):
                    self.fail('failure')
                with self.subTest(i=2):
                    self.fail('failure')
                self.fail('failure')

        expected = ['startTest', 'setUp', 'test', 'tearDown',
                    'addSubTestFailure', 'stopTest']
        Foo(events).run(result)
        self.assertEqual(events, expected)

    def test_subtests_failfast(self):
        # Ensure proper test flow with subtests and failfast (issue #22894)
        events = []

        class Foo(unittest.TestCase):
            def test_a(self):
                with self.subTest():
                    events.append('a1')
                events.append('a2')

            def test_b(self):
                with self.subTest():
                    events.append('b1')
                with self.subTest():
                    self.fail('failure')
                events.append('b2')

            def test_c(self):
                events.append('c')

        result = unittest.TestResult()
        result.failfast = True
        suite = unittest.makeSuite(Foo)
        suite.run(result)

        expected = ['a1', 'a2', 'b1']
        self.assertEqual(events, expected)

    # "This class attribute gives the exception raised by the test() method.
    # If a test framework needs to use a specialized exception, possibly to
    # carry additional information, it must subclass this exception in
    # order to ``play fair'' with the framework.  The initial value of this
    # attribute is AssertionError"
    def test_failureException__default(self):
        class Foo(unittest2.TestCase):
            def test(self):
                pass

        self.assertIs(Foo('test').failureException, AssertionError)

    # "This class attribute gives the exception raised by the test() method.
    # If a test framework needs to use a specialized exception, possibly to
    # carry additional information, it must subclass this exception in
    # order to ``play fair'' with the framework."
    #
    # Make sure TestCase.run() respects the designated failureException
    def test_failureException__subclassing__explicit_raise(self):
        events = []
        result = LoggingResult(events)

        class Foo(unittest2.TestCase):
            def test(self):
                raise RuntimeError()

            failureException = RuntimeError

        self.assertIs(Foo('test').failureException, RuntimeError)


        Foo('test').run(result)
        expected = ['startTest', 'addFailure', 'stopTest']
        self.assertEqual(events, expected)

    # "This class attribute gives the exception raised by the test() method.
    # If a test framework needs to use a specialized exception, possibly to
    # carry additional information, it must subclass this exception in
    # order to ``play fair'' with the framework."
    #
    # Make sure TestCase.run() respects the designated failureException
    def test_failureException__subclassing__implicit_raise(self):
        events = []
        result = LoggingResult(events)

        class Foo(unittest2.TestCase):
            def test(self):
                self.fail("foo")

            failureException = RuntimeError

        self.assertIs(Foo('test').failureException, RuntimeError)


        Foo('test').run(result)
        expected = ['startTest', 'addFailure', 'stopTest']
        self.assertEqual(events, expected)

    # "The default implementation does nothing."
    def test_setUp(self):
        class Foo(unittest2.TestCase):
            def runTest(self):
                pass

        # ... and nothing should happen
        Foo().setUp()

    # "The default implementation does nothing."
    def test_tearDown(self):
        class Foo(unittest2.TestCase):
            def runTest(self):
                pass

        # ... and nothing should happen
        Foo().tearDown()

    # "Return a string identifying the specific test case."
    #
    # Because of the vague nature of the docs, I'm not going to lock this
    # test down too much. Really all that can be asserted is that the id()
    # will be a string (either 8-byte or unicode -- again, because the docs
    # just say "string")
    def test_id(self):
        class Foo(unittest2.TestCase):
            def runTest(self):
                pass

        self.assertIsInstance(Foo().id(), six.string_types)

    # "If result is omitted or None, a temporary result object is created
    # and used, but is not made available to the caller. As TestCase owns the
    # temporary result startTestRun and stopTestRun are called.

    def test_run__uses_defaultTestResult(self):
        events = []

        class Foo(unittest2.TestCase):
            def test(self):
                events.append('test')

            def defaultTestResult(self):
                return LoggingResult(events)

        # Make run() find a result object on its own
        Foo('test').run()

        expected = ['startTestRun', 'startTest', 'test', 'addSuccess',
            'stopTest', 'stopTestRun']
        self.assertEqual(events, expected)

    def testShortDescriptionWithoutDocstring(self):
        self.assertIsNone(self.shortDescription())

    def testShortDescriptionWithOneLineDocstring(self):
        """Tests shortDescription() for a method with a docstring."""
        self.assertEqual(
                self.shortDescription(),
                'Tests shortDescription() for a method with a docstring.')

    def testShortDescriptionWithMultiLineDocstring(self):
        """Tests shortDescription() for a method with a longer docstring.

        This method ensures that only the first line of a docstring is
        returned used in the short description, no matter how long the
        whole thing is.
        """
        self.assertEqual(
                self.shortDescription(),
                 'Tests shortDescription() for a method with a longer '
                 'docstring.')

    def testAddTypeEqualityFunc(self):
        class SadSnake(object):
            """Dummy class for test_addTypeEqualityFunc."""
        s1, s2 = SadSnake(), SadSnake()
        self.assertNotEqual(s1, s2)
        def AllSnakesCreatedEqual(a, b, msg=None):
            return type(a) is type(b) is SadSnake
        self.addTypeEqualityFunc(SadSnake, AllSnakesCreatedEqual)
        self.assertEqual(s1, s2)
        # No this doesn't clean up and remove the SadSnake equality func
        # from this TestCase instance but since its a local nothing else
        # will ever notice that.

    def testAssertIs(self):
        thing = object()
        self.assertIs(thing, thing)
        self.assertRaises(self.failureException, self.assertIs, thing, object())

    def testAssertIsNot(self):
        thing = object()
        self.assertIsNot(thing, object())
        self.assertRaises(self.failureException, self.assertIsNot, thing, thing)

    def testAssertIsInstance(self):
        thing = []
        self.assertIsInstance(thing, list)
        self.assertRaises(self.failureException, self.assertIsInstance,
                          thing, dict)

    def testAssertNotIsInstance(self):
        thing = []
        self.assertNotIsInstance(thing, dict)
        self.assertRaises(self.failureException, self.assertNotIsInstance,
                          thing, list)

    def testAssertIn(self):
        animals = {'monkey': 'banana', 'cow': 'grass', 'seal': 'fish'}

        self.assertIn('a', 'abc')
        self.assertIn(2, [1, 2, 3])
        self.assertIn('monkey', animals)

        self.assertNotIn('d', 'abc')
        self.assertNotIn(0, [1, 2, 3])
        self.assertNotIn('otter', animals)

        self.assertRaises(self.failureException, self.assertIn, 'x', 'abc')
        self.assertRaises(self.failureException, self.assertIn, 4, [1, 2, 3])
        self.assertRaises(self.failureException, self.assertIn, 'elephant',
                          animals)

        self.assertRaises(self.failureException, self.assertNotIn, 'c', 'abc')
        self.assertRaises(self.failureException, self.assertNotIn, 1, [1, 2, 3])
        self.assertRaises(self.failureException, self.assertNotIn, 'cow',
                          animals)

    def testAssertDictContainsSubset(self):
        self.assertDictContainsSubset({}, {})
        self.assertDictContainsSubset({}, {'a': 1})
        self.assertDictContainsSubset({'a': 1}, {'a': 1})
        self.assertDictContainsSubset({'a': 1}, {'a': 1, 'b': 2})
        self.assertDictContainsSubset({'a': 1, 'b': 2}, {'a': 1, 'b': 2})

        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertDictContainsSubset, {'a': 2}, {'a': 1},
                          '.*Mismatched values:.*')

        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertDictContainsSubset, {'c': 1}, {'a': 1},
                          '.*Missing:.*')

        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertDictContainsSubset, {'a': 1, 'c': 1},
                          {'a': 1}, '.*Missing:.*')

        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertDictContainsSubset, {'a': 1, 'c': 1},
                          {'a': 1}, '.*Missing:.*Mismatched values:.*')

        self.assertRaises(self.failureException,
                          self.assertDictContainsSubset, {1: "one"}, {})

    def testAssertEqual(self):
        equal_pairs = [
                ((), ()),
                ({}, {}),
                ([], []),
                (set(), set()),
                (frozenset(), frozenset())]
        for a, b in equal_pairs:
            # This mess of try excepts is to test the assertEqual behavior
            # itself.
            try:
                self.assertEqual(a, b)
            except self.failureException:
                self.fail('assertEqual(%r, %r) failed' % (a, b))
            try:
                self.assertEqual(a, b, msg='foo')
            except self.failureException:
                self.fail('assertEqual(%r, %r) with msg= failed' % (a, b))
            try:
                self.assertEqual(a, b, 'foo')
            except self.failureException:
                self.fail('assertEqual(%r, %r) with third parameter failed' %
                          (a, b))

        unequal_pairs = [
               ((), []),
               ({}, set()),
               (set([4,1]), frozenset([4,2])),
               (frozenset([4,5]), set([2,3])),
               (set([3,4]), set([5,4]))]
        for a, b in unequal_pairs:
            self.assertRaises(self.failureException, self.assertEqual, a, b)
            self.assertRaises(self.failureException, self.assertEqual, a, b,
                              'foo')
            self.assertRaises(self.failureException, self.assertEqual, a, b,
                              msg='foo')

    def testEquality(self):
        self.assertListEqual([], [])
        self.assertTupleEqual((), ())
        self.assertSequenceEqual([], ())

        a = [0, 'a', []]
        b = []
        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertListEqual, a, b)
        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertListEqual, tuple(a), tuple(b))
        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertSequenceEqual, a, tuple(b))

        b.extend(a)
        self.assertListEqual(a, b)
        self.assertTupleEqual(tuple(a), tuple(b))
        self.assertSequenceEqual(a, tuple(b))
        self.assertSequenceEqual(tuple(a), b)

        self.assertRaises(self.failureException, self.assertListEqual,
                          a, tuple(b))
        self.assertRaises(self.failureException, self.assertTupleEqual,
                          tuple(a), b)
        self.assertRaises(self.failureException, self.assertListEqual, None, b)
        self.assertRaises(self.failureException, self.assertTupleEqual, None,
                          tuple(b))
        self.assertRaises(self.failureException, self.assertSequenceEqual,
                          None, tuple(b))
        self.assertRaises(self.failureException, self.assertListEqual, 1, 1)
        self.assertRaises(self.failureException, self.assertTupleEqual, 1, 1)
        self.assertRaises(self.failureException, self.assertSequenceEqual,
                          1, 1)

        self.assertDictEqual({}, {})

        c = { 'x': 1 }
        d = {}
        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertDictEqual, c, d)

        d.update(c)
        self.assertDictEqual(c, d)

        d['x'] = 0
        self.assertRaises(unittest2.TestCase.failureException,
                          self.assertDictEqual, c, d, 'These are unequal')

        self.assertRaises(self.failureException, self.assertDictEqual, None, d)
        self.assertRaises(self.failureException, self.assertDictEqual, [], d)
        self.assertRaises(self.failureException, self.assertDictEqual, 1, 1)

    def testAssertEqual_shorten(self):
        # set a lower threshold value and add a cleanup to restore it
        old_threshold = self._diffThreshold
        self._diffThreshold = 0
        self.addCleanup(lambda: setattr(self, '_diffThreshold', old_threshold))

        s = 'x' * 100
        s1, s2 = s + 'a', s + 'b'
        with self.assertRaises(self.failureException) as cm:
            self.assertEqual(s1, s2)
        c = 'xxxx[35 chars]' + 'x' * 61
        self.assertEqual(str(cm.exception), "'%sa' != '%sb'" % (c, c))
        self.assertEqual(s + 'a', s + 'a')

        p = 'y' * 50
        s1, s2 = s + 'a' + p, s + 'b' + p
        with self.assertRaises(self.failureException) as cm:
            self.assertEqual(s1, s2)
        c = 'xxxx[85 chars]xxxxxxxxxxx'
        self.assertEqual(str(cm.exception), "'%sa%s' != '%sb%s'" % (c, p, c, p))

        p = 'y' * 100
        s1, s2 = s + 'a' + p, s + 'b' + p
        with self.assertRaises(self.failureException) as cm:
            self.assertEqual(s1, s2)
        c = 'xxxx[91 chars]xxxxx'
        d = 'y' * 40 + '[56 chars]yyyy'
        self.assertEqual(str(cm.exception), "'%sa%s' != '%sb%s'" % (c, d, c, d))

    def testAssertItemsEqual(self):
        self.assertItemsEqual([1, 2, 3], [3, 2, 1])
        self.assertItemsEqual(['foo', 'bar', 'baz'], ['bar', 'baz', 'foo'])
        self.assertRaises(self.failureException, self.assertItemsEqual,
                          [10], [10, 11])
        self.assertRaises(self.failureException, self.assertItemsEqual,
                          [10, 11], [10])
        self.assertRaises(self.failureException, self.assertItemsEqual,
                          [10, 11, 10], [10, 11])

        # Test that sequences of unhashable objects can be tested for sameness:
        self.assertItemsEqual([[1, 2], [3, 4]], [[3, 4], [1, 2]])

        self.assertItemsEqual([{'a': 1}, {'b': 2}], [{'b': 2}, {'a': 1}])
        self.assertRaises(self.failureException, self.assertItemsEqual,
                          [[1]], [[2]])

        # Test unsortable objects
        self.assertItemsEqual([2j, None], [None, 2j])
        self.assertRaises(self.failureException, self.assertItemsEqual,
                          [2j, None], [None, 3j])

    def testAssertSetEqual(self):
        set1 = set()
        set2 = set()
        self.assertSetEqual(set1, set2)

        self.assertRaises(self.failureException, self.assertSetEqual, None, set2)
        self.assertRaises(self.failureException, self.assertSetEqual, [], set2)
        self.assertRaises(self.failureException, self.assertSetEqual, set1, None)
        self.assertRaises(self.failureException, self.assertSetEqual, set1, [])

        set1 = set(['a'])
        set2 = set()
        self.assertRaises(self.failureException, self.assertSetEqual, set1, set2)

        set1 = set(['a'])
        set2 = set(['a'])
        self.assertSetEqual(set1, set2)

        set1 = set(['a'])
        set2 = set(['a', 'b'])
        self.assertRaises(self.failureException, self.assertSetEqual, set1, set2)

        set1 = set(['a'])
        set2 = frozenset(['a', 'b'])
        self.assertRaises(self.failureException, self.assertSetEqual, set1, set2)

        set1 = set(['a', 'b'])
        set2 = frozenset(['a', 'b'])
        self.assertSetEqual(set1, set2)

        set1 = set()
        set2 = "foo"
        self.assertRaises(self.failureException, self.assertSetEqual, set1, set2)
        self.assertRaises(self.failureException, self.assertSetEqual, set2, set1)

        # make sure any string formatting is tuple-safe
        set1 = set([(0, 1), (2, 3)])
        set2 = set([(4, 5)])
        self.assertRaises(self.failureException, self.assertSetEqual, set1, set2)

    def testInequality(self):
        # Try ints
        self.assertGreater(2, 1)
        self.assertGreaterEqual(2, 1)
        self.assertGreaterEqual(1, 1)
        self.assertLess(1, 2)
        self.assertLessEqual(1, 2)
        self.assertLessEqual(1, 1)
        self.assertRaises(self.failureException, self.assertGreater, 1, 2)
        self.assertRaises(self.failureException, self.assertGreater, 1, 1)
        self.assertRaises(self.failureException, self.assertGreaterEqual, 1, 2)
        self.assertRaises(self.failureException, self.assertLess, 2, 1)
        self.assertRaises(self.failureException, self.assertLess, 1, 1)
        self.assertRaises(self.failureException, self.assertLessEqual, 2, 1)

        # Try Floats
        self.assertGreater(1.1, 1.0)
        self.assertGreaterEqual(1.1, 1.0)
        self.assertGreaterEqual(1.0, 1.0)
        self.assertLess(1.0, 1.1)
        self.assertLessEqual(1.0, 1.1)
        self.assertLessEqual(1.0, 1.0)
        self.assertRaises(self.failureException, self.assertGreater, 1.0, 1.1)
        self.assertRaises(self.failureException, self.assertGreater, 1.0, 1.0)
        self.assertRaises(self.failureException, self.assertGreaterEqual, 1.0, 1.1)
        self.assertRaises(self.failureException, self.assertLess, 1.1, 1.0)
        self.assertRaises(self.failureException, self.assertLess, 1.0, 1.0)
        self.assertRaises(self.failureException, self.assertLessEqual, 1.1, 1.0)

        # Try Strings
        self.assertGreater('bug', 'ant')
        self.assertGreaterEqual('bug', 'ant')
        self.assertGreaterEqual('ant', 'ant')
        self.assertLess('ant', 'bug')
        self.assertLessEqual('ant', 'bug')
        self.assertLessEqual('ant', 'ant')
        self.assertRaises(self.failureException, self.assertGreater, 'ant', 'bug')
        self.assertRaises(self.failureException, self.assertGreater, 'ant', 'ant')
        self.assertRaises(self.failureException, self.assertGreaterEqual, 'ant', 'bug')
        self.assertRaises(self.failureException, self.assertLess, 'bug', 'ant')
        self.assertRaises(self.failureException, self.assertLess, 'ant', 'ant')
        self.assertRaises(self.failureException, self.assertLessEqual, 'bug', 'ant')

        # Try Unicode
        self.assertGreater(u('bug'), u('ant'))
        self.assertGreaterEqual(u('bug'), u('ant'))
        self.assertGreaterEqual(u('ant'), u('ant'))
        self.assertLess(u('ant'), u('bug'))
        self.assertLessEqual(u('ant'), u('bug'))
        self.assertLessEqual(u('ant'), u('ant'))
        self.assertRaises(self.failureException, self.assertGreater, u('ant'), u('bug'))
        self.assertRaises(self.failureException, self.assertGreater, u('ant'), u('ant'))
        self.assertRaises(self.failureException, self.assertGreaterEqual, u('ant'),
                          u('bug'))
        self.assertRaises(self.failureException, self.assertLess, u('bug'), u('ant'))
        self.assertRaises(self.failureException, self.assertLess, u('ant'), u('ant'))
        self.assertRaises(self.failureException, self.assertLessEqual, u('bug'), u('ant'))

        # Try Mixed String/Unicode
        self.assertGreater('bug', u('ant'))
        self.assertGreater(u('bug'), 'ant')
        self.assertGreaterEqual('bug', u('ant'))
        self.assertGreaterEqual(u('bug'), 'ant')
        self.assertGreaterEqual('ant', u('ant'))
        self.assertGreaterEqual(u('ant'), 'ant')
        self.assertLess('ant', u('bug'))
        self.assertLess(u('ant'), 'bug')
        self.assertLessEqual('ant', u('bug'))
        self.assertLessEqual(u('ant'), 'bug')
        self.assertLessEqual('ant', u('ant'))
        self.assertLessEqual(u('ant'), 'ant')
        self.assertRaises(self.failureException, self.assertGreater, 'ant', u('bug'))
        self.assertRaises(self.failureException, self.assertGreater, u('ant'), 'bug')
        self.assertRaises(self.failureException, self.assertGreater, 'ant', u('ant'))
        self.assertRaises(self.failureException, self.assertGreater, u('ant'), 'ant')
        self.assertRaises(self.failureException, self.assertGreaterEqual, 'ant',
                          u('bug'))
        self.assertRaises(self.failureException, self.assertGreaterEqual, u('ant'),
                          'bug')
        self.assertRaises(self.failureException, self.assertLess, 'bug', u('ant'))
        self.assertRaises(self.failureException, self.assertLess, u('bug'), 'ant')
        self.assertRaises(self.failureException, self.assertLess, 'ant', u('ant'))
        self.assertRaises(self.failureException, self.assertLess, u('ant'), 'ant')
        self.assertRaises(self.failureException, self.assertLessEqual, 'bug', u('ant'))
        self.assertRaises(self.failureException, self.assertLessEqual, u('bug'), 'ant')

    def testAssertMultiLineEqual(self):
        sample_text = u("""\
http://www.python.org/doc/2.3/lib/module-unittest.html
test case
    A test case is the smallest unit of testing. [...]
""")
        revised_sample_text = u("""\
http://www.python.org/doc/2.4.1/lib/module-unittest.html
test case
    A test case is the smallest unit of testing. [...] You may provide your
    own implementation that does not subclass from TestCase, of course.
""")
        sample_text_error = u("""\
- http://www.python.org/doc/2.3/lib/module-unittest.html
?                             ^
+ http://www.python.org/doc/2.4.1/lib/module-unittest.html
?                             ^^^
  test case
-     A test case is the smallest unit of testing. [...]
+     A test case is the smallest unit of testing. [...] You may provide your
?                                                       +++++++++++++++++++++
+     own implementation that does not subclass from TestCase, of course.
""")
        self.maxDiff = None
        # On python 3 we skip bytestrings as they fail the string
        # check. in assertMultiLineEqual
        changers = [lambda x: x]
        if sys.version_info[0] < 3:
            changers.append(lambda x: x.encode('utf8'))
        for type_changer in changers:
            try:
                self.assertMultiLineEqual(type_changer(sample_text),
                                          type_changer(revised_sample_text))
            except self.failureException:
                e = sys.exc_info()[1]
                # need to remove the first line of the error message
                error_str = str(e)
                if not isinstance(error_str, six.text_type):
                    error_str = error_str.decode('utf8')
                error_lines = error_str.split(u('\n'), 1)
                if len(error_lines) > 1:
                    error = error_lines[1]
                else:
                    error = error_lines[0]
                self.assertEqual(sample_text_error, error)

    def testAssertSequenceEqualMaxDiff(self):
        self.assertEqual(self.maxDiff, 80*8)
        seq1 = 'a' + 'x' * 80**2
        seq2 = 'b' + 'x' * 80**2
        diff = '\n'.join(difflib.ndiff(pprint.pformat(seq1).splitlines(),
                                       pprint.pformat(seq2).splitlines()))
        # the +1 is the leading \n added by assertSequenceEqual
        omitted = unittest2.case.DIFF_OMITTED % (len(diff) + 1,)

        self.maxDiff = len(diff)//2
        try:
            self.assertSequenceEqual(seq1, seq2)
        except self.failureException:
            e = sys.exc_info()[1]
            msg = e.args[0]
        else:
            self.fail('assertSequenceEqual did not fail.')
        self.assertLess(len(msg), len(diff))
        self.assertIn(omitted, msg)

        self.maxDiff = len(diff) * 2
        try:
            self.assertSequenceEqual(seq1, seq2)
        except self.failureException:
            e = sys.exc_info()[1]
            msg = e.args[0]
        else:
            self.fail('assertSequenceEqual did not fail.')
        self.assertGreater(len(msg), len(diff))
        self.assertNotIn(omitted, msg)

        self.maxDiff = None
        try:
            self.assertSequenceEqual(seq1, seq2)
        except self.failureException:
            e = sys.exc_info()[1]
            msg = e.args[0]
        else:
            self.fail('assertSequenceEqual did not fail.')
        self.assertGreater(len(msg), len(diff))
        self.assertNotIn(omitted, msg)

    def testTruncateMessage(self):
        self.maxDiff = 1
        message = self._truncateMessage('foo', 'bar')
        omitted = unittest2.case.DIFF_OMITTED % len('bar')
        self.assertEqual(message, 'foo' + omitted)

        self.maxDiff = None
        message = self._truncateMessage('foo', 'bar')
        self.assertEqual(message, 'foobar')

        self.maxDiff = 4
        message = self._truncateMessage('foo', 'bar')
        self.assertEqual(message, 'foobar')

    def testAssertDictEqualTruncates(self):
        test = unittest2.TestCase('assertEqual')
        def truncate(msg, diff):
            return 'foo'
        test._truncateMessage = truncate
        try:
            test.assertDictEqual({}, {1: 0})
        except self.failureException:
            e = sys.exc_info()[1]
            self.assertEqual(str(e), 'foo')
        else:
            self.fail('assertDictEqual did not fail')

    def testAssertMultiLineEqualTruncates(self):
        test = unittest2.TestCase('assertEqual')
        def truncate(msg, diff):
            return 'foo'
        test._truncateMessage = truncate
        try:
            test.assertMultiLineEqual('foo', 'bar')
        except self.failureException:
            e = sys.exc_info()[1]
            self.assertEqual(str(e), 'foo')
        else:
            self.fail('assertMultiLineEqual did not fail')

    def testAssertEqualSingleLine(self):
        sample_text = "laden swallows fly slowly"
        revised_sample_text = "unladen swallows fly quickly"
        sample_text_error = """\
- laden swallows fly slowly
?                    ^^^^
+ unladen swallows fly quickly
? ++                   ^^^^^
"""
        try:
            self.assertEqual(sample_text, revised_sample_text)
        except self.failureException as e:
            error = str(e).split('\n', 1)[1]
            self.assertEqual(sample_text_error, error)

    def testAssertIsNone(self):
        self.assertIsNone(None)
        self.assertRaises(self.failureException, self.assertIsNone, False)
        self.assertIsNotNone('DjZoPloGears on Rails')
        self.assertRaises(self.failureException, self.assertIsNotNone, None)

    def testAssertRegex(self):
        self.assertRegex('asdfabasdf', r'ab+')
        self.assertRaises(self.failureException, self.assertRegex,
                          'saaas', r'aaaa')

    def testAssertRaisesCallable(self):
        class ExceptionMock(Exception):
            pass
        def Stub():
            raise ExceptionMock('We expect')
        self.assertRaises(ExceptionMock, Stub)
        # A tuple of exception classes is accepted
        self.assertRaises((ValueError, ExceptionMock), Stub)
        # *args and **kwargs also work
        self.assertRaises(ValueError, int, '19', base=8)
        # Failure when no exception is raised
        with self.assertRaises(self.failureException):
            self.assertRaises(ExceptionMock, lambda: 0)
        # Failure when the function is None
        with self.assertWarns(DeprecationWarning):
            self.assertRaises(ExceptionMock, None)
        # Failure when another exception is raised
        with self.assertRaises(ExceptionMock):
            self.assertRaises(ValueError, Stub)

    def testAssertRaisesContext(self):
        class ExceptionMock(Exception):
            pass
        def Stub():
            raise ExceptionMock('We expect')
        with self.assertRaises(ExceptionMock):
            Stub()
        # A tuple of exception classes is accepted
        with self.assertRaises((ValueError, ExceptionMock)) as cm:
            Stub()
        # The context manager exposes caught exception
        self.assertIsInstance(cm.exception, ExceptionMock)
        self.assertEqual(cm.exception.args[0], 'We expect')
        # *args and **kwargs also work
        with self.assertRaises(ValueError):
            int('19', base=8)
        # Failure when no exception is raised
        with self.assertRaises(self.failureException):
            with self.assertRaises(ExceptionMock):
                pass
        # Custom message
        with self.assertRaisesRegex(self.failureException, 'foobar'):
            with self.assertRaises(ExceptionMock, msg='foobar'):
                pass
        # Invalid keyword argument
        with self.assertWarnsRegex(DeprecationWarning, 'foobar'):
            with self.assertRaises(AssertionError):
                with self.assertRaises(ExceptionMock, foobar=42):
                    pass
        # Failure when another exception is raised
        with self.assertRaises(ExceptionMock):
            self.assertRaises(ValueError, Stub)

    def testAssertRaisesNoExceptionType(self):
        with self.assertRaises(TypeError):
            self.assertRaises()
        with self.assertRaises(TypeError):
            self.assertRaises(1)
        with self.assertRaises(TypeError):
            self.assertRaises(object)
        with self.assertRaises(TypeError):
            self.assertRaises((ValueError, 1))
        with self.assertRaises(TypeError):
            self.assertRaises((ValueError, object))

    def testAssertRaisesRegex(self):
        class ExceptionMock(Exception):
            pass

        def Stub():
            raise ExceptionMock('We expect')

        self.assertRaisesRegex(ExceptionMock, re.compile('expect$'), Stub)
        self.assertRaisesRegex(ExceptionMock, 'expect$', Stub)
        self.assertRaisesRegex(ExceptionMock, u('expect$'), Stub)
        with self.assertWarns(DeprecationWarning):
            self.assertRaisesRegex(ExceptionMock, 'expect$', None)

    def testAssertNotRaisesRegex(self):
        self.assertRaisesRegex(
                self.failureException, '^Exception not raised by <lambda>$',
                self.assertRaisesRegex, Exception, re.compile('x'),
                lambda: None)
        self.assertRaisesRegex(
                self.failureException, '^Exception not raised by <lambda>$',
                self.assertRaisesRegex, Exception, 'x',
                lambda: None)
        # Custom message
        with self.assertRaisesRegex(self.failureException, 'foobar'):
            with self.assertRaisesRegex(Exception, 'expect', msg='foobar'):
                pass
        # Invalid keyword argument
        with self.assertWarnsRegex(DeprecationWarning, 'foobar'):
            with self.assertRaises(AssertionError):
                with self.assertRaisesRegex(Exception, 'expect', foobar=42):
                    pass

    def testAssertRaisesRegexInvalidRegex(self):
        # Issue 20145.
        class MyExc(Exception):
            pass
        self.assertRaises(TypeError, self.assertRaisesRegex, MyExc, lambda: True)

    def testAssertWarnsRegexInvalidRegex(self):
        # Issue 20145.
        class MyWarn(Warning):
            pass
        self.assertRaises(TypeError, self.assertWarnsRegex, MyWarn, lambda: True)

    def testAssertRaisesRegexInvalidRegex(self):
        # Issue 20145.
        class MyExc(Exception):
            pass
        self.assertRaises(TypeError, self.assertRaisesRegex, MyExc, lambda: True)

    def testAssertWarnsRegexInvalidRegex(self):
        # Issue 20145.
        class MyWarn(Warning):
            pass
        self.assertRaises(TypeError, self.assertWarnsRegex, MyWarn, lambda: True)

    def testAssertRaisesRegexMismatch(self):
        def Stub():
            raise Exception('Unexpected')

        self.assertRaisesRegex(
                self.failureException,
                r'"\^Expected\$" does not match "Unexpected"',
                self.assertRaisesRegex, Exception, '^Expected$',
                Stub)
        self.assertRaisesRegex(
                self.failureException,
                r'"\^Expected\$" does not match "Unexpected"',
                self.assertRaisesRegex, Exception, u('^Expected$'),
                Stub)
        self.assertRaisesRegex(
                self.failureException,
                r'"\^Expected\$" does not match "Unexpected"',
                self.assertRaisesRegex, Exception,
                re.compile('^Expected$'), Stub)

    def testAssertRaisesRegexNoExceptionType(self):
        with self.assertRaises(TypeError):
            self.assertRaisesRegex()
        with self.assertRaises(TypeError):
            self.assertRaisesRegex(ValueError)
        with self.assertRaises(TypeError):
            self.assertRaisesRegex(1, 'expect')
        with self.assertRaises(TypeError):
            self.assertRaisesRegex(object, 'expect')
        with self.assertRaises(TypeError):
            self.assertRaisesRegex((ValueError, 1), 'expect')
        with self.assertRaises(TypeError):
            self.assertRaisesRegex((ValueError, object), 'expect')

    def testAssertWarnsNoExceptionType(self):
        with self.assertRaises(TypeError):
            self.assertWarns()
        with self.assertRaises(TypeError):
            self.assertWarns(1)
        with self.assertRaises(TypeError):
            self.assertWarns(object)
        with self.assertRaises(TypeError):
            self.assertWarns((UserWarning, 1))
        with self.assertRaises(TypeError):
            self.assertWarns((UserWarning, object))
        with self.assertRaises(TypeError):
            self.assertWarns((UserWarning, Exception))

    def testAssertWarnsRegexNoExceptionType(self):
        with self.assertRaises(TypeError):
            self.assertWarnsRegex()
        with self.assertRaises(TypeError):
            self.assertWarnsRegex(UserWarning)
        with self.assertRaises(TypeError):
            self.assertWarnsRegex(1, 'expect')
        with self.assertRaises(TypeError):
            self.assertWarnsRegex(object, 'expect')
        with self.assertRaises(TypeError):
            self.assertWarnsRegex((UserWarning, 1), 'expect')
        with self.assertRaises(TypeError):
            self.assertWarnsRegex((UserWarning, object), 'expect')
        with self.assertRaises(TypeError):
            self.assertWarnsRegex((UserWarning, Exception), 'expect')

    @contextlib.contextmanager
    def assertNoStderr(self):
        with captured_stderr() as buf:
            yield
        self.assertEqual(buf.getvalue(), "")

    def assertLogRecords(self, records, matches):
        self.assertEqual(len(records), len(matches))
        for rec, match in zip(records, matches):
            self.assertIsInstance(rec, logging.LogRecord)
            for k, v in match.items():
                self.assertEqual(getattr(rec, k), v)

    def testAssertLogsDefaults(self):
        # defaults: root logger, level INFO
        with self.assertNoStderr():
            with self.assertLogs() as cm:
                log_foo.info("1")
                log_foobar.debug("2")
            self.assertEqual(cm.output, ["INFO:foo:1"])
            self.assertLogRecords(cm.records, [{'name': 'foo'}])

    def testAssertLogsTwoMatchingMessages(self):
        # Same, but with two matching log messages
        with self.assertNoStderr():
            with self.assertLogs() as cm:
                log_foo.info("1")
                log_foobar.debug("2")
                log_quux.warning("3")
            self.assertEqual(cm.output, ["INFO:foo:1", "WARNING:quux:3"])
            self.assertLogRecords(cm.records,
                                   [{'name': 'foo'}, {'name': 'quux'}])

    def checkAssertLogsPerLevel(self, level):
        # Check level filtering
        with self.assertNoStderr():
            with self.assertLogs(level=level) as cm:
                log_foo.warning("1")
                log_foobar.error("2")
                log_quux.critical("3")
            self.assertEqual(cm.output, ["ERROR:foo.bar:2", "CRITICAL:quux:3"])
            self.assertLogRecords(cm.records,
                                   [{'name': 'foo.bar'}, {'name': 'quux'}])

    def testAssertLogsPerLevel(self):
        self.checkAssertLogsPerLevel(logging.ERROR)
        self.checkAssertLogsPerLevel('ERROR')

    def checkAssertLogsPerLogger(self, logger):
        # Check per-logger filtering
        with self.assertNoStderr():
            with self.assertLogs(level='DEBUG') as outer_cm:
                with self.assertLogs(logger, level='DEBUG') as cm:
                    log_foo.info("1")
                    log_foobar.debug("2")
                    log_quux.warning("3")
                self.assertEqual(cm.output, ["INFO:foo:1", "DEBUG:foo.bar:2"])
                self.assertLogRecords(cm.records,
                                       [{'name': 'foo'}, {'name': 'foo.bar'}])
            # The outer catchall caught the quux log
            self.assertEqual(outer_cm.output, ["WARNING:quux:3"])

    def testAssertLogsPerLogger(self):
        self.checkAssertLogsPerLogger(logging.getLogger('foo'))
        self.checkAssertLogsPerLogger('foo')

    def testAssertLogsFailureNoLogs(self):
        # Failure due to no logs
        with self.assertNoStderr():
            with self.assertRaises(self.failureException):
                with self.assertLogs():
                    pass

    def testAssertLogsFailureLevelTooHigh(self):
        # Failure due to level too high
        with self.assertNoStderr():
            with self.assertRaises(self.failureException):
                with self.assertLogs(level='WARNING'):
                    log_foo.info("1")

    def testAssertLogsFailureMismatchingLogger(self):
        # Failure due to mismatching logger (and the logged message is
        # passed through)
        with self.assertLogs('quux', level='ERROR'):
            with self.assertRaises(self.failureException):
                with self.assertLogs('foo'):
                    log_quux.error("1")


    def testDeepcopy(self):
        # Issue: 5660
        class TestableTest(unittest2.TestCase):
            def testNothing(self):
                pass

        test = TestableTest('testNothing')

        # This shouldn't blow up
        deepcopy(test)


    def testPickle(self):
        # Issue 10326

        # Can't use TestCase classes defined in Test class as
        # pickle does not work with inner classes
        test = unittest2.TestCase('run')
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):

            # blew up prior to fix
            pickled_test = pickle.dumps(test, protocol=protocol)
            unpickled_test = pickle.loads(pickled_test)
            self.assertEqual(test, unpickled_test)

            # exercise the TestCase instance in a way that will invoke
            # the type equality lookup mechanism
            unpickled_test.assertEqual(set(), set())


    def testKeyboardInterrupt(self):
        def _raise(self=None):
            raise KeyboardInterrupt
        def nothing(self):
            pass

        class Test1(unittest2.TestCase):
            test_something = _raise

        class Test2(unittest2.TestCase):
            setUp = _raise
            test_something = nothing

        class Test3(unittest2.TestCase):
            test_something = nothing
            tearDown = _raise

        class Test4(unittest2.TestCase):
            def test_something(self):
                self.addCleanup(_raise)

        for klass in (Test1, Test2, Test3, Test4):
            self.assertRaises(KeyboardInterrupt,
                klass('test_something').run)

    def testSkippingEverywhere(self):
        def _skip(self=None):
            raise unittest2.SkipTest('some reason')
        def nothing(self):
            pass

        class Test1(unittest2.TestCase):
            test_something = _skip

        class Test2(unittest2.TestCase):
            setUp = _skip
            test_something = nothing

        class Test3(unittest2.TestCase):
            test_something = nothing
            tearDown = _skip

        class Test4(unittest2.TestCase):
            def test_something(self):
                self.addCleanup(_skip)

        for klass in (Test1, Test2, Test3, Test4):
            result = unittest2.TestResult()
            klass('test_something').run(result)
            self.assertEqual(len(result.skipped), 1)
            self.assertEqual(result.testsRun, 1)

    def testSystemExit(self):
        def _raise(self=None):
            raise SystemExit
        def nothing(self):
            pass

        class Test1(unittest2.TestCase):
            test_something = _raise

        class Test2(unittest2.TestCase):
            setUp = _raise
            test_something = nothing

        class Test3(unittest2.TestCase):
            test_something = nothing
            tearDown = _raise

        class Test4(unittest2.TestCase):
            def test_something(self):
                self.addCleanup(_raise)

        for klass in (Test1, Test2, Test3, Test4):
            result = unittest2.TestResult()
            klass('test_something').run(result)
            self.assertEqual(len(result.errors), 1)
            self.assertEqual(result.testsRun, 1)

    def test_no_exception_leak(self):
        # Issue #19880: TestCase.run() should not keep a reference
        # to the exception
        class MyException(Exception):
            ninstance = 0

            def __init__(self):
                MyException.ninstance += 1
                Exception.__init__(self)

            def __del__(self):
                MyException.ninstance -= 1

        class TestCase(unittest.TestCase):
            def test1(self):
                raise MyException()

            @unittest.expectedFailure
            def test2(self):
                raise MyException()

        for method_name in ('test1', 'test2'):
            testcase = TestCase(method_name)
            testcase.run()
            gc.collect()
            self.assertEqual(MyException.ninstance, 0)


if __name__ == "__main__":
    unittest2.main()
