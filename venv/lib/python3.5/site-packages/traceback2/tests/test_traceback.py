"""Test cases for traceback module"""

from collections import namedtuple
import doctest
import io
from io import StringIO
import platform
import sys
import re

import contextlib2 as contextlib
import fixtures
import linecache2 as linecache
import six
from six import b, text_type, u
try:
    from six import raise_from
except ImportError:
# support raise_from on 3.x:
# submitted to six: https://bitbucket.org/gutworth/six/issue/102/raise-foo-from-bar-is-a-syntax-error-on-27
    if sys.version_info[:2] > (3, 1):
        six.exec_("""def raise_from(value, from_value):
        raise value from from_value
    """)
    else:
        def raise_from(value, from_value):
            raise value
import unittest2 as unittest
import testtools
from testtools.matchers import DocTestMatches, Equals, MatchesAny

import traceback2 as traceback


@contextlib.contextmanager
def captured_output(streamname):
    stream = StringIO()
    patch = fixtures.MonkeyPatch('sys.%s' % streamname, stream)
    with patch:
        yield stream


FNAME = __file__
if FNAME.endswith('.pyc'):
    FNAME = FNAME[:-1]
class FakeLoader:
    def __init__(self, lines):
        self._lines = lines
    def get_source(self, name):
        return self._lines
fake_module = dict(
    __name__='fred',
    __loader__=FakeLoader(''.join(linecache.getlines(FNAME)))
    )


test_code = namedtuple('code', ['co_filename', 'co_name'])
test_frame = namedtuple('frame', ['f_code', 'f_globals', 'f_locals'])
test_tb = namedtuple('tb', ['tb_frame', 'tb_lineno', 'tb_next'])


class SyntaxTracebackCases(testtools.TestCase):
    # For now, a very minimal set of tests.  I want to be sure that
    # formatting of SyntaxErrors works based on changes for 2.1.

    def get_exception_format(self, func, exc):
        try:
            func()
        except exc as value:
            return traceback.format_exception_only(exc, value)
        else:
            raise ValueError("call did not raise exception")

    def syntax_error_with_caret(self):
        compile("def fact(x):\n\treturn x!\n", "?", "exec")

    def syntax_error_with_caret_2(self):
        compile("1 +\n", "?", "exec")

    def syntax_error_bad_indentation(self):
        compile("def spam():\n  print(1)\n print(2)", "?", "exec")

    def syntax_error_with_caret_non_ascii(self):
        compile('Python = "\u1e54\xfd\u0163\u0125\xf2\xf1" +', "?", "exec")

    def syntax_error_bad_indentation2(self):
        compile(" print(2)", "?", "exec")

    def test_caret(self):
        err = self.get_exception_format(self.syntax_error_with_caret,
                                        SyntaxError)
        self.assertEqual(len(err), 4)
        self.assertTrue(err[1].strip() == "return x!")
        self.assertIn("^", err[2]) # third line has caret
        self.assertEqual(err[1].find("!"), err[2].find("^")) # in the right place

        err = self.get_exception_format(self.syntax_error_with_caret_2,
                                        SyntaxError)
        self.assertIn("^", err[2]) # third line has caret
        self.assertEqual(err[2].count('\n'), 1)   # and no additional newline
        self.assertEqual(err[1].find("+"), err[2].find("^"))  # in the right place

        err = self.get_exception_format(self.syntax_error_with_caret_non_ascii,
                                        SyntaxError)
        self.assertIn("^", err[2]) # third line has caret
        self.assertEqual(err[2].count('\n'), 1)   # and no additional newline
        self.assertEqual(err[1].find("+"), err[2].find("^"))  # in the right place

    def test_nocaret(self):
        exc = SyntaxError("error", ("x.py", 23, None, "bad syntax"))
        err = traceback.format_exception_only(SyntaxError, exc)
        self.assertEqual(len(err), 3)
        self.assertEqual(err[1].strip(), "bad syntax")

    def test_bad_indentation(self):
        err = self.get_exception_format(self.syntax_error_bad_indentation,
                                        IndentationError)
        self.assertEqual(len(err), 4)
        self.assertEqual(err[1].strip(), "print(2)")
        self.assertIn("^", err[2])
        self.assertEqual(err[1].find(")"), err[2].find("^"))

        err = self.get_exception_format(self.syntax_error_bad_indentation2,
                                        IndentationError)
        self.assertEqual(len(err), 4)
        self.assertEqual(err[1].strip(), "print(2)")
        self.assertIn("^", err[2])
        # pypy has a different offset for its errors.
        pos_cpython = err[1].find("p")
        pos_pypy = err[1].find(")")
        self.assertThat(
            err[2].find("^"),
            MatchesAny(Equals(pos_cpython), Equals(pos_pypy)))

    def test_base_exception(self):
        # Test that exceptions derived from BaseException are formatted right
        e = KeyboardInterrupt()
        lst = traceback.format_exception_only(e.__class__, e)
        self.assertThat(lst,
            MatchesAny(Equals(['KeyboardInterrupt\n']),
                       Equals(['exceptions.KeyboardInterrupt\n'])))

    def test_format_exception_only_bad__str__(self):
        def qualname(X):
            return getattr(X, '__qualname__', X.__name__)
        class X(Exception):
            def __str__(self):
                1/0
        err = traceback.format_exception_only(X, X())
        self.assertEqual(len(err), 1)
        str_value = '<unprintable %s object>' % X.__name__
        if X.__module__ in ('__main__', 'builtins'):
            str_name = qualname(X)
        else:
            str_name = '.'.join([X.__module__, qualname(X)])
        self.assertEqual(err[0], "%s: %s\n" % (str_name, str_value))

    def test_format_exception_only_undecodable__str__(self):
        # This won't decode via the ascii codec.
        X = Exception(u('\u5341').encode('shift-jis'))
        err = traceback.format_exception_only(type(X), X)
        self.assertEqual(len(err), 1)
        str_value = "b'\\x8f\\\\'"
        self.assertEqual(err[0], "Exception: %s\n" % str_value)

    def test_without_exception(self):
        err = traceback.format_exception_only(None, None)
        self.assertEqual(err, ['None\n'])

    def test_encoded_file(self):
        # Test that tracebacks are correctly printed for encoded source files:
        # - correct line number (Issue2384)
        # - respect file encoding (Issue3975)
        import tempfile, sys, subprocess, os

        # The spawned subprocess has its stdout redirected to a PIPE, and its
        # encoding may be different from the current interpreter, on Windows
        # at least.
        process = subprocess.Popen([sys.executable, "-c",
                                    "import sys; print(sys.stdout.encoding)"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        stdout, stderr = process.communicate()
        output_encoding = text_type(stdout, 'ascii').splitlines()[0]

        def do_test(firstlines, message, charset, lineno, output_encoding):
            # Raise the message in a subprocess, and catch the output
            with fixtures.TempDir() as d:
                TESTFN = d.path + '/fname'
                output = io.open(TESTFN, "w", encoding=charset)
                output.write(u("""{0}if 1:
                    import traceback;
                    raise RuntimeError('{1}')
                    """).format(firstlines, message))
                output.close()
                process = subprocess.Popen([sys.executable, TESTFN],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout, stderr = process.communicate()
                if output_encoding == 'None':
                    output_encoding = charset
                stdout = stdout.decode(output_encoding).splitlines()

            # The source lines are encoded with the 'backslashreplace' handler
            encoded_message = message.encode(output_encoding,
                                             'backslashreplace')
            # and we just decoded them with the output_encoding.
            message_ascii = encoded_message.decode(output_encoding)

            err_line = u("raise RuntimeError('{0}')").format(message_ascii)
            err_msg = u("RuntimeError: {0}").format(message_ascii)

            if platform.python_implementation() == 'PyPy':
                # PyPy includes its own top level app_main.py in the traceback.
                del stdout[1]
            self.assertIn(("line %s" % lineno), stdout[1],
                "Invalid line number: {0!r} instead of {1}".format(
                    stdout[1], lineno))
            self.assertTrue(stdout[2].endswith(err_line),
                "Invalid traceback line: {0!r} instead of {1!r}".format(
                    stdout[2], err_line))
            self.assertTrue(stdout[3] == err_msg,
                "Invalid error message: {0!r} instead of {1!r}".format(
                    stdout[3], err_msg))

        do_test("", "foo", "ascii", 3, output_encoding)
        for charset in ("ascii", "iso-8859-1", "utf-8", "GBK"):
            if charset == "ascii":
                text = u("foo")
            elif charset == "GBK":
                text = u("\u4E02\u5100")
            else:
                text = u("h\xe9 ho")
            do_test("# coding: {0}\n".format(charset),
                    text, charset, 4, output_encoding)
            do_test("#!shebang\n# coding: {0}\n".format(charset),
                    text, charset, 5, output_encoding)
            do_test(" \t\f\n# coding: {0}\n".format(charset),
                    text, charset, 5, output_encoding)
        # Issue #18960: coding spec should has no effect
        # (Fixed in 3.4)
        if sys.version_info[:2] > (3, 3):
            do_test(
                "0\n# coding: GBK\n", u("h\xe9 ho"), 'utf-8', 5,
                output_encoding)


class TracebackFormatTests(unittest.TestCase):

    def some_exception(self):
        raise KeyError('blah')

    def check_traceback_format(self, cleanup_func=None):
        try:
            if issubclass(six.binary_type, six.string_types):
                # Python 2.6 or other platform where the interpreter 
                # is likely going to be spitting out bytes, which will
                # then fail with io.StringIO(), so we skip the cross-
                # checks with the C API there. Note that _testcapi
                # is included in (at least) Ubuntu CPython packages, which
                # makes the import check less effective than desired.
                raise ImportError
            from _testcapi import traceback_print
        except ImportError:
            traceback_print = None
        try:
            self.some_exception()
        except KeyError:
            type_, value, tb = sys.exc_info()
            if cleanup_func is not None:
                # Clear the inner frames, not this one
                cleanup_func(tb.tb_next)
            traceback_fmt = u('Traceback (most recent call last):\n') + \
                            u('').join(traceback.format_tb(tb))
            if traceback_print is not None:
                file_ = StringIO()
                traceback_print(tb, file_)
                python_fmt  = file_.getvalue()
            # Call all _tb and _exc functions
            with captured_output("stderr") as tbstderr:
                traceback.print_tb(tb)
            tbfile = StringIO()
            traceback.print_tb(tb, file=tbfile)
            with captured_output("stderr") as excstderr:
                traceback.print_exc()
            excfmt = traceback.format_exc()
            excfile = StringIO()
            traceback.print_exc(file=excfile)
        else:
            self.fail("unable to create test traceback string")

        # Make sure that Python and the traceback module format the same thing
        if traceback_print is not None:
            self.assertEqual(traceback_fmt, python_fmt)
        # Now verify the _tb func output
        self.assertEqual(tbstderr.getvalue(), tbfile.getvalue())
        # Now verify the _exc func output
        self.assertEqual(excstderr.getvalue(), excfile.getvalue())
        self.assertEqual(excfmt, excfile.getvalue())

        # Make sure that the traceback is properly indented.
        tb_lines = traceback_fmt.splitlines()
        self.assertEqual(len(tb_lines), 5)
        banner = tb_lines[0]
        location, source_line = tb_lines[-2:]
        self.assertTrue(banner.startswith('Traceback'))
        self.assertTrue(location.startswith('  File'))
        self.assertTrue(source_line.startswith('    raise'))

    def test_traceback_format(self):
        self.check_traceback_format()

    def test_traceback_format_with_cleared_frames(self):
        # Check that traceback formatting also works with a clear()ed frame
        def cleanup_tb(tb):
            if getattr(tb.tb_frame, 'clear_frames', None):
                tb.tb_frame.clear()
        self.check_traceback_format(cleanup_tb)

    def test_stack_format(self):
        # Verify _stack functions. Note we have to use _getframe(1) to
        # compare them without this frame appearing in the output
        with captured_output("stderr") as ststderr:
            traceback.print_stack(sys._getframe(1))
        stfile = StringIO()
        traceback.print_stack(sys._getframe(1), file=stfile)
        self.assertEqual(ststderr.getvalue(), stfile.getvalue())

        stfmt = traceback.format_stack(sys._getframe(1))

        self.assertEqual(ststderr.getvalue(), "".join(stfmt))


cause_message = (
    "\nThe above exception was the direct cause "
    "of the following exception:\n\n")

context_message = (
    "\nDuring handling of the above exception, "
    "another exception occurred:\n\n")

boundaries = re.compile(
    '(%s|%s)' % (re.escape(cause_message), re.escape(context_message)))


class BaseExceptionReportingTests:

    def get_exception(self, exception_or_callable, tb=None):
        if isinstance(exception_or_callable, Exception):
            return exception_or_callable, tb
        try:
            exception_or_callable()
        except Exception as e:
            return e, sys.exc_info()[2]

    def zero_div(self):
        1/0 # In zero_div

    def check_zero_div(self, msg):
        lines = msg.splitlines()
        self.assertTrue(lines[-3].startswith('  File'))
        self.assertIn('1/0 # In zero_div', lines[-2])
        self.assertTrue(lines[-1].startswith('ZeroDivisionError'), lines[-1])

    def test_simple(self):
        try:
            1/0 # Marker
        except ZeroDivisionError as _:
            e = _
            tb = sys.exc_info()[2]
        lines = self.get_report(e, tb=tb).splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith('Traceback'))
        self.assertTrue(lines[1].startswith('  File'))
        self.assertIn('1/0 # Marker', lines[2])
        # < 3 show as exceptions.ZeroDivisionError.
        self.assertIn('ZeroDivisionError', lines[3])

    @unittest.skipIf(sys.version_info[:2] < (3, 2), "Only applies to 3.2+")
    def test_cause(self):
        def inner_raise():
            try:
                self.zero_div()
            except ZeroDivisionError as e:
                raise_from(KeyError, e)
        def outer_raise():
            inner_raise() # Marker
        blocks = boundaries.split(self.get_report(outer_raise))
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[1], cause_message)
        self.check_zero_div(blocks[0])
        self.assertIn('inner_raise() # Marker', blocks[2])

    @unittest.skipIf(sys.version_info[:2] < (3, 2), "Only applies to 3.2+")
    def test_context(self):
        def inner_raise():
            try:
                self.zero_div()
            except ZeroDivisionError:
                raise KeyError
        def outer_raise():
            inner_raise() # Marker
        blocks = boundaries.split(self.get_report(outer_raise))
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[1], context_message)
        self.check_zero_div(blocks[0])
        self.assertIn('inner_raise() # Marker', blocks[2])

    @unittest.skipIf(sys.version_info[:2] < (3, 3), "Only applies to 3.3+")
    def test_context_suppression(self):
        try:
            try:
                raise Exception
            except:
                raise_from(ZeroDivisionError, None)
        except ZeroDivisionError as _:
            e = _
            tb = sys.exc_info()[2]
        lines = self.get_report(e, tb)
        self.assertThat(lines, DocTestMatches("""\
Traceback (most recent call last):
  File "...traceback2/tests/test_traceback.py", line ..., in test_context_suppression
    raise_from(ZeroDivisionError, None)
  File "<string>", line 2, in raise_from
ZeroDivisionError
""", doctest.ELLIPSIS))

    @unittest.skipIf(sys.version_info[:2] < (3, 2), "Only applies to 3.2+")
    def test_cause_and_context(self):
        # When both a cause and a context are set, only the cause should be
        # displayed and the context should be muted.
        def inner_raise():
            try:
                self.zero_div()
            except ZeroDivisionError as _e:
                e = _e
            try:
                xyzzy
            except NameError:
                raise_from(KeyError, e)
        def outer_raise():
            inner_raise() # Marker
        blocks = boundaries.split(self.get_report(outer_raise))
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[1], cause_message)
        self.check_zero_div(blocks[0])
        self.assertIn('inner_raise() # Marker', blocks[2])

    @unittest.skipIf(sys.version_info[:2] < (3, 2), "Only applies to 3.2+")
    def test_cause_recursive(self):
        def inner_raise():
            try:
                try:
                    self.zero_div()
                except ZeroDivisionError as e:
                    z = e
                    raise_from(KeyError, e)
            except KeyError as e:
                raise_from(z, e)
        def outer_raise():
            inner_raise() # Marker
        blocks = boundaries.split(self.get_report(outer_raise))
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[1], cause_message)
        # The first block is the KeyError raised from the ZeroDivisionError
        self.assertIn('raise_from(KeyError, e)', blocks[0])
        self.assertNotIn('1/0', blocks[0])
        # The second block (apart from the boundary) is the ZeroDivisionError
        # re-raised from the KeyError
        self.assertIn('inner_raise() # Marker', blocks[2])
        self.check_zero_div(blocks[2])

    def test_syntax_error_offset_at_eol(self):
        # See #10186.
        def e():
            raise SyntaxError('', ('', 0, 5, u('hello')))
        msg = self.get_report(e).splitlines()
        self.assertEqual(msg[-2], "        ^")
        def e():
            exec("x = 5 | 4 |")
        msg = self.get_report(e).splitlines()
        self.assertEqual(msg[-2], '              ^')


class PyExcReportingTests(BaseExceptionReportingTests, testtools.TestCase):
    #
    # This checks reporting through the 'traceback' module, with both
    # format_exception() and print_exception().
    #

    def get_report(self, e, tb=None):
        e, tb = self.get_exception(e, tb)
        s = ''.join(
            traceback.format_exception(type(e), e, tb))
        with captured_output("stderr") as sio:
            traceback.print_exception(type(e), e, tb)
        self.assertEqual(sio.getvalue(), s)
        return s


class MiscTracebackCases(unittest.TestCase):
    #
    # Check non-printing functions in traceback module
    #

    def test_clear(self):
        def outer():
            middle()
        def middle():
            inner()
        def inner():
            i = 1
            1/0

        try:
            outer()
        except:
            type_, value, tb = sys.exc_info()

        # Initial assertion: there's one local in the inner frame.
        inner_frame = tb.tb_next.tb_next.tb_next.tb_frame
        self.assertEqual(len(inner_frame.f_locals), 1)

        # Clear traceback frames
        traceback.clear_frames(tb)

        # Local variable dict should now be empty (on Python 3.4+)
        if sys.version_info[:2] > (3, 3):
            self.assertEqual({}, inner_frame.f_locals)


class TestFrame(unittest.TestCase):

    def test_basics(self):
        linecache.clearcache()
        linecache.lazycache("f", fake_module)
        f = traceback.FrameSummary("f", 1, "dummy")
        self.assertEqual(
            ("f", 1, "dummy", '"""Test cases for traceback module"""'),
            tuple(f))
        self.assertEqual(None, f.locals)

    def test_lazy_lines(self):
        linecache.clearcache()
        f = traceback.FrameSummary("f", 1, "dummy", lookup_line=False)
        self.assertEqual(None, f._line)
        linecache.lazycache("f", fake_module)
        self.assertEqual(
            '"""Test cases for traceback module"""',
            f.line)

    def test_explicit_line(self):
        f = traceback.FrameSummary("f", 1, "dummy", line="line")
        self.assertEqual("line", f.line)


class TestStack(unittest.TestCase):

    def test_walk_stack(self):
        s = list(traceback.walk_stack(None))
        self.assertGreater(len(s), 10)

    def test_walk_tb(self):
        try:
            1/0
        except Exception:
            _, _, tb = sys.exc_info()
        s = list(traceback.walk_tb(tb))
        self.assertEqual(len(s), 1)

    def test_extract_stack(self):
        s = traceback.StackSummary.extract(traceback.walk_stack(None))
        self.assertIsInstance(s, traceback.StackSummary)

    def test_extract_stack_limit(self):
        s = traceback.StackSummary.extract(traceback.walk_stack(None), limit=5)
        self.assertEqual(len(s), 5)

    def test_extract_stack_lookup_lines(self):
        linecache.clearcache()
        linecache.updatecache('/foo.py', fake_module)
        c = test_code('/foo.py', 'method')
        f = test_frame(c, None, None)
        s = traceback.StackSummary.extract(iter([(f, 8)]), lookup_lines=True)
        linecache.clearcache()
        self.assertEqual(s[0].line, "import sys")

    def test_extract_stackup_deferred_lookup_lines(self):
        linecache.clearcache()
        c = test_code('/foo.py', 'method')
        f = test_frame(c, None, None)
        s = traceback.StackSummary.extract(iter([(f, 8)]), lookup_lines=False)
        self.assertEqual({}, linecache.cache)
        linecache.updatecache('/foo.py', fake_module)
        self.assertEqual(s[0].line, "import sys")

    def test_from_list(self):
        s = traceback.StackSummary.from_list([('foo.py', 1, 'fred', 'line')])
        self.assertEqual(
            ['  File "foo.py", line 1, in fred\n    line\n'],
            s.format())

    def test_format_smoke(self):
        # For detailed tests see the format_list tests, which consume the same
        # code.
        s = traceback.StackSummary.from_list([('foo.py', 1, 'fred', 'line')])
        self.assertEqual(
            ['  File "foo.py", line 1, in fred\n    line\n'],
            s.format())

    @unittest.skipIf(sys.getfilesystemencoding()=='ANSI_X3.4-1968',
                     'Requires non-ascii fs encoding')
    def test_format_unicode_filename(self):
        # Filenames in Python2 may be bytestrings that will fail to implicit
        # decode.
        fname = u('\u5341').encode(sys.getfilesystemencoding())
        s = traceback.StackSummary.from_list([(fname, 1, 'fred', 'line')])
        self.assertEqual(
            [u('  File "\u5341", line 1, in fred\n    line\n')],
            s.format())

    def test_format_bad_filename(self):
        # Filenames in Python2 may be bytestrings that will fail to implicit
        # decode.
        # This won't decode via the implicit(ascii) codec or the default
        # fs encoding (unless the encoding is a wildcard encoding).
        fname = b('\x8b')
        s = traceback.StackSummary.from_list([(fname, 1, 'fred', 'line')])
        self.assertEqual(
            ['  File "b\'\\x8b\'", line 1, in fred\n    line\n'],
            s.format())

    def test_locals(self):
        linecache.updatecache('/foo.py', globals())
        c = test_code('/foo.py', 'method')
        f = test_frame(c, globals(), {'something': 1})
        s = traceback.StackSummary.extract(iter([(f, 6)]), capture_locals=True)
        self.assertEqual(s[0].locals, {'something': '1'})

    def test_no_locals(self):
        linecache.updatecache('/foo.py', globals())
        c = test_code('/foo.py', 'method')
        f = test_frame(c, globals(), {'something': 1})
        s = traceback.StackSummary.extract(iter([(f, 6)]))
        self.assertEqual(s[0].locals, None)

    def test_format_locals(self):
        def some_inner(k, v):
            a = 1
            b = 2
            return traceback.StackSummary.extract(
                traceback.walk_stack(None), capture_locals=True, limit=1)
        s = some_inner(3, 4)
        self.assertEqual(
            ['  File "' + FNAME + '", line 651, '
             'in some_inner\n'
             '    traceback.walk_stack(None), capture_locals=True, limit=1)\n'
             '    a = 1\n'
             '    b = 2\n'
             '    k = 3\n'
             '    v = 4\n'
            ], s.format())



class TestTracebackException(unittest.TestCase):

    def test_smoke(self):
        try:
            1/0
        except Exception:
            exc_info = sys.exc_info()
            exc = traceback.TracebackException(*exc_info)
            expected_stack = traceback.StackSummary.extract(
                traceback.walk_tb(exc_info[2]))
        self.assertEqual(None, exc.__cause__)
        self.assertEqual(None, exc.__context__)
        self.assertEqual(False, exc.__suppress_context__)
        self.assertEqual(expected_stack, exc.stack)
        self.assertEqual(exc_info[0], exc.exc_type)
        self.assertEqual(str(exc_info[1]), str(exc))

    @unittest.skipIf(sys.version_info[:2] < (3, 0), "Only applies to 3+")
    def test_from_exception(self):
        # Check all the parameters are accepted.
        def foo():
            1/0
        try:
            foo()
        except Exception as e:
            exc_info = sys.exc_info()
            self.expected_stack = traceback.StackSummary.extract(
                traceback.walk_tb(exc_info[2]), limit=1, lookup_lines=False,
                capture_locals=True)
            self.exc = traceback.TracebackException.from_exception(
                e, limit=1, lookup_lines=False, capture_locals=True)
        expected_stack = self.expected_stack
        exc = self.exc
        self.assertEqual(None, exc.__cause__)
        self.assertEqual(None, exc.__context__)
        self.assertEqual(False, exc.__suppress_context__)
        self.assertEqual(expected_stack, exc.stack)
        self.assertEqual(exc_info[0], exc.exc_type)
        self.assertEqual(str(exc_info[1]), str(exc))

    @unittest.skipIf(sys.version_info[:2] < (3, 2), "Only applies to 3.2+")
    def test_cause(self):
        try:
            try:
                1/0
            finally:
                exc_info_context = sys.exc_info()
                exc_context = traceback.TracebackException(*exc_info_context)
                cause = Exception("cause")
                raise_from(Exception("uh ok"), cause)
        except Exception:
            exc_info = sys.exc_info()
            exc = traceback.TracebackException(*exc_info)
            expected_stack = traceback.StackSummary.extract(
                traceback.walk_tb(exc_info[2]))
        exc_cause = traceback.TracebackException(Exception, cause, None)
        self.assertEqual(exc_cause, exc.__cause__)
        self.assertEqual(exc_context, exc.__context__)
        if hasattr(exc_info[1], '__suppress_context__'):
            self.assertEqual(True, exc.__suppress_context__)
        self.assertEqual(expected_stack, exc.stack)
        self.assertEqual(exc_info[0], exc.exc_type)
        self.assertEqual(str(exc_info[1]), str(exc))

    @unittest.skipIf(sys.version_info[:2] < (3, 2), "Only applies to 3.2+")
    def test_context(self):
        try:
            try:
                1/0
            finally:
                exc_info_context = sys.exc_info()
                exc_context = traceback.TracebackException(*exc_info_context)
                raise Exception("uh oh")
        except Exception:
            exc_info = sys.exc_info()
            exc = traceback.TracebackException(*exc_info)
            expected_stack = traceback.StackSummary.extract(
                traceback.walk_tb(exc_info[2]))
        self.assertEqual(None, exc.__cause__)
        self.assertEqual(exc_context, exc.__context__)
        self.assertEqual(False, exc.__suppress_context__)
        self.assertEqual(expected_stack, exc.stack)
        self.assertEqual(exc_info[0], exc.exc_type)
        self.assertEqual(str(exc_info[1]), str(exc))

    def test_limit(self):
        def recurse(n):
            if n:
                recurse(n-1)
            else:
                1/0
        try:
            recurse(10)
        except Exception:
            exc_info = sys.exc_info()
            exc = traceback.TracebackException(*exc_info, limit=5)
            expected_stack = traceback.StackSummary.extract(
                traceback.walk_tb(exc_info[2]), limit=5)
        self.assertEqual(expected_stack, exc.stack)

    def test_lookup_lines(self):
        linecache.clearcache()
        e = Exception("uh oh")
        c = test_code('/foo.py', 'method')
        f = test_frame(c, None, None)
        tb = test_tb(f, 8, None)
        exc = traceback.TracebackException(Exception, e, tb, lookup_lines=False)
        self.assertEqual({}, linecache.cache)
        linecache.updatecache('/foo.py', fake_module)
        self.assertEqual(exc.stack[0].line, "import sys")

    def test_locals(self):
        linecache.updatecache('/foo.py', fake_module)
        e = Exception("uh oh")
        c = test_code('/foo.py', 'method')
        f = test_frame(c, globals(), {'something': 1, 'other': 'string'})
        tb = test_tb(f, 6, None)
        exc = traceback.TracebackException(
            Exception, e, tb, capture_locals=True)
        self.assertEqual(
            exc.stack[0].locals, {'something': '1', 'other': "'string'"})

    def test_no_locals(self):
        linecache.updatecache('/foo.py', fake_module)
        e = Exception("uh oh")
        c = test_code('/foo.py', 'method')
        f = test_frame(c, fake_module, {'something': 1})
        tb = test_tb(f, 6, None)
        exc = traceback.TracebackException(Exception, e, tb)
        self.assertEqual(exc.stack[0].locals, None)

    def test_syntax_no_extras(self):
        linecache.updatecache('/foo.py', fake_module)
        e = SyntaxError("uh oh")
        c = test_code('/foo.py', 'method')
        f = test_frame(c, fake_module, {'something': 1})
        tb = test_tb(f, 6, None)
        exc = traceback.TracebackException(SyntaxError, e, tb)
        self.assertEqual([
            u('Traceback (most recent call last):\n'),
            u('  File "/foo.py", line 6, in method\n    from io import StringIO\n'),
            u('  File "<string>", line None\n'),
            u('SyntaxError: uh oh\n')],
            list(exc.format()))

    def test_syntax_undecoded_lines(self):
        # If the interpreter returns bytestrings, we have to decode ourselves.
        lines = u("1\n\u5341\n3\n")
        fake_module = dict(
            __name__='fred',
            __loader__=FakeLoader(lines)
            )
        linecache.updatecache('/foo.py', fake_module)
        e = SyntaxError("uh oh")
        e.filename = '/foo.py'
        e.lineno = 2
        e.text = b('something wrong')
        e.offset = 1
        c = test_code('/foo.py', 'method')
        f = test_frame(c, fake_module, {'something': 1})
        tb = test_tb(f, 2, None)
        exc = traceback.TracebackException(SyntaxError, e, tb)
        list(exc.format_exception_only())
        self.assertEqual([
            u('Traceback (most recent call last):\n'),
            u('  File "/foo.py", line 2, in method\n    \u5341\n'),
            u('  File "/foo.py", line 2\n'),
            u('    \u5341\n'),
            u('    ^\n'),
            u('SyntaxError: uh oh\n')],
            list(exc.format()))

    @unittest.skipUnless(sys.version_info[0] < 3, "Applies to 2.x only.")
    @unittest.skipIf(sys.getfilesystemencoding()=='ANSI_X3.4-1968',
                     'Requires non-ascii fs encoding')
    def test_format_unicode_filename(self):
        # Filenames in Python2 may be bytestrings that will fail to implicit
        # decode.
        fname = u('\u5341').encode(sys.getfilesystemencoding())
        lines = u("1\n2\n3\n")
        fake_module = dict(
            __name__='fred',
            __loader__=FakeLoader(lines)
            )
        linecache.updatecache(fname, fake_module)
        e = SyntaxError("uh oh")
        e.filename = fname
        e.lineno = 2
        e.text = b('something wrong')
        e.offset = 1
        c = test_code(fname, 'method')
        f = test_frame(c, fake_module, {'something': 1})
        tb = test_tb(f, 2, None)
        exc = traceback.TracebackException(SyntaxError, e, tb)
        list(exc.format_exception_only())
        self.assertEqual([
            u('Traceback (most recent call last):\n'),
            u('  File "\u5341", line 2, in method\n    2\n'),
            u('  File "\u5341", line 2\n'),
            u('    something wrong\n'),
            u('    ^\n'),
            u('SyntaxError: uh oh\n')],
            list(exc.format()))

    @unittest.skipUnless(sys.version_info[0] < 3, "Applies to 2.x only.")
    def test_format_bad_filename(self):
        # Filenames in Python2 may be bytestrings that will fail to implicit
        # decode.
        # This won't decode via the implicit(ascii) codec or the default
        # fs encoding (unless the encoding is a wildcard encoding).
        fname = b('\x8b')
        lines = u("1\n2\n3\n")
        fake_module = dict(
            __name__='fred',
            __loader__=FakeLoader(lines)
            )
        linecache.updatecache(fname, fake_module)
        e = SyntaxError("uh oh")
        e.filename = fname
        e.lineno = 2
        e.text = b('something wrong')
        e.offset = 1
        c = test_code(fname, 'method')
        f = test_frame(c, fake_module, {'something': 1})
        tb = test_tb(f, 2, None)
        exc = traceback.TracebackException(SyntaxError, e, tb)
        list(exc.format_exception_only())
        self.assertEqual([
            u('Traceback (most recent call last):\n'),
            b('  File "b\'\\x8b\'", line 2, in method\n    2\n').decode(),
            b('  File "b\'\\x8b\'", line 2\n').decode(),
            u('    something wrong\n'),
            u('    ^\n'),
            u('SyntaxError: uh oh\n')],
            list(exc.format()))
