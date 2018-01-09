# test_config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import glob
import io

from git import (
    GitConfigParser
)
from git.compat import string_types
from git.config import cp
from git.test.lib import (
    TestCase,
    fixture_path,
    SkipTest,
)
from git.test.lib import with_rw_directory

import os.path as osp
from git.util import rmfile


_tc_lock_fpaths = osp.join(osp.dirname(__file__), 'fixtures/*.lock')


def _rm_lock_files():
    for lfp in glob.glob(_tc_lock_fpaths):
        rmfile(lfp)


class TestBase(TestCase):
    def setUp(self):
        _rm_lock_files()

    def tearDown(self):
        for lfp in glob.glob(_tc_lock_fpaths):
            if osp.isfile(lfp):
                raise AssertionError('Previous TC left hanging git-lock file: %s', lfp)

    def _to_memcache(self, file_path):
        with open(file_path, "rb") as fp:
            sio = io.BytesIO(fp.read())
        sio.name = file_path
        return sio

    def test_read_write(self):
        # writer must create the exact same file as the one read before
        for filename in ("git_config", "git_config_global"):
            file_obj = self._to_memcache(fixture_path(filename))
            with GitConfigParser(file_obj, read_only=False) as w_config:
                w_config.read()                 # enforce reading
                assert w_config._sections
                w_config.write()                # enforce writing

                # we stripped lines when reading, so the results differ
                assert file_obj.getvalue()
                self.assertEqual(file_obj.getvalue(), self._to_memcache(fixture_path(filename)).getvalue())

                # creating an additional config writer must fail due to exclusive access
                with self.assertRaises(IOError):
                    GitConfigParser(file_obj, read_only=False)

                # should still have a lock and be able to make changes
                assert w_config._lock._has_lock()

                # changes should be written right away
                sname = "my_section"
                oname = "mykey"
                val = "myvalue"
                w_config.add_section(sname)
                assert w_config.has_section(sname)
                w_config.set(sname, oname, val)
                assert w_config.has_option(sname, oname)
                assert w_config.get(sname, oname) == val

                sname_new = "new_section"
                oname_new = "new_key"
                ival = 10
                w_config.set_value(sname_new, oname_new, ival)
                assert w_config.get_value(sname_new, oname_new) == ival

                file_obj.seek(0)
                r_config = GitConfigParser(file_obj, read_only=True)
                assert r_config.has_section(sname)
                assert r_config.has_option(sname, oname)
                assert r_config.get(sname, oname) == val
        # END for each filename

    def test_includes_order(self):
        with GitConfigParser(list(map(fixture_path, ("git_config", "git_config_global")))) as r_config:
            r_config.read()                 # enforce reading
            # Simple inclusions, again checking them taking precedence
            assert r_config.get_value('sec', 'var0') == "value0_included"
            # This one should take the git_config_global value since included
            # values must be considered as soon as they get them
            assert r_config.get_value('diff', 'tool') == "meld"
            try:
                assert r_config.get_value('sec', 'var1') == "value1_main"
            except AssertionError:
                raise SkipTest(
                    'Known failure -- included values are not in effect right away'
                )

    @with_rw_directory
    def test_lock_reentry(self, rw_dir):
        fpl = osp.join(rw_dir, 'l')
        gcp = GitConfigParser(fpl, read_only=False)
        with gcp as cw:
            cw.set_value('include', 'some_value', 'a')
        # entering again locks the file again...
        with gcp as cw:
            cw.set_value('include', 'some_other_value', 'b')
            # ...so creating an additional config writer must fail due to exclusive access
            with self.assertRaises(IOError):
                GitConfigParser(fpl, read_only=False)
        # but work when the lock is removed
        with GitConfigParser(fpl, read_only=False):
            assert osp.exists(fpl)
            # reentering with an existing lock must fail due to exclusive access
            with self.assertRaises(IOError):
                gcp.__enter__()

    def test_multi_line_config(self):
        file_obj = self._to_memcache(fixture_path("git_config_with_comments"))
        with GitConfigParser(file_obj, read_only=False) as config:
            ev = "ruby -e '\n"
            ev += "		system %(git), %(merge-file), %(--marker-size=%L), %(%A), %(%O), %(%B)\n"
            ev += "		b = File.read(%(%A))\n"
            ev += "		b.sub!(/^<+ .*\\nActiveRecord::Schema\\.define.:version => (\\d+). do\\n=+\\nActiveRecord::Schema\\."  # noqa E501
            ev += "define.:version => (\\d+). do\\n>+ .*/) do\n"
            ev += "		  %(ActiveRecord::Schema.define(:version => #{[$1, $2].max}) do)\n"
            ev += "		end\n"
            ev += "		File.open(%(%A), %(w)) {|f| f.write(b)}\n"
            ev += "		exit 1 if b.include?(%(<)*%L)'"
            self.assertEqual(config.get('merge "railsschema"', 'driver'), ev)
            self.assertEqual(config.get('alias', 'lg'),
                             "log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset'"
                             " --abbrev-commit --date=relative")
            self.assertEqual(len(config.sections()), 23)

    def test_base(self):
        path_repo = fixture_path("git_config")
        path_global = fixture_path("git_config_global")
        r_config = GitConfigParser([path_repo, path_global], read_only=True)
        assert r_config.read_only
        num_sections = 0
        num_options = 0

        # test reader methods
        assert r_config._is_initialized is False
        for section in r_config.sections():
            num_sections += 1
            for option in r_config.options(section):
                num_options += 1
                val = r_config.get(section, option)
                val_typed = r_config.get_value(section, option)
                assert isinstance(val_typed, (bool, int, float, ) + string_types)
                assert val
                assert "\n" not in option
                assert "\n" not in val

                # writing must fail
                with self.assertRaises(IOError):
                    r_config.set(section, option, None)
                with self.assertRaises(IOError):
                    r_config.remove_option(section, option)
            # END for each option
            with self.assertRaises(IOError):
                r_config.remove_section(section)
        # END for each section
        assert num_sections and num_options
        assert r_config._is_initialized is True

        # get value which doesnt exist, with default
        default = "my default value"
        assert r_config.get_value("doesnt", "exist", default) == default

        # it raises if there is no default though
        with self.assertRaises(cp.NoSectionError):
            r_config.get_value("doesnt", "exist")

    @with_rw_directory
    def test_config_include(self, rw_dir):
        def write_test_value(cw, value):
            cw.set_value(value, 'value', value)
        # end

        def check_test_value(cr, value):
            assert cr.get_value(value, 'value') == value
        # end

        # PREPARE CONFIG FILE A
        fpa = osp.join(rw_dir, 'a')
        with GitConfigParser(fpa, read_only=False) as cw:
            write_test_value(cw, 'a')

            fpb = osp.join(rw_dir, 'b')
            fpc = osp.join(rw_dir, 'c')
            cw.set_value('include', 'relative_path_b', 'b')
            cw.set_value('include', 'doesntexist', 'foobar')
            cw.set_value('include', 'relative_cycle_a_a', 'a')
            cw.set_value('include', 'absolute_cycle_a_a', fpa)
        assert osp.exists(fpa)

        # PREPARE CONFIG FILE B
        with GitConfigParser(fpb, read_only=False) as cw:
            write_test_value(cw, 'b')
            cw.set_value('include', 'relative_cycle_b_a', 'a')
            cw.set_value('include', 'absolute_cycle_b_a', fpa)
            cw.set_value('include', 'relative_path_c', 'c')
            cw.set_value('include', 'absolute_path_c', fpc)

        # PREPARE CONFIG FILE C
        with GitConfigParser(fpc, read_only=False) as cw:
            write_test_value(cw, 'c')

        with GitConfigParser(fpa, read_only=True) as cr:
            for tv in ('a', 'b', 'c'):
                check_test_value(cr, tv)
            # end for each test to verify
            assert len(cr.items('include')) == 8, "Expected all include sections to be merged"

        # test writable config writers - assure write-back doesn't involve includes
        with GitConfigParser(fpa, read_only=False, merge_includes=True) as cw:
            tv = 'x'
            write_test_value(cw, tv)

        with GitConfigParser(fpa, read_only=True) as cr:
            with self.assertRaises(cp.NoSectionError):
                check_test_value(cr, tv)

        # But can make it skip includes altogether, and thus allow write-backs
        with GitConfigParser(fpa, read_only=False, merge_includes=False) as cw:
            write_test_value(cw, tv)

        with GitConfigParser(fpa, read_only=True) as cr:
            check_test_value(cr, tv)

    def test_rename(self):
        file_obj = self._to_memcache(fixture_path('git_config'))
        with GitConfigParser(file_obj, read_only=False, merge_includes=False) as cw:
            with self.assertRaises(ValueError):
                cw.rename_section("doesntexist", "foo")
            with self.assertRaises(ValueError):
                cw.rename_section("core", "include")

            nn = "bee"
            assert cw.rename_section('core', nn) is cw
            assert not cw.has_section('core')
            assert len(cw.items(nn)) == 4

    def test_complex_aliases(self):
        file_obj = self._to_memcache(fixture_path('.gitconfig'))
        with GitConfigParser(file_obj, read_only=False) as w_config:
            self.assertEqual(w_config.get('alias', 'rbi'), '"!g() { git rebase -i origin/${1:-master} ; } ; g"')
        self.assertEqual(file_obj.getvalue(), self._to_memcache(fixture_path('.gitconfig')).getvalue())

    def test_empty_config_value(self):
        cr = GitConfigParser(fixture_path('git_config_with_empty_value'), read_only=True)

        assert cr.get_value('core', 'filemode'), "Should read keys with values"

        with self.assertRaises(cp.NoOptionError):
            cr.get_value('color', 'ui')
