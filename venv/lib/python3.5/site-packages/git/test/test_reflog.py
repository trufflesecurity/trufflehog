import os
import tempfile

from git.objects import IndexObject
from git.refs import (
    RefLogEntry,
    RefLog
)
from git.test.lib import (
    TestBase,
    fixture_path
)
from git.util import Actor, rmtree, hex_to_bin

import os.path as osp


class TestRefLog(TestBase):

    def test_reflogentry(self):
        nullhexsha = IndexObject.NULL_HEX_SHA
        hexsha = 'F' * 40
        actor = Actor('name', 'email')
        msg = "message"

        self.failUnlessRaises(ValueError, RefLogEntry.new, nullhexsha, hexsha, 'noactor', 0, 0, "")
        e = RefLogEntry.new(nullhexsha, hexsha, actor, 0, 1, msg)

        assert e.oldhexsha == nullhexsha
        assert e.newhexsha == hexsha
        assert e.actor == actor
        assert e.time[0] == 0
        assert e.time[1] == 1
        assert e.message == msg

        # check representation (roughly)
        assert repr(e).startswith(nullhexsha)

    def test_base(self):
        rlp_head = fixture_path('reflog_HEAD')
        rlp_master = fixture_path('reflog_master')
        tdir = tempfile.mktemp(suffix="test_reflogs")
        os.mkdir(tdir)

        rlp_master_ro = RefLog.path(self.rorepo.head)
        assert osp.isfile(rlp_master_ro)

        # simple read
        reflog = RefLog.from_file(rlp_master_ro)
        assert reflog._path is not None
        assert isinstance(reflog, RefLog)
        assert len(reflog)

        # iter_entries works with path and with stream
        assert len(list(RefLog.iter_entries(open(rlp_master, 'rb'))))
        assert len(list(RefLog.iter_entries(rlp_master)))

        # raise on invalid revlog
        # TODO: Try multiple corrupted ones !
        pp = 'reflog_invalid_'
        for suffix in ('oldsha', 'newsha', 'email', 'date', 'sep'):
            self.failUnlessRaises(ValueError, RefLog.from_file, fixture_path(pp + suffix))
        # END for each invalid file

        # cannot write an uninitialized reflog
        self.failUnlessRaises(ValueError, RefLog().write)

        # test serialize and deserialize - results must match exactly
        binsha = hex_to_bin(('f' * 40).encode('ascii'))
        msg = "my reflog message"
        cr = self.rorepo.config_reader()
        for rlp in (rlp_head, rlp_master):
            reflog = RefLog.from_file(rlp)
            tfile = osp.join(tdir, osp.basename(rlp))
            reflog.to_file(tfile)
            assert reflog.write() is reflog

            # parsed result must match ...
            treflog = RefLog.from_file(tfile)
            assert treflog == reflog

            # ... as well as each bytes of the written stream
            assert open(tfile).read() == open(rlp).read()

            # append an entry
            entry = RefLog.append_entry(cr, tfile, IndexObject.NULL_BIN_SHA, binsha, msg)
            assert entry.oldhexsha == IndexObject.NULL_HEX_SHA
            assert entry.newhexsha == 'f' * 40
            assert entry.message == msg
            assert RefLog.from_file(tfile)[-1] == entry

            # index entry
            # raises on invalid index
            self.failUnlessRaises(IndexError, RefLog.entry_at, rlp, 10000)

            # indices can be positive ...
            assert isinstance(RefLog.entry_at(rlp, 0), RefLogEntry)
            RefLog.entry_at(rlp, 23)

            # ... and negative
            for idx in (-1, -24):
                RefLog.entry_at(rlp, idx)
            # END for each index to read
        # END for each reflog

        # finally remove our temporary data
        rmtree(tdir)
