"""Performance data streaming performance"""
from __future__ import print_function

import os
import subprocess
import sys
from time import time

from git.test.lib import (
    with_rw_repo
)
from git.util import bin_to_hex
from gitdb import (
    LooseObjectDB,
    IStream
)
from gitdb.test.lib import make_memory_file

import os.path as osp

from .lib import (
    TestBigRepoR
)


class TestObjDBPerformance(TestBigRepoR):

    large_data_size_bytes = 1000 * 1000 * 10        # some MiB should do it
    moderate_data_size_bytes = 1000 * 1000 * 1      # just 1 MiB

    @with_rw_repo('HEAD', bare=True)
    def test_large_data_streaming(self, rwrepo):
        # TODO: This part overlaps with the same file in gitdb.test.performance.test_stream
        # It should be shared if possible
        ldb = LooseObjectDB(osp.join(rwrepo.git_dir, 'objects'))

        for randomize in range(2):
            desc = (randomize and 'random ') or ''
            print("Creating %s data ..." % desc, file=sys.stderr)
            st = time()
            size, stream = make_memory_file(self.large_data_size_bytes, randomize)
            elapsed = time() - st
            print("Done (in %f s)" % elapsed, file=sys.stderr)

            # writing - due to the compression it will seem faster than it is
            st = time()
            binsha = ldb.store(IStream('blob', size, stream)).binsha
            elapsed_add = time() - st
            assert ldb.has_object(binsha)
            db_file = ldb.readable_db_object_path(bin_to_hex(binsha))
            fsize_kib = osp.getsize(db_file) / 1000

            size_kib = size / 1000
            msg = "Added %i KiB (filesize = %i KiB) of %s data to loose odb in %f s ( %f Write KiB / s)"
            msg %= (size_kib, fsize_kib, desc, elapsed_add, size_kib / elapsed_add)
            print(msg, file=sys.stderr)

            # reading all at once
            st = time()
            ostream = ldb.stream(binsha)
            shadata = ostream.read()
            elapsed_readall = time() - st

            stream.seek(0)
            assert shadata == stream.getvalue()
            msg = "Read %i KiB of %s data at once from loose odb in %f s ( %f Read KiB / s)"
            msg %= (size_kib, desc, elapsed_readall, size_kib / elapsed_readall)
            print(msg, file=sys.stderr)

            # reading in chunks of 1 MiB
            cs = 512 * 1000
            chunks = list()
            st = time()
            ostream = ldb.stream(binsha)
            while True:
                data = ostream.read(cs)
                chunks.append(data)
                if len(data) < cs:
                    break
            # END read in chunks
            elapsed_readchunks = time() - st

            stream.seek(0)
            assert b''.join(chunks) == stream.getvalue()

            cs_kib = cs / 1000
            print("Read %i KiB of %s data in %i KiB chunks from loose odb in %f s ( %f Read KiB / s)"
                  % (size_kib, desc, cs_kib, elapsed_readchunks, size_kib / elapsed_readchunks), file=sys.stderr)

            # del db file so git has something to do
            ostream = None
            import gc
            gc.collect()
            os.remove(db_file)

            # VS. CGIT
            ##########
            # CGIT ! Can using the cgit programs be faster ?
            proc = rwrepo.git.hash_object('-w', '--stdin', as_process=True, istream=subprocess.PIPE)

            # write file - pump everything in at once to be a fast as possible
            data = stream.getvalue()    # cache it
            st = time()
            proc.stdin.write(data)
            proc.stdin.close()
            gitsha = proc.stdout.read().strip()
            proc.wait()
            gelapsed_add = time() - st
            del(data)
            assert gitsha == bin_to_hex(binsha)     # we do it the same way, right ?

            #  as its the same sha, we reuse our path
            fsize_kib = osp.getsize(db_file) / 1000
            msg = "Added %i KiB (filesize = %i KiB) of %s data to using git-hash-object in %f s ( %f Write KiB / s)"
            msg %= (size_kib, fsize_kib, desc, gelapsed_add, size_kib / gelapsed_add)
            print(msg, file=sys.stderr)

            # compare ...
            print("Git-Python is %f %% faster than git when adding big %s files"
                  % (100.0 - (elapsed_add / gelapsed_add) * 100, desc), file=sys.stderr)

            # read all
            st = time()
            hexsha, typename, size, data = rwrepo.git.get_object_data(gitsha)  # @UnusedVariable
            gelapsed_readall = time() - st
            print("Read %i KiB of %s data at once using git-cat-file in %f s ( %f Read KiB / s)"
                  % (size_kib, desc, gelapsed_readall, size_kib / gelapsed_readall), file=sys.stderr)

            # compare
            print("Git-Python is %f %% faster than git when reading big %sfiles"
                  % (100.0 - (elapsed_readall / gelapsed_readall) * 100, desc), file=sys.stderr)

            # read chunks
            st = time()
            hexsha, typename, size, stream = rwrepo.git.stream_object_data(gitsha)  # @UnusedVariable
            while True:
                data = stream.read(cs)
                if len(data) < cs:
                    break
            # END read stream
            gelapsed_readchunks = time() - st
            msg = "Read %i KiB of %s data in %i KiB chunks from git-cat-file in %f s ( %f Read KiB / s)"
            msg %= (size_kib, desc, cs_kib, gelapsed_readchunks, size_kib / gelapsed_readchunks)
            print(msg, file=sys.stderr)

            # compare
            print("Git-Python is %f %% faster than git when reading big %s files in chunks"
                  % (100.0 - (elapsed_readchunks / gelapsed_readchunks) * 100, desc), file=sys.stderr)
        # END for each randomization factor
