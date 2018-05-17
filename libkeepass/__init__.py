# -*- coding: utf-8 -*-
import io
from contextlib import contextmanager

# Python 2 BytesIO has no getbuffer method
if not hasattr(io.BytesIO(), 'getbuffer'):
    class BytesIO(io.BytesIO):
        def getbuffer(self):
            return memoryview(self.getvalue())
    io.BytesIO = BytesIO


import libkeepass.common
import libkeepass.kdb3
import libkeepass.kdb4


BASE_SIGNATURE = 0x9AA2D903

_kdb_readers = {
    libkeepass.kdb3.KDB3_SIGNATURE[1]: libkeepass.kdb3.KDB3Reader,
    # 0xB54BFB66: KDB4Reader, # pre2.x may work, untested
    libkeepass.kdb4.KDB4_SIGNATURE[1]: libkeepass.kdb4.KDB4Reader,
}

class UnknownKDBError(IOError): pass


def open(filename, mode='rb+', **credentials):
    """
    A contextmanager to open the KeePass file with `filename`. Use a `password`
    and/or `keyfile` named argument for decryption.
    
    Files are identified using their signature and a reader suitable for 
    the file format is intialized and returned.
    
    Note: `keyfile` is currently not supported for v3 KeePass files.
    """
    kdb = None
    try:
        with io.open(filename, mode) as stream:
            kdb = open_stream(stream, **credentials)
            return kdb
    except:
        if kdb:
            kdb.close()
        raise


def open_stream(stream, **credentials):
    """
    Create a keepass database reader object from a `stream`.
    
    Files are identified using their signature and a reader suitable for 
    the file format is intialized and returned.
    """
    assert isinstance(stream, io.IOBase) or isinstance(stream, file)
    signature = common.read_signature(stream)
    cls = get_kdb_reader(signature)
    kdb = cls(stream, **credentials)
    return kdb


def add_kdb_reader(sub_signature, cls):
    """
    Add or overwrite the class used to process a KeePass file.
    
    KeePass uses two signatures to identify files. The base signature is 
    always `0x9AA2D903`. The second/sub signature varies. For example
    KeePassX uses the v3 sub signature `0xB54BFB65` and KeePass2 the v4 sub 
    signature `0xB54BFB67`.
    
    Use this method to add or replace a class by givin a `sub_signature` as
    integer and a class, which should be a subclass of 
    `keepass.common.KDBFile`.
    """
    _kdb_readers[sub_signature] = cls


def get_kdb_reader(signature):
    """
    Retrieve the class used to process a KeePass file by `signature`, which
    is a a tuple or list with two elements. The first being the base signature 
    and the second the sub signature as integers.
    """
    if signature[0] != BASE_SIGNATURE:
        raise UnknownKDBError('Unknown base signature.')

    if signature[1] not in _kdb_readers:
        raise UnknownKDBError('Unknown sub signature.')

    return _kdb_readers[signature[1]]

