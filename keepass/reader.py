
import io
import struct
import hashlib
import zlib


class HashedBlockReader:
    """
    The decrypted data is written in hashed blocks. Each block consists of 
    a block index (4 bytes), the hash (32 bytes) and the block length (4 bytes),
    followed by the block data. The block index starts counting at 0. The 
    block hash is a SHA-256 hash of the block data. A block has a maximum
    length of HASHED_BLOCK_LENGTH, but can be shorter.
    
    The HashedBlockReader supports reading all data or only specific sections
    using a combination of the seek() and read() functions. The read() function
    only returns actual block data. Likewise the seek() function moves the
    absolute position of read pointer within the data blocks, ignoring the
    length of the block headers.
    
    The reading function raise an IOError if the block hash does not match the 
    block data.
    
    Provide a I/O stream like io.BytesIO containing the hashed block data as 
    the `stream` when creating a HashedBlockReader.
    """
    def __init__(self, stream):
        self.stream = stream
        self.offset = 0

    def seek(self, offset, whence=io.SEEK_SET):
        """
        Change the stream position to the given byte offset.
        
        Only SEEK_SET or 0 is supported.
        """
        if whence == io.SEEK_SET:
            self.offset = offset
        if whence == io.SEEK_CUR:
            pass
        if whence == io.SEEK_END:
            pass
        return self.offset

    def tell(self):
        """Return the current stream position."""
        return self.offset

    def close(self):
        """Flush and close the underlying I/O stream."""
        self.stream.close()

    @property
    def closed(self):
        """True if the underlying I/O stream is closed."""
        return self.stream.closed

    def readall(self):
        """Read and return all the bytes from the stream until EOF."""
        return self.read(-1)

    def read(self, n=-1):
        """read at the most n bytes from the hashed block stream"""
        data = bytearray()
        # always begin at start of input stream
        self.stream.seek(0)

        while True:
            tmp = self.read_block()
            # end of stream
            if tmp is None:
                break
            data.extend(tmp)
            # check if enough data read
            if n > 0 and len(data) >= (self.offset+n):
                break

        # skip data before offset
        data = data[self.offset:]

        # limit to number of requested bytes
        if n > 0:
            data = data[:n]
        
        # move offset
        self.offset += len(data)
        return bytes(data)

    def read_block(self):
        """
        read a single block, check the hash and return the data
        returns none on error or when last block is reached
        this moves the pointer in the input stream forward to the next block
        """
        try:
            block_index = struct.unpack('<I', self.stream.read(4))[0]
            block_hash = self.stream.read(32)
            block_length = struct.unpack('<I', self.stream.read(4))[0]
        # catch end of input stream
        except struct.error:
            return None
        except:
            raise

        # empty/last block reached, empty hash
        if block_length == 0:
            return None

        # read and verify data in this block
        data = self.stream.read(block_length)
        if hashlib.sha256(data).digest() == block_hash:
            return data
        else:
            raise IOError('Block hash error.')

