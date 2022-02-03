import bz2
import hashlib
import io
from typing import IO, NoReturn

import tqdm


class FileProxyBase(IO[bytes], io.RawIOBase):
	targetfd: IO[bytes]

	def flush(self) -> None:
		self.targetfd.flush()

	def close(self) -> None:
		self.targetfd.close()

	def __enter__(self):
		return super().__enter__()

	def __exit__(self, exc_type, exc_value, traceback) -> None:
		# io.RawIOBase.__exit__ is not doing this job for us, so we have to
		# implement our own context manager.  We'll still call super() for good
		# form.
		super().__exit__(exc_type, exc_value, traceback)
		# But to actually get the job done...
		self.close()


class IncrementalBZ2Decompressor(FileProxyBase):
	def __init__(self, targetfd: IO[bytes], block_size: int = 64 * 1024):
		self.targetfd = targetfd
		self.block_size = block_size
		self._decompressor = bz2.BZ2Decompressor()
		self.decompressed_bytes = 0

	def read(self, *args, **kwargs) -> NoReturn:
		raise io.UnsupportedOperation('read() is not supported')

	def write(self, data: bytes) -> int:
		if self._decompressor.eof:
			raise ValueError('Additional data supplied beyond the end of the BZ2 stream.')
		ret = len(data)
		while data or not (self._decompressor.needs_input or self._decompressor.eof):
			data = self._decompressor.decompress(data, max_length=self.block_size)
			self.targetfd.write(data)
			self.decompressed_bytes += len(data)
			data = b''  # Further decompression passes, if any, will not require more data.
		return ret


class IncrementalHasher(FileProxyBase):
	def __init__(self, hash: str, targetfd: IO[bytes]):
		self.targetfd = targetfd
		self.hash = hashlib.new(hash)

	def read(self, length: int) -> bytes:
		data = self.targetfd.read(length)
		self.hash.update(data)
		return data

	def write(self, data: bytes) -> int:
		self.hash.update(data)
		return self.targetfd.write(data)


class IncrementalTQDMProxy(FileProxyBase):
	def __init__(self, targetfd: IO[bytes], tqdm: tqdm.tqdm):
		self.targetfd = targetfd
		self.tqdm = tqdm

	def read(self, length: int) -> bytes:
		data = self.targetfd.read(length)
		self.tqdm.update(len(data))
		return data

	def write(self, data: bytes) -> int:
		self.tqdm.update(len(data))
		return self.targetfd.write(data)
