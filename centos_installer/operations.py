import os
import shlex
import signal
import subprocess
import time
import urllib.parse
from abc import abstractmethod
from pathlib import Path
from typing import IO, TYPE_CHECKING, Dict, List, Optional, Tuple, Union

import pydantic
import requests
import tqdm
from typing_extensions import Annotated, Literal

from .lib import fail
from .pseudofiles import (IncrementalBZ2Decompressor, IncrementalHasher, IncrementalTQDMProxy)

if TYPE_CHECKING:
	# Pseudo-circular import for type checking/IDEs.
	from configuration import Configuration


class RootedPath(object):
	__slots__ = ['chrooted', 'relpath', '__chrootpath']
	chrooted: bool
	relpath: str
	__chrootpath: Optional[Path]

	def __init__(self, path: Union[Path, str], chroot: Union[None, bool, Path], chroot_path: Optional[Path] = None):
		path = str(path)
		if isinstance(chroot, Path):
			if chroot != chroot_path and chroot_path is not None:
				raise ValueError('`chroot` conflicts with `chroot_path`')
			root = os.path.abspath(chroot)
			path = os.path.abspath(path)
			self.__chrootpath = chroot
			try:
				self.relpath = '/' + str(Path(path).relative_to(root))
				self.chrooted = True
			except ValueError:
				self.relpath = os.path.abspath(path)  # It's not realtive.
				self.chrooted = False
		else:
			self.__chrootpath = chroot_path
			self.relpath = os.path.abspath(path)
			self.chrooted = bool(chroot)

	def __repr__(self) -> str:
		return f'RootedPath({self.relpath!r}, {self.chrooted!r}, chroot_path={self.__chrootpath!r})'

	def __str__(self) -> str:
		return f'{"target" if self.chrooted else "host"}:{self.relpath!s}'

	@property
	def abspath(self) -> Path:
		if self.chrooted:
			if self.__chrootpath is None:
				raise ValueError('The chroot path is not known.')
			return self.__chrootpath / str(self.relpath).lstrip('/')
		else:
			return Path(self.relpath)


class Operation(object):
	@abstractmethod
	def run(self, config: 'Configuration') -> None:
		...


class OperationMount(Operation, pydantic.BaseModel):
	operation: Literal['mount'] = 'mount'

	def run(self, config: 'Configuration') -> None:
		print('Mounting target filesystem.')
		if config.installroot is not None:
			print('Already done...')
			return
		mountpoint = Path('/mnt/installroot').resolve()
		root_part = config.partitions[config.manifest.image_root_part_number]
		try:
			mountpoint.mkdir(0o000, parents=True, exist_ok=False)
			subprocess.run(['mount', str(root_part), str(mountpoint)], check=True)
			subprocess.run(['mount', '-o', 'bind', '/dev', str(mountpoint / 'dev')], check=True)
			subprocess.run(['mount', '-o', 'bind', '/sys', str(mountpoint / 'sys')], check=True)
			subprocess.run(['mount', '-t', 'proc', 'proc', str(mountpoint / 'proc')], check=True)
			subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', str(mountpoint / 'tmp')], check=True)
			subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', str(mountpoint / 'var/tmp')], check=True)
			with open('/etc/resolv.conf', 'rb') as host_resolv:
				with open(mountpoint / 'etc/resolv.conf', 'wb') as target_resolv:
					target_resolv.write(host_resolv.read())
			# Handle all sub-mounts as per the target's fstab.
			subprocess.run(['chroot', str(mountpoint), 'mount', '-a'], check=True)
		except Exception as e:
			fail(
			    f'Unable to mount installroot: {e!s}\n'
			    f'Warning: You may need to manually clean up {str(mountpoint)}.'
			)
		config.installroot = mountpoint


class OperationUnmount(Operation, pydantic.BaseModel):
	operation: Literal['unmount'] = 'unmount'

	def run(self, config: 'Configuration') -> None:
		print('Unmounting target filesystem.')
		if config.installroot is None:
			print('Already done...')
			return
		mountpoint = config.installroot
		# Before we begin, we'll need to ensure things like gpg-agent aren't
		# still running in the chroot, holding the devices open.
		# NOTE: This won't kill host processes with open handles.
		self.kill_chrooted_processes(mountpoint)
		# Now that we've dealt with any leftover processes, we'll attempt the
		# unmount.
		try:
			# First let's clean up our resolv.conf we added.
			try:
				(mountpoint / 'etc/resolv.conf').unlink()
			except FileNotFoundError:
				pass
			# Get a list of all mounts on the system.
			mounts: List[Tuple[str, str]] = [tuple(line.split(' ', 5)) for line in open('/proc/mounts', 'r')]
			# Sort by longest mountpoint first.  This will allow us to do a depth first unmount sequence.
			mounts.sort(key=lambda x: (-len(x[1]), x[1], x[0]))
			for mount in mounts:
				if mount[1] == str(mountpoint) or mount[1].startswith(str(mountpoint) + '/'):
					subprocess.run(['umount', str(mount[1])], check=True)
			# Delete the mountpoint.
			mountpoint.rmdir()
		except Exception as e:
			fail(
			    f'Unable to unmount installroot: {e!s}\n'
			    f'Warning: You may need to manually clean up {str(mountpoint)}.'
			)
		config.installroot = None  # Done.

	def kill_chrooted_processes(self, chroot: Path) -> None:
		def get_elligible_pids(chroot: Path) -> Dict[int, str]:
			chroot = chroot.resolve()
			pids: Dict[int, str] = {}
			for f in os.listdir('/proc'):
				try:
					pid = int(f)
				except ValueError:
					continue  # Not a pid.
				if chroot != Path(f'/proc/{pid!s}/root').resolve():
					continue  # Not in chroot.
				pname = open(f'/proc/{pid}/cmdline', 'rb').read().split(b'\0', 1)[0]
				pids[pid] = pname.decode('utf8', errors='replace')
			return pids

		for _ in range(0, 10):  # Limit attempts.
			pids = get_elligible_pids(chroot)
			if not pids:
				return  # Done.
			for pid, pname in pids.items():
				print(f'Sending SIGTERM to leftover process {pid} ({pname})')
				os.kill(pid, signal.SIGTERM)
			time.sleep(1)
			for pid, pname in pids.items():
				try:
					os.kill(pid, 0)  # Check if it's still alive.
				except ProcessLookupError:
					continue  # Exited as requested.
				print(f'Sending SIGKILL to leftover process {pid} ({pname})')
				os.kill(pid, signal.SIGKILL)


class OperationDownload(Operation, pydantic.BaseModel):
	operation: Literal['download'] = 'download'
	source: str
	sha256: Optional[str]
	filesize: Optional[bytes] = None
	dest: str
	chroot: bool = True
	mode: pydantic.StrictStr

	def run(self, config: 'Configuration') -> None:
		target = RootedPath(config.substitute(self.dest), self.chroot, config.installroot)
		if target.chrooted and config.installroot is None:
			fail('Unable to download file: The installation target is not mounted.')
		print(f'Downloading {target!s}')
		with tqdm.tqdm(total=self.filesize, unit='B', unit_scale=True, delay=3) as progress:
			# Set up the output pipeline
			pipeline: IO[bytes] = open(target.abspath, 'wb', buffering=config.block_size)
			pipeline = hasher = IncrementalHasher('sha256', pipeline)
			pipeline = IncrementalTQDMProxy(pipeline, progress)
			# Fill it with data.
			rsp = requests.get(urllib.parse.urljoin(config.manifest.fetch_base, self.source), stream=True)
			with pipeline:
				for chunk in rsp.iter_content(config.block_size):
					pipeline.write(chunk)
			if self.sha256 and self.sha256 != hasher.hash.hexdigest():
				try:
					target.abspath.unlink()
				except Exception:
					pass
				fail(
				    f'Download failed due to checksum mismatch:\n'
				    f'Source: {self.source}\n'
				    f'Target: {target}\n'
				    f'Expected SHA256: {self.sha256}\n'
				    f'Actual SHA256:   {hasher.hash.hexdigest()}\n'
				    f'Target file deleted.'
				)


class OperationSed(Operation, pydantic.BaseModel):
	operation: Literal['sed'] = 'sed'
	file: str
	chroot: bool = True
	glob: bool = False
	flags: str
	script: str
	interpolate: bool = False

	def run(self, config: 'Configuration') -> None:
		pattern = RootedPath(config.substitute(self.file), self.chroot, config.installroot)
		if pattern.chrooted and config.installroot is None:
			fail('Unable to edit file: The installation target is not mounted.')
		if self.glob:
			files = [RootedPath(file, config.installroot) for file in Path('/').glob(str(pattern.abspath).lstrip('/'))]
		else:
			files = [pattern]
		for target in files:
			print(f'Editing {target!s}')
			if not target.abspath.exists():
				fail(f'Unable to edit file: File not found: {target!s}\n')
			script = config.substitute(self.script) if self.interpolate else self.script
			sedcmd = ['sed', '-i'] + shlex.split(self.flags) + ['-e', script, str(target.abspath)]
			try:
				subprocess.run(sedcmd, check=True)
			except subprocess.CalledProcessError as e:
				fail(f'Unable to edit file {target!s}: The call to sed failed: {e!s}')


class OperationExec(Operation, pydantic.BaseModel):
	operation: Literal['exec'] = 'exec'
	command: Union[str, List[str]]
	chroot: bool
	interpolate: bool = False
	check_result: bool = True

	def run(self, config: 'Configuration') -> None:
		command = type(self.command)(self.command)  # Clone value.
		if self.interpolate:
			if isinstance(command, list):
				command = [config.substitute(arg) for arg in command]
			else:
				command = config.substitute(command)
		print(f'Running in {"target" if self.chroot else "host"}: {command!r}')
		if self.chroot:
			if config.installroot is None:
				fail('Unable to run in target: The installation target is not mounted.')
			if isinstance(command, list):
				command = ['chroot', str(config.installroot)] + command
			else:
				command = f'chroot {shlex.quote(str(config.installroot))} ' + command
		try:
			proc = subprocess.run(command, shell=not isinstance(command, list))
		except Exception as e:
			fail(f'Unable to execute command: {e!s}')
		if self.check_result and proc.returncode != 0:
			fail(f'Command exited with non-zero exit status: {proc.returncode}')


class OperationInteractive(Operation, pydantic.BaseModel):
	operation: Literal['interactive'] = 'interactive'
	chroot: bool
	check_result: bool = False

	def run(self, config: 'Configuration') -> None:
		print(f'Starting an interactive shell in the {"target" if self.chroot else "host"}.')
		if self.chroot:
			if config.installroot is None:
				fail('Unable to run in target: The installation target is not mounted.')
			shellcmd = ['chroot', str(config.installroot), '/bin/bash']
		else:
			shellcmd = ['/bin/bash']
		try:
			proc = subprocess.run(shellcmd)
		except Exception as e:
			fail(f'Unable to launch interactive shell: {e!s}')
		if self.check_result and proc.returncode != 0:
			fail(f'Interactive shell exited with non-zero exit status: {proc.returncode}')


class OperationInstallProxy(Operation, pydantic.BaseModel):
	operation: Literal['install_proxy'] = 'install_proxy'

	def run(self, config: 'Configuration') -> None:
		print(f'Installing persistent proxy configuration in target.')
		if config.installroot is None:
			fail('Unable to install proxy configuration: The installation target is not mounted.')

		# Generate the list of environment variables to be merged.
		merge_env = ''
		for env in ('http_proxy', 'https_proxy', 'ftp_proxy', 'no_proxy'):
			val = getattr(config.manifest.proxies, env)
			if val is not None:
				merge_env += f' {env}="{val}"'

		if not merge_env:
			print('No proxies are configured, so none will be installed.')
			return

		# Do the merging.
		target = RootedPath('/etc/systemd/system.conf', True, config.installroot)
		try:
			fd = open(target.abspath, 'r+', encoding='utf8', errors='surrogateescape')
		except Exception as e:
			fail(f'Unable to configure proxies: Unable to open {target!s}: {e!s}')
		with fd:
			configval = ''
			lines = list(fd)
			for i in range(len(lines)):
				if lines[i].lstrip('# ').startswith('DefaultEnvironment='):
					if not lines[i].lstrip(' ').startswith('#'):
						# We'll want to preserve any existing value, since it wasn't commented.
						if lines[i].strip():
							configval += ' ' + lines[i].partition('=')[2]
						else:
							# In systemd parlance, a blank value will clear any prior accumulation.
							configval = ''
						# And then we're commenting this one out.
						lines[i] = '#' + lines[i]
			if merge_env.strip() not in configval:
				configval += merge_env
				lines.append('DefaultEnvironment=' + configval.strip() + '\n')
				print(lines[-1])
				fd.seek(0, os.SEEK_SET)
				fd.truncate(0)
				fd.write(''.join(lines))


CustomizationOperation = Annotated[Union[OperationMount,
                                         OperationUnmount,
                                         OperationDownload,
                                         OperationSed,
                                         OperationExec,
                                         OperationInteractive,
                                         OperationInstallProxy,
                                         ],
                                   pydantic.Field(discriminator='operation')]


def image_disk(config: 'Configuration') -> None:
	try:
		rawdisk = open(config.device, 'r+b', buffering=config.block_size)
	except Exception as e:
		fail('Unable to open device for imaging: ' + str(e))

	# Set up the output pipeline
	progress_in = tqdm.tqdm(total=564161790, unit='B', unit_scale=True, desc='fetch')
	progress_out = tqdm.tqdm(total=2771567104, unit='B', unit_scale=True, desc='unzip')

	pipeline: IO[bytes] = open(config.device, 'r+b', buffering=config.block_size)
	pipeline = IncrementalTQDMProxy(pipeline, progress_out)
	pipeline = IncrementalBZ2Decompressor(pipeline, block_size=config.block_size)
	pipeline = hasher = IncrementalHasher('sha256', pipeline)
	pipeline = IncrementalTQDMProxy(pipeline, progress_in)

	image_url = urllib.parse.urljoin(config.manifest.fetch_base, config.substitute(config.manifest.image_url))
	rsp = requests.get(image_url, stream=True)
	if rsp.status_code != 200:
		fail(f'Unable to fetch image from {image_url}: HTTP {rsp.status_code}')
	with pipeline:
		for chunk in rsp.iter_content(config.block_size):
			pipeline.write(chunk)

	progress_in.close()
	progress_out.close()

	# Validate checksum
	if config.manifest.image_sha256 != hasher.hash.hexdigest():
		rawdisk.seek(0, os.SEEK_SET)
		rawdisk.write(b'\0' * 1024**2)  # Wipe 1MB to ensure it is not accidentally used.
		fail(
		    'The image applied to the disk had an invalid checksum:\n'
		    'Found:    {shabad}.\n'
		    'Expected: {shagood}.\nErased disk headers.\n'.format(
		        shabad=hasher.hash.hexdigest(), shagood=config.manifest.image_sha256
		    )
		)
