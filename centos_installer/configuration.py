#!/usr/bin/python3

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional

import pydantic
import requests
import yaml

from .operations import CustomizationOperation


def fail(message: str, exitstatus: int = 1) -> NoReturn:
	print('\n' + message + '\n', file=sys.stderr)
	raise SystemExit(exitstatus)


class ManifestProxyConfig(pydantic.BaseModel):
	http_proxy: Optional[str] = None
	https_proxy: Optional[str] = None
	ftp_proxy: Optional[str] = None
	no_proxy: Optional[str] = None


class Manifest(pydantic.BaseModel):
	vars: Dict[str, str] = {}
	fetch_base: str = ''
	image_url: str
	image_sha256: str
	image_bz2_size: Optional[int] = None
	image_raw_size: Optional[int] = None
	image_root_part_number: int
	proxies: ManifestProxyConfig = ManifestProxyConfig()
	customization_steps: List[CustomizationOperation] = []


class Configuration(object):
	arch: str
	device: Path
	manifest_loc: str
	manifest_hash: Optional[str]
	fetch_base: str
	manifest_vars: Dict[str, str]
	manifest: Manifest

	installroot: Optional[Path] = None
	partitions: List[Path]

	block_size: int = 4096

	def __init__(self):
		self.arch = os.uname().machine
		self.partitions = []

	def parse_args(self) -> None:
		parser = argparse.ArgumentParser()
		parser.add_argument('-d', '--device', type=Path, required=True, help='The raw device to install on')
		parser.add_argument('-m', '--manifest', type=str, required=True, help='The installation manifest file (or url)')
		parser.add_argument(
		    '-M', '--manifest-hash', type=str, default=None, help='A sha256 hash of the manifest to verify'
		)
		parser.add_argument(
		    '--fetch-base',
		    type=str,
		    default='',
		    help='The URL to which all other manifest URLs are relative (overrides manifest fetch_base)'
		)
		parser.add_argument(
		    'manifest_vars',
		    nargs='*',
		    type=str,
		    metavar='VAR=value',
		    help='Manifest variables in the form `VAR=value`'
		)
		ARGS = parser.parse_args()

		self.device = ARGS.device
		self.manifest_loc = ARGS.manifest
		self.manifest_hash = ARGS.manifest_hash
		self.fetch_base = ARGS.fetch_base

		self.manifest_vars: Dict[str, str] = {}
		for arg in ARGS.manifest_vars:
			k, _, v = arg.partition('=')
			self.manifest_vars[k] = v

	def load_manifest(self) -> None:
		# Acquire manifest text.
		if '://' in self.manifest_loc:
			r = requests.get(self.manifest_loc)
			if r.status_code == 200:
				raw_manifest_data = r.content
			else:
				fail('Unable to fetch manifest.')
		elif Path(self.manifest_loc).exists():
			try:
				raw_manifest_data = open(self.manifest_loc, 'rb').read()
			except Exception as e:
				fail('Unable to load manifest: ' + str(e))
		else:
			fail('Unable to locate manifest.')

		# Verify manifest hash.
		if self.manifest_hash is not None:
			manifest_hash = hashlib.new('sha256', raw_manifest_data).hexdigest()
			if manifest_hash != self.manifest_hash:
				fail(
				    f'The manifest does not match the provided checksum:\n'
				    f'Found:    {manifest_hash}\n'
				    f'Expected: {self.manifest}'
				)

		# Load manifest YAML
		try:
			raw_manifest = yaml.safe_load(raw_manifest_data)
		except Exception as e:
			fail('Unable to load manifest: ' + str(e))

		# Verify and import the manifest datastructure.  (Types only: No value verification.)
		if not isinstance(raw_manifest, dict):
			fail('The manifest file must be a yaml mapping object.')
		try:
			self.manifest = Manifest(**raw_manifest)
		except pydantic.ValidationError as e:
			fail(str(e))

		# Ensure all required manifest variables are defined.
		missing_manifest_vars: List[str] = []
		for var, desc in self.manifest.vars.items():
			if var not in self.manifest_vars:
				missing_manifest_vars.append(var)
		if missing_manifest_vars:
			failmsg = 'This manifest requires that the following variables be defined:\n'
			for var, desc in self.manifest.vars.items():
				failmsg += f'  {var}: {desc}\n'
			failmsg += f'The following variables are not defined: {", ".join(missing_manifest_vars)}'
			fail(failmsg)
		else:
			# Store the collected variables into the manifest for later convenience.
			self.manifest.vars = self.manifest_vars

		# Finalize fetch_base
		# Priority:
		#   1. CLI
		#   2. Manifest
		#   3. Manifest Origin.
		fetch_base: str = self.fetch_base
		if not fetch_base:
			fetch_base = self.substitute(self.manifest.fetch_base)
		if not self.fetch_base:
			fetch_base = urllib.parse.urljoin(self.manifest_loc, '.')
		self.fetch_base = self.manifest.fetch_base = fetch_base

	def setup_proxies(self) -> None:
		for env in ('http_proxy', 'https_proxy', 'ftp_proxy', 'no_proxy'):
			val = getattr(self.manifest.proxies, env)
			if val is not None:
				if val:
					os.environ[env] = val
				else:
					os.environ.pop(env, '')

	def update_install_devices(self) -> None:
		self.partitions = []
		try:
			subprocess.run(['hdparm', '-z', self.device], check=True)
		except Exception as e:
			fail('Unable to reread partition table: ' + str(e))
		try:
			proc = subprocess.run(['lsblk', '-p', '--json', str(self.device)], check=True, stdout=subprocess.PIPE)
			partinfo = json.loads(proc.stdout)
		except Exception as e:
			fail(f'Unable to read lsblk information for {str(self.device)!r}: {e!s}')
		try:
			part = partinfo['blockdevices'][0]['name']
			children = [child['name'] for child in partinfo['blockdevices'][0]['children']]
		except Exception as e:
			fail(f'Unable to parse lsblk information for {str(self.device)!r}: {e!s}')
		if self.device.resolve() != Path(part).resolve():
			fail(
			    f'Unable to parse lsblk information for {str(self.device)!r}: Found unexpected device: {str(self.device.resolve())!r} != {str(Path(part).resolve())!r}'
			)
		self.partitions.append(Path(part).resolve())
		for part in children:
			if not Path(part).exists():
				fail(f'Unable to parse lsblk information for {str(self.device)!r}: Found missing partition: {part!r}')
			self.partitions.append(Path(part).resolve())

	def substitution_dict(self) -> Dict[str, Any]:
		# Build the substitution dict.
		data: Dict[str, Any] = {}
		data.update(self.manifest.vars)
		data['manifest'] = self.manifest
		if self.installroot is not None:
			data['installroot'] = self.installroot
		else:
			data.pop('installroot', None)
		data['partitions'] = [str(partition) for partition in self.partitions]
		data['arch'] = self.arch
		return data

	def substitute(self, string: str, user_supplied: bool = True) -> str:
		try:
			return string.format(**self.substitution_dict())
		except Exception as e:
			if user_supplied:
				fail(f'Unable to perform parameter substitution on {string!r}: {e!s}')
			else:
				raise
