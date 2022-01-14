from .configuration import Configuration
from .operations import OperationInteractive, OperationUnmount, image_disk


def main():
	## Stage 0: Parse arguments & Load manifest

	config = Configuration()
	config.parse_args()
	config.load_manifest()
	config.setup_proxies()

	## Stage 1: Image the disk

	image_disk(config)
	config.update_install_devices()

	## Stage 2: Perform customization actions.

	try:
		for step in config.manifest.customization_steps:
			step.run(config)
	finally:
		if config.installroot is not None:
			print('\n'
			      'Caught exit with the target still mounted.\n'
			      'Attempting to unmount the target.\n'
			      '')
			try:
				OperationUnmount().run(config)
				print('Successfully unmounted the target.')
			except Exception:
				pass
			except SystemExit:
				pass
