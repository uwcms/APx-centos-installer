import sys
from typing import NoReturn


def fail(message: str, exitstatus: int = 1) -> NoReturn:
	print('\n' + message + '\n', file=sys.stderr)
	raise SystemExit(exitstatus)
