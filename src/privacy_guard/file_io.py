"""Bounded reads and exclusive output creation."""
import os
from pathlib import Path

def read_bounded(path, limit):
    with Path(path).open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'File exceeds supported size limit: {path}')
    return data


def write_new(path, data):
    """Never overwrite; restrict permissions on systems that support POSIX modes."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
