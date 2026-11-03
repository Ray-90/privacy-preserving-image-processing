"""Internal child process: decode, detect, encrypt, delete selected input, exit."""
from contextlib import redirect_stdout
import json
from pathlib import Path
import sys


def handle(request):
    from privacy_guard.isolation import windows_is_elevated
    if windows_is_elevated():
        raise ValueError('Image protection requires a standard Windows user session.')
    if not isinstance(request, dict) or request.get('action') not in ('image-add', 'protect'):
        raise ValueError('Unknown image protection request.')
    source = Path(request['source'])
    password = request['image_password'].encode('utf-8')
    options = {'image_password': password, 'fill': request['fill'],
               'conf': request['conf'], 'device': request['device'], 'imgsz': request['imgsz']}
    if request['action'] == 'image-add':
        from privacy_guard.image_store import ImageStore
        record = ImageStore(request['store'], create=True).add(
            source, request['weights'], request['public_key'],
            name=request['name'], **options)
        result = {'record': record}
    else:
        from privacy_guard.pipeline import protect_with_yolo
        protect_with_yolo(source, request['weights'], request['public_key'],
                          request['output'], **options)
        result = {}
    # Check the selected path after the pipeline verified and removed its source.
    if source.exists() or source.is_symlink():
        raise RuntimeError('Selected original still exists after protection.')
    return {'ok': True, 'selected_source_absent': True, **result}


def main():
    try:
        encoded = sys.stdin.buffer.read(64_001)
        if len(encoded) > 64_000:
            raise ValueError('Protection request is too large.')
        request = json.loads(encoded)
        # Keep protocol stdout separate from dependency progress messages.
        with redirect_stdout(sys.stderr):
            result = handle(request)
    except (Exception, KeyboardInterrupt) as exc:
        result = {'ok': False, 'error': str(exc)}
    sys.stdout.write(json.dumps(result) + '\n')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
