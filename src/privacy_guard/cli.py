# One command interface for the private-document pipeline.
import argparse
import getpass
import json
import struct
import sys
from privacy_guard.crypto.keys import generate_keys
from privacy_guard.crypto.hybrid import encrypt_file, decrypt_file
from privacy_guard.detection.dataset import check_dataset
from privacy_guard.detection.training import train_or_evaluate
from privacy_guard.detection.prediction import predict
from privacy_guard.pipeline import restore
from privacy_guard.benchmark import run_benchmark
from privacy_guard.integrity import compare_integrity
from privacy_guard.forensics import inspect_image
from pathlib import Path
from privacy_guard.file_io import write_new
from privacy_guard.image_store import ImageStore
from privacy_guard.isolation import add_image_isolated, protect_image_isolated, synced_folder_warning


def warn_if_synced(source):
    warning = synced_folder_warning(source)
    if warning:
        print(f'Warning: {warning}', file=sys.stderr)

def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('Must be a positive integer.')
    return number


def confidence(value):
    number = float(value)
    if not 0 < number <= 1:
        raise argparse.ArgumentTypeError('Must be greater than 0 and at most 1.')
    return number

def prompt_password(confirm=False):
    value = getpass.getpass('Private-key password: ')
    if not value:
        raise ValueError('A nonempty password is required.')
    if confirm and value != getpass.getpass('Repeat password: '):
        raise ValueError('Passwords do not match.')
    return value.encode('utf-8')


def prompt_image_password(confirm=False):
    value = getpass.getpass('New image password (8+ characters): ' if confirm else
                            'Image password (press Enter for an older image): ')
    if confirm and len(value) < 8:
        raise ValueError('Image password must contain at least 8 characters.')
    if confirm and value != getpass.getpass('Repeat image password: '):
        raise ValueError('Image passwords do not match.')
    return value.encode('utf-8')
    
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ['train', 'evaluate', 'predict', 'check']:
        p = commands.add_parser(command)
        p.add_argument('--device', default='cpu', help='cpu, 0 for CUDA GPU, or mps')
        p.add_argument('--imgsz', type=positive_int, default=640)
        p.add_argument('--output', default='runs')
        if command in ['train', 'evaluate', 'check']:
            p.add_argument('--dataset', required=True, help='Folder containing data.yaml and train/valid/test')
        if command == 'train':
            p.add_argument('--model', default='yolov8n.pt')
            p.add_argument('--epochs', type=positive_int, default=50)
            p.add_argument('--batch', type=positive_int, default=8)
        elif command in ['evaluate', 'predict']:
            p.add_argument('--weights', required=True, help='Path to trained best.pt')
        if command == 'evaluate':
            p.add_argument('--split', choices=['val', 'test'], default='test')
        if command == 'predict':
            p.add_argument('--source', required=True)
            p.add_argument('--conf', type=confidence, default=0.25)
    keygen = commands.add_parser('keygen', help='Generate a new password-protected RSA key pair')
    keygen.add_argument('--directory', default='keys', help='New directory; must not already exist')
    for name in ['encrypt', 'decrypt']:
        command = commands.add_parser(name)
        command.add_argument('--input', required=True)
        command.add_argument('--output', required=True, help='New file; parent folder must exist')
        command.add_argument('--public-key' if name == 'encrypt' else '--private-key', required=True)
    protect = commands.add_parser('protect')
    protect.add_argument('--input', required=True)
    protect.add_argument('--weights', required=True)
    protect.add_argument('--public-key', required=True)
    protect.add_argument('--output', required=True, help='New directory with existing parent')
    protect.add_argument('--conf', type=confidence, default=0.25)
    protect.add_argument('--device', default='cpu')
    protect.add_argument('--imgsz', type=positive_int, default=640)
    protect.add_argument('--fill', choices=['black', 'texture', 'inpaint'], default='black',
                         help='Preview style; texture copies clean background, inpaint needs OpenCV')
    decrypt = commands.add_parser('restore')
    decrypt.add_argument('--image', required=True)
    decrypt.add_argument('--regions', required=True)
    decrypt.add_argument('--private-key', required=True)
    decrypt.add_argument('--output', required=True)
    decrypt.add_argument('--report', help='Optional new restoration report JSON')
    benchmark = commands.add_parser('benchmark')
    benchmark.add_argument('--original', default='sample.jpg')
    benchmark.add_argument('--protected', default='protected_sample/protected.png')
    benchmark.add_argument('--regions', default='protected_sample/regions.islenc')
    benchmark.add_argument('--restored', default='restored.png')
    benchmark.add_argument('--public-key', default='keys/public.pem')
    benchmark.add_argument('--private-key', default='keys/private.pem')
    benchmark.add_argument('--runs', type=int, default=10)
    verify = commands.add_parser('verify', help='Compare original and restored SHA-256 hashes')
    verify.add_argument('--original', required=True)
    verify.add_argument('--restored', required=True)
    verify.add_argument('--mode', choices=['pixels', 'file'], default='pixels')
    verify.add_argument('--report', help='Optional new JSON report file')
    inspect = commands.add_parser('inspect', help='Inspect image format, metadata presence and SHA-256')
    inspect.add_argument('--input', required=True)
    inspect.add_argument('--report', help='Optional new JSON report file')
    indexed_add = commands.add_parser('image-add', help='Protect one image and give it an ID')
    indexed_add.add_argument('--store', required=True, help='Folder holding ID-named image bundles')
    indexed_add.add_argument('--input', required=True)
    indexed_add.add_argument('--weights', required=True)
    indexed_add.add_argument('--public-key', required=True)
    indexed_add.add_argument('--name', default='Image', help='Non-sensitive label')
    indexed_add.add_argument('--conf', type=confidence, default=0.25)
    indexed_add.add_argument('--device', default='cpu')
    indexed_add.add_argument('--imgsz', type=positive_int, default=640)
    indexed_add.add_argument('--fill', choices=['black', 'texture', 'inpaint'], default='black')
    indexed_list = commands.add_parser('image-list', help='List protected image IDs and labels')
    indexed_list.add_argument('--store', required=True)
    indexed_restore = commands.add_parser('image-restore', help='Restore one protected image by ID')
    indexed_restore.add_argument('--store', required=True)
    indexed_restore.add_argument('--id', required=True)
    indexed_restore.add_argument('--private-key', required=True)
    indexed_restore.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'image-add':
            warn_if_synced(args.input)
            record = add_image_isolated(args.input, args.weights, args.public_key, args.store,
                                        name=args.name, conf=args.conf, device=args.device,
                                        imgsz=args.imgsz, fill=args.fill,
                                        image_password=prompt_image_password(confirm=True))
            print(json.dumps(record, indent=2))
            print('Cleanup: selected original file removed and confirmed absent.', file=sys.stderr)
        elif args.command == 'image-list':
            print(json.dumps(ImageStore(args.store).list(), indent=2))
        elif args.command == 'image-restore':
            report = ImageStore(args.store).restore(args.id, args.output,
                                                    args.private_key, prompt_password(),
                                                    image_password=prompt_image_password())
            print(json.dumps(report, indent=2))
        elif args.command == 'inspect':
            _, report = inspect_image(args.input)
            encoded = json.dumps(report, indent=2)
            if args.report:
                write_new(args.report, (encoded + '\n').encode('utf-8'))
            print(encoded)
        elif args.command == 'verify':
            report = compare_integrity(args.original, args.restored, args.mode)
            encoded = json.dumps(report, indent=2)
            if args.report:
                write_new(args.report, (encoded + '\n').encode('utf-8'))
            print(encoded)
            if not report['match']:
                parser.exit(1)
        elif args.command == 'check':
            print(json.dumps(check_dataset(args.dataset), indent=2))
        elif args.command in ('train', 'evaluate'):
            train_or_evaluate(args)
        elif args.command == 'predict':
            predict(args)
        elif args.command == 'keygen':
            directory = generate_keys(args.directory, prompt_password(confirm=True))
            print(f'Key pair created in {directory}')
        elif args.command == 'encrypt':
            encrypt_file(args.input, args.output, args.public_key)
            print(f'Encrypted file saved: {args.output}')
            print(f'Original file removed: {args.input}')
        elif args.command == 'decrypt':
            decrypt_file(args.input, args.output, args.private_key, prompt_password())
            print(f'Decrypted file saved: {args.output}')
        elif args.command == 'protect':
            warn_if_synced(args.input)
            output = protect_image_isolated(args.input, args.weights, args.public_key, args.output,
                                            conf=args.conf, device=args.device, imgsz=args.imgsz,
                                            fill=args.fill,
                                            image_password=prompt_image_password(confirm=True))
            print(f'Saved {output / "protected.png"} and {output / "regions.islenc"}')
            print(f'Cleanup: selected original file removed and confirmed absent: {args.input}')
        elif args.command == 'restore':
            if args.report and (Path(args.report).exists() or
                                Path(args.report).resolve() == Path(args.output).resolve()):
                raise ValueError('Report must be a new file distinct from the restored image.')
            if args.report and not Path(args.report).parent.is_dir():
                raise ValueError('Report parent directory must exist.')
            report = restore(args.image, args.regions, args.output, args.private_key, prompt_password(),
                             image_password=prompt_image_password())
            if args.report:
                write_new(args.report, (json.dumps(report, indent=2) + '\n').encode('utf-8'))
            print(f'Restored image: {args.output}')
        elif args.command == 'benchmark':
            print(json.dumps(run_benchmark(args, prompt_password(), prompt_image_password()), indent=2))
    except (ValueError, OSError, TypeError, KeyError, RuntimeError, ImportError, EOFError, struct.error) as exc:
        parser.exit(1, f'Error: {exc}\n')
