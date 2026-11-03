"""Small terminal menu for the single-image Privacy Guard workflow.

Run from the project directory with: python app.py
"""
from getpass import getpass
from pathlib import Path

from privacy_guard.crypto.keys import generate_keys
from privacy_guard.image_store import ImageStore
from privacy_guard.isolation import add_image_isolated, synced_folder_warning


STORE = Path('protected_images')
PUBLIC_KEY = Path('keys/public.pem')
PRIVATE_KEY = Path('keys/private.pem')
# Set your trained model path here once. Use Path(r'C:\...\best.pt') for an absolute Windows path.
MODEL_WEIGHTS = Path('runs/train-2/weights/best.pt')


def path_input(prompt):
    return input(prompt).strip().strip('"')


def entries():
    if not STORE.is_dir():
        return []
    return ImageStore(STORE).list()


def show_entries():
    records = entries()
    if not records:
        print('No protected images yet. Choose 1 to add one.')
    for number, record in enumerate(records, 1):
        print(f"{number}. {record['name']}  ({record['id']})")
    return records


def create_keys():
    if Path('keys').exists():
        print('The keys folder already exists. Your existing key pair was not changed.')
        return
    first = getpass('Choose a private-key password: ')
    if not first or first != getpass('Repeat password: '):
        raise ValueError('Passwords must be nonempty and match.')
    generate_keys('keys', first.encode('utf-8'))
    print('Created keys/public.pem and keys/private.pem. Keep a secure backup of the private key.')


def add_image():
    if not PUBLIC_KEY.is_file():
        print('No keys/public.pem found. Choose 4 to create a key pair first.')
        return
    source = path_input('Image path (you can paste it): ')
    if not source:
        return
    if not MODEL_WEIGHTS.is_file():
        print(f'Trained model file not found: {MODEL_WEIGHTS}. Set MODEL_WEIGHTS in app.py once.')
        return
    warning = synced_folder_warning(source)
    if warning:
        print(warning)
        if input('Continue with this image [y/N]? ').strip().lower() not in ('y', 'yes'):
            return
    label = input('Short label [Image]: ').strip() or 'Image'
    fill_choice = input('Preview fill [1 black, 2 texture, 3 inpaint] (default 1): ').strip()
    if fill_choice not in ('', '1', '2', '3'):
        raise ValueError('Choose 1, 2 or 3 for preview fill.')
    fill = {'': 'black', '1': 'black', '2': 'texture', '3': 'inpaint'}[fill_choice]
    image_password = getpass('Create a new password for this image (8+ characters): ')
    if len(image_password) < 8:
        raise ValueError('Image password must contain at least 8 characters.')
    if image_password != getpass('Repeat image password: '):
        raise ValueError('Image passwords do not match.')
    record = add_image_isolated(source, MODEL_WEIGHTS, PUBLIC_KEY, STORE,
                                name=label, fill=fill,
                                image_password=image_password.encode('utf-8'))
    folder = STORE / record['id']
    print(f"Protected image #{record['id']}: {folder / 'protected.png'}")
    print(f"Encrypted regions: {folder / 'regions.islenc'}")
    print(f'Cleanup: selected original file removed and confirmed absent: {source}')


def restore_image():
    records = show_entries()
    if not records:
        return
    if not PRIVATE_KEY.is_file():
        print('Matching keys/private.pem not found. Use the private key used for these images.')
        return
    choice = input('Which number should be restored? ').strip()
    if not choice.isdecimal() or not 1 <= int(choice) <= len(records):
        print('Choose a number from the list.')
        return
    record = records[int(choice) - 1]
    destination = Path(f"restored_{record['id'][4:12]}.png")
    count = 2
    while destination.exists():
        destination = Path(f"restored_{record['id'][4:12]}_{count}.png")
        count += 1
    image_password = getpass('Image password (press Enter for an older image): ')
    password = getpass('Private-key password: ')
    store = ImageStore(STORE)
    report = store.restore(record['id'], destination, PRIVATE_KEY,
                           password.encode('utf-8'), image_password=image_password.encode('utf-8'))
    print(f'Restored to: {destination.resolve()}')
    print(f"AES-GCM authentication: {report['aes_gcm_authentication']}; "
          f"restored pixel hash: {'PASS' if report['restored_pixel_sha256_match'] else 'FAIL'}")


def delete_image():
    records = show_entries()
    if not records:
        return
    choice = input('Which number should be deleted? ').strip()
    if not choice.isdecimal() or not 1 <= int(choice) <= len(records):
        print('Choose a number from the list.')
        return
    record = records[int(choice) - 1]
    if input(f"Type DELETE to remove {record['name']} ({record['id'][4:12]}): ").strip() != 'DELETE':
        print('Deletion cancelled.')
        return
    ImageStore(STORE).delete(record['id'])
    print(f"Deleted saved image {record['id'][4:12]}.")


def main():
    while True:
        print('\nPrivacy Guard')
        print('1. Protect an image')
        print('2. List saved images')
        print('3. Restore an image')
        print('4. Create keys (first time only)')
        print('5. Delete a saved image')
        print('6. Exit')
        try:
            choice = input('Choose 1–6: ').strip()
            if choice == '1':
                add_image()
            elif choice == '2':
                show_entries()
            elif choice == '3':
                restore_image()
            elif choice == '4':
                create_keys()
            elif choice == '5':
                delete_image()
            elif choice == '6':
                return
            else:
                print('Choose a number from 1 to 6.')
        except (ValueError, OSError, ImportError, KeyError, RuntimeError) as exc:
            print(f'Could not complete that action: {exc}')
        except (EOFError, KeyboardInterrupt):
            print('\nExited.')
            return


if __name__ == '__main__':
    main()
