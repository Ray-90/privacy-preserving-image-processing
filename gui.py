r"""Local desktop interface for the single-image Privacy Guard workflow.

Run from the project folder with: .\.venv\Scripts\python.exe gui.py
"""
import io
from pathlib import Path
from threading import Thread
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from PIL import Image, ImageTk

import app
from privacy_guard.config import MAX_PIXELS
from privacy_guard.crypto.format import MAX_PLAINTEXT
from privacy_guard.crypto.keys import generate_keys
from privacy_guard.file_io import read_bounded
from privacy_guard.image_store import ImageStore
from privacy_guard.isolation import add_image_isolated, synced_folder_warning


BASE = Path(__file__).resolve().parent


def project_path(path):
    path = Path(path).expanduser()
    return path if path.is_absolute() else BASE / path


class PrivacyGuardWindow:
    def __init__(self, root):
        self.root = root
        self.root.title('Privacy Guard')
        self.root.minsize(820, 600)
        self.store_path = project_path(app.STORE)
        self.public_key = project_path(app.PUBLIC_KEY)
        self.private_key = project_path(app.PRIVATE_KEY)
        self.model = project_path(app.MODEL_WEIGHTS)
        self.busy = False
        self.preview_photo = None
        self.status = tk.StringVar(value='Ready. Choose a photo or browse your saved images.')
        self.key_status = tk.StringVar()
        self.model_status = tk.StringVar()
        self.selected_info = tk.StringVar(value='Select a saved image to view its details.')
        self.source = tk.StringVar()
        self.name = tk.StringVar(value='Image')
        self.fill = tk.StringVar(value='black')
        self.fill_help = tk.StringVar()

        main = ttk.Frame(root, padding=16)
        main.pack(fill='both', expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        heading = ttk.Frame(main)
        heading.grid(row=0, column=0, sticky='ew', pady=(0, 12))
        ttk.Label(heading, text='Privacy Guard', font=('Segoe UI', 17, 'bold')).pack(anchor='w')
        ttk.Label(heading, text='Protect document photos locally and restore them when needed.').pack(anchor='w')

        self.tabs = ttk.Notebook(main)
        self.tabs.grid(row=1, column=0, sticky='nsew')
        protect_tab = ttk.Frame(self.tabs, padding=14)
        self.saved_tab = ttk.Frame(self.tabs, padding=14)
        self.tabs.add(protect_tab, text='  Protect an image  ')
        self.tabs.add(self.saved_tab, text='  Saved images & restore  ')
        protect_tab.columnconfigure(0, weight=1)
        self.saved_tab.columnconfigure(0, weight=1)
        self.saved_tab.rowconfigure(1, weight=1)

        setup = ttk.LabelFrame(protect_tab, text='1 · Check setup', padding=12)
        setup.grid(row=0, column=0, sticky='ew', pady=(0, 12))
        setup.columnconfigure(0, weight=1)
        ttk.Label(setup, textvariable=self.key_status, wraplength=620).grid(row=0, column=0, sticky='w')
        self.key_button = ttk.Button(setup, text='Create keys', command=self.create_keys)
        self.key_button.grid(row=0, column=1, padx=(12, 0))
        ttk.Label(setup, textvariable=self.model_status, wraplength=720).grid(
            row=1, column=0, columnspan=2, sticky='w', pady=(8, 0))

        form = ttk.LabelFrame(protect_tab, text='2 · Choose a photo and preview style', padding=12)
        form.grid(row=1, column=0, sticky='ew', pady=(0, 12))
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text='Photo to protect').grid(row=0, column=0, sticky='w')
        ttk.Entry(form, textvariable=self.source).grid(row=0, column=1, sticky='ew', padx=10)
        self.browse_button = ttk.Button(form, text='Browse...', command=self.browse)
        self.browse_button.grid(row=0, column=2)
        ttk.Label(form, text='Short label').grid(row=1, column=0, sticky='w', pady=(12, 0))
        ttk.Entry(form, textvariable=self.name).grid(row=1, column=1, sticky='ew', padx=10, pady=(12, 0))
        ttk.Label(form, text='Visible in your saved-images list; do not put private details in the label.').grid(
            row=2, column=1, columnspan=2, sticky='w', padx=10)
        ttk.Label(form, text='Hidden area').grid(row=3, column=0, sticky='w', pady=(12, 0))
        style = ttk.Combobox(form, textvariable=self.fill, values=('black', 'texture', 'inpaint'),
                             state='readonly', width=18)
        style.grid(row=3, column=1, sticky='w', padx=10, pady=(12, 0))
        style.bind('<<ComboboxSelected>>', self.update_fill_help)
        ttk.Label(form, textvariable=self.fill_help, wraplength=570).grid(
            row=4, column=1, columnspan=2, sticky='w', padx=10, pady=(3, 0))

        action = ttk.LabelFrame(protect_tab, text='3 · Protect', padding=12)
        action.grid(row=2, column=0, sticky='ew')
        ttk.Label(action, text='You will create an image password (8+ characters). '
                  'The selected original file is removed after protection succeeds.',
                  wraplength=690).pack(anchor='w')
        self.protect_button = ttk.Button(action, text='Protect this photo', command=self.protect)
        self.protect_button.pack(anchor='w', pady=(12, 0))
        self.update_fill_help()
        self.update_setup()

        saved_heading = ttk.Frame(self.saved_tab)
        saved_heading.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        ttk.Label(saved_heading, text='Your protected images', font=('Segoe UI', 12, 'bold')).pack(side='left')
        self.refresh_button = ttk.Button(saved_heading, text='Refresh', command=self.refresh)
        self.refresh_button.pack(side='right')

        manager = ttk.Frame(self.saved_tab)
        manager.grid(row=1, column=0, sticky='nsew')
        manager.columnconfigure(0, weight=3)
        manager.columnconfigure(1, weight=2)
        manager.rowconfigure(0, weight=1)

        listing = ttk.Frame(manager)
        listing.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
        listing.columnconfigure(0, weight=1)
        listing.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(listing, columns=('name', 'created', 'id'), show='headings')
        for column, title, width in [('name', 'Label', 160), ('created', 'Saved (UTC)', 140),
                                     ('id', 'Short ID', 110)]:
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, stretch=column != 'created')
        self.tree.grid(row=0, column=0, sticky='nsew')
        bar = ttk.Scrollbar(listing, orient='vertical', command=self.tree.yview)
        bar.grid(row=0, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=bar.set)
        self.tree.bind('<<TreeviewSelect>>', self.show_preview)

        preview = ttk.LabelFrame(manager, text='Preview (sensitive areas hidden)', padding=8)
        preview.grid(row=0, column=1, sticky='nsew')
        preview.columnconfigure(0, weight=1)
        preview.rowconfigure(0, weight=1)
        self.preview_label = ttk.Label(preview, text='Select a saved image to view its protected PNG.',
                                       anchor='center', justify='center', wraplength=250)
        self.preview_label.grid(row=0, column=0, sticky='nsew')

        details = ttk.Frame(self.saved_tab)
        details.grid(row=2, column=0, sticky='ew', pady=(12, 0))
        ttk.Label(details, textvariable=self.selected_info, wraplength=740).pack(anchor='w')
        self.restore_button = ttk.Button(details, text='Restore selected image...', command=self.restore)
        self.restore_button.pack(anchor='w', pady=(9, 0))
        self.delete_button = ttk.Button(details, text='Delete selected image...', command=self.delete_image)
        self.delete_button.pack(anchor='w', pady=(6, 0))
        ttk.Label(details, text='Restoration asks for this image’s password and the password '
                  'chosen when the key pair was created.', wraplength=740).pack(anchor='w', pady=(6, 0))

        ttk.Separator(main).grid(row=2, column=0, sticky='ew', pady=(12, 7))
        ttk.Label(main, textvariable=self.status, wraplength=790).grid(row=3, column=0, sticky='w')
        self.refresh()

    def update_fill_help(self, _event=None):
        self.fill_help.set({
            'black': 'Solid black; the clearest sign that a region is hidden.',
            'texture': 'Copies nearby clean background. Best on a plain or consistent surface.',
            'inpaint': 'OpenCV reconstruction; large document boxes may look smeared.',
        }.get(self.fill.get(), 'Choose a preview style.'))

    def update_setup(self):
        if self.public_key.is_file() and self.private_key.is_file():
            self.key_status.set('Keys ready. The same key pair can protect several images.')
        elif self.public_key.parent.exists():
            self.key_status.set('Keys folder is incomplete. Restore your original key pair before proceeding.')
        else:
            self.key_status.set('No key pair found. Create one before protecting your first image.')
        self.key_button.configure(state='disabled' if self.busy or self.public_key.parent.exists()
                                  else 'normal')
        self.model_status.set(f'Model ready: {self.model}' if self.model.is_file() else
                              f'Model not found: {self.model}. Set MODEL_WEIGHTS in app.py to your best.pt.')

    def update_restore_button(self):
        state = 'normal' if self.selected_id() and not self.busy else 'disabled'
        self.restore_button.configure(state=state)
        self.delete_button.configure(state=state)

    def browse(self):
        selected = filedialog.askopenfilename(
            parent=self.root, title='Choose an image',
            filetypes=[('Images', '*.jpg *.jpeg *.png *.webp *.bmp *.tif *.tiff'),
                       ('All files', '*.*')])
        if selected:
            self.source.set(selected)

    def selected_id(self):
        selected = self.tree.selection()
        return selected[0] if selected else None

    def refresh(self, select_id=None):
        self.update_setup()
        selected = select_id or self.selected_id()
        rows = self.tree.get_children()
        if rows:
            self.tree.delete(*rows)
        try:
            records = ImageStore(self.store_path).list() if self.store_path.is_dir() else []
        except (OSError, ValueError, KeyError) as exc:
            messagebox.showerror('Could not list images', str(exc), parent=self.root)
            return
        for record in records:
            created = record['created_utc'][:16].replace('T', ' ')
            self.tree.insert('', 'end', iid=record['id'],
                             values=(record['name'], created, record['id'][4:12]))
        self.status.set(f'{len(records)} protected image(s) saved.')
        if selected in self.tree.get_children():
            self.tree.selection_set(selected)
            self.tree.see(selected)
            self.show_preview()
        else:
            self.preview_photo = None
            self.preview_label.configure(image='', text='Select a saved image to view its protected PNG.')
            self.selected_info.set('Select a saved image to view its details.')
        self.update_restore_button()

    def show_preview(self, _event=None):
        image_id = self.selected_id()
        if not image_id:
            self.selected_info.set('Select a saved image to view its details.')
            self.update_restore_button()
            return
        name, created, _short_id = self.tree.item(image_id, 'values')
        self.selected_info.set(f'{name} · Saved {created} UTC · ID: {image_id}')
        self.update_restore_button()
        path = self.store_path / image_id / 'protected.png'
        try:
            data = read_bounded(path, MAX_PLAINTEXT)
            with Image.open(io.BytesIO(data)) as image:
                if image.width * image.height > MAX_PIXELS:
                    raise ValueError('Preview exceeds the image size limit.')
                thumbnail = image.convert('RGB')
                thumbnail.thumbnail((420, 400))
                self.preview_photo = ImageTk.PhotoImage(thumbnail, master=self.root)
            self.preview_label.configure(image=self.preview_photo, text='')
        except (OSError, ValueError) as exc:
            self.preview_photo = None
            self.preview_label.configure(image='', text='Preview unavailable.')
            messagebox.showerror('Could not show preview', str(exc), parent=self.root)

    def run_task(self, description, operation, on_success):
        if self.busy:
            return
        self.busy = True
        self.protect_button.configure(state='disabled')
        self.restore_button.configure(state='disabled')
        self.delete_button.configure(state='disabled')
        self.key_button.configure(state='disabled')
        self.browse_button.configure(state='disabled')
        self.status.set(description)

        def finished(result=None, error=None):
            self.busy = False
            self.protect_button.configure(state='normal')
            self.browse_button.configure(state='normal')
            self.update_restore_button()
            self.update_setup()
            if error is not None:
                self.status.set(f'Failed: {error}')
                messagebox.showerror('Privacy Guard', error, parent=self.root)
            else:
                on_success(result)

        def worker():
            try:
                result = operation()
            except Exception as exc:
                detail = str(exc).strip() or f'{type(exc).__name__}: operation failed.'
                self.root.after(0, lambda error=detail: finished(error=error))
            else:
                self.root.after(0, lambda: finished(result=result))

        Thread(target=worker, daemon=True).start()

    def protect(self):
        source = self.source.get().strip().strip('"')
        name = self.name.get().strip() or 'Image'
        fill = self.fill.get()
        if not source or not Path(source).is_file():
            messagebox.showerror('Missing image', 'Choose an existing image first.', parent=self.root)
            return
        if not self.model.is_file():
            messagebox.showerror('Missing model',
                f'Could not find {self.model}. Set MODEL_WEIGHTS once in app.py.', parent=self.root)
            return
        if not self.public_key.is_file():
            messagebox.showerror('Missing keys', 'Create keys first, or copy your existing keys into keys/.',
                                 parent=self.root)
            return
        warning = synced_folder_warning(source)
        if warning and not messagebox.askyesno('Synced image location',
                warning + '\n\nContinue protecting this image?', parent=self.root):
            return
        image_password = simpledialog.askstring('Image password',
            'Create a new password for this image (8+ characters):', show='*', parent=self.root)
        if image_password is None:
            return
        if len(image_password) < 8:
            messagebox.showerror('Image password too short',
                                 'Use at least 8 characters for the image password.',
                                 parent=self.root)
            return
        repeated = simpledialog.askstring('Image password', 'Repeat the new image password:',
                                          show='*', parent=self.root)
        if repeated is None:
            return
        if repeated != image_password:
            messagebox.showerror('Image passwords do not match',
                                 'The two image passwords differ. Please enter them again.',
                                 parent=self.root)
            return

        def operation():
            return add_image_isolated(source, self.model, self.public_key, self.store_path,
                                      name=name, fill=fill,
                                      image_password=image_password.encode('utf-8'))

        def done(record):
            self.source.set('')
            self.refresh(select_id=record['id'])
            self.tabs.select(self.saved_tab)
            self.status.set(f"Protected '{record['name']}' as {record['id']}. "
                            'Cleanup: selected original file removed and confirmed absent.')

        self.run_task('Detecting and encrypting the image...', operation, done)

    def restore(self):
        image_id = self.selected_id()
        if not image_id:
            messagebox.showinfo('Choose an image', 'Select a saved image first.', parent=self.root)
            return
        if not self.private_key.is_file():
            messagebox.showerror('Missing key', 'Matching keys/private.pem was not found.', parent=self.root)
            return
        destination = filedialog.asksaveasfilename(
            parent=self.root, title='Save restored PNG', initialdir=str(BASE),
            initialfile=f'restored_{image_id[4:12]}.png', defaultextension='.png',
            filetypes=[('PNG image', '*.png')])
        if not destination:
            return
        if Path(destination).exists():
            messagebox.showerror('Choose a new name', 'That file already exists.', parent=self.root)
            return
        image_password = simpledialog.askstring('Image password',
                                               'Enter the password created for this image. '
                                               'Leave blank only for an older image without one:',
                                               show='*', parent=self.root)
        if image_password is None:
            return
        password = simpledialog.askstring('Private-key password',
                                         'Enter the password chosen when keys/private.pem was created:',
                                         show='*', parent=self.root)
        if not password:
            return

        def operation():
            return ImageStore(self.store_path).restore(
                image_id, destination, self.private_key, password.encode('utf-8'),
                image_password=image_password.encode('utf-8'))

        def done(report):
            self.status.set(f'Restored to {destination}. Authentication: {report["aes_gcm_authentication"]}.')
            messagebox.showinfo('Restoration complete', f'Restored PNG saved to:\n{destination}',
                                parent=self.root)

        self.run_task('Authenticating and restoring the image...', operation, done)

    def delete_image(self):
        image_id = self.selected_id()
        if not image_id or self.busy:
            return
        name = self.tree.item(image_id, 'values')[0]
        if not messagebox.askyesno('Delete saved image',
                f'Delete "{name}" ({image_id[4:12]})?\n\n'
                'Its protected preview and encrypted regions will be removed. '
                'You will not be able to restore it afterward.', parent=self.root):
            return

        def done(_record):
            self.refresh()
            self.status.set(f'Deleted saved image {image_id[4:12]}.')

        self.run_task('Deleting selected saved image...',
                      lambda: ImageStore(self.store_path).delete(image_id), done)

    def create_keys(self):
        directory = self.public_key.parent
        if directory.exists():
            messagebox.showinfo('Existing keys', 'The keys folder already exists; keys were not changed.',
                                parent=self.root)
            return
        password = simpledialog.askstring('Create keys', 'Choose a private-key password:',
                                          show='*', parent=self.root)
        if not password:
            return
        again = simpledialog.askstring('Create keys', 'Repeat the password:',
                                       show='*', parent=self.root)
        if password != again:
            messagebox.showerror('Passwords do not match', 'No keys were created.', parent=self.root)
            return

        def done(_result):
            self.update_setup()
            self.status.set('Keys created. Back up keys/private.pem and remember its password.')
            messagebox.showinfo('Keys created', 'Keys saved in keys/. Keep a backup of private.pem.',
                                parent=self.root)

        self.run_task('Creating keys...', lambda: generate_keys(directory, password.encode('utf-8')),
                      done)


def main():
    root = tk.Tk()
    PrivacyGuardWindow(root)
    root.mainloop()


if __name__ == '__main__':
    main()
