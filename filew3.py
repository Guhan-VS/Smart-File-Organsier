import os
import shutil
import json
import platform
import subprocess
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, IntVar

CONFIG_FILE = "config.json"

# ------------------ Persisted Config ------------------
config = {
    "default_source": "",
    "default_destination": "",
    "default_recursive": True
}

def load_config():
    global config
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                cfg = json.load(f)
                if isinstance(cfg, dict):
                    config.update(cfg)
        except Exception:
            pass

def save_config():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        messagebox.showerror("Settings", f"Failed to save settings:\n{e}")

load_config()

# ------------------ Undo Log (in-memory) ------------------
# Each entry: (moved_path, original_path)
undo_log = []

# ------------------ Root Window (Main UI) ------------------
root = tb.Window(themename="cosmo")
root.title("🧠 Smart File Organizer")
root.geometry("820x520")
root.minsize(780, 500)
root.resizable(False, False)

# ------------------ Status helpers ------------------
status_text = tb.StringVar(value="Ready")
def set_status(msg):
    status_text.set(msg)
    root.update_idletasks()

# ------------------Sub Process------------------
def open_folder(path):
    """Open folder in system's default file explorer."""
    if platform.system() == "Windows":
        os.startfile(path)
    elif platform.system() == "Darwin":  # macOS
        subprocess.Popen(["open", path])
    else:  # Linux
        subprocess.Popen(["xdg-open", path])

# ------------------ Utilities ------------------
def list_files(src, recursive):
    files = []
    if recursive:
        for dirpath, _, filenames in os.walk(src):
            for f in filenames:
                files.append(os.path.join(dirpath, f))
    else:
        try:
            for f in os.listdir(src):
                p = os.path.join(src, f)
                if os.path.isfile(p):
                    files.append(p)
        except Exception:
            pass
    return files

def show_progress_popup(total, title="Processing..."):
    win = tb.Toplevel(root)
    win.title(title)
    win.resizable(False, False)
    tb.Label(win, text="Please wait...", font=("Segoe UI", 10)).pack(padx=16, pady=(14, 6))
    pb = tb.Progressbar(win, orient=HORIZONTAL, mode="determinate", maximum=max(1, total), length=320)
    pb.pack(padx=16, pady=(0, 12))
    win.update()
    return win, pb

def safe_move(src_path, dst_path):
    """Move with overwrite protection: if name exists, append counter."""
    base, ext = os.path.splitext(dst_path)
    candidate = dst_path
    counter = 1
    while os.path.exists(candidate):
        candidate = f"{base} ({counter}){ext}"
        counter += 1
    shutil.move(src_path, candidate)
    return candidate

def tidy_empty_dirs(paths):
    """Try removing empty directories from a set of folder paths."""
    for folder in sorted(paths, key=lambda p: len(p.split(os.sep)), reverse=True):
        try:
            if os.path.isdir(folder) and not os.listdir(folder):
                os.rmdir(folder)
        except Exception:
            pass

# ------------------ Extension Flow ------------------
# ------------------ Extension Flow ------------------
def open_extension_window():
    win = tb.Toplevel(root)
    win.title("🗂️ Organize by Extension")
    win.geometry("560x560")
    win.resizable(False, False)

    src_var = tb.StringVar(value=config.get("default_source", ""))
    dst_var = tb.StringVar(value=config.get("default_destination", ""))
    recursive_var = tb.BooleanVar(value=bool(config.get("default_recursive", True)))

    # UI
    tb.Label(win, text="Source Folder:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
    f1 = tb.Frame(win)
    f1.pack(fill="x", padx=16)
    src_entry = tb.Entry(f1, textvariable=src_var)
    src_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
    tb.Button(f1, text="Browse", bootstyle="primary-outline",
              command=lambda: _browse_dir(src_var)).pack(side="left")

    tb.Label(win, text="Destination Folder (optional):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
    f2 = tb.Frame(win)
    f2.pack(fill="x", padx=16)
    dst_entry = tb.Entry(f2, textvariable=dst_var)
    dst_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
    tb.Button(f2, text="Browse", bootstyle="primary-outline",
              command=lambda: _browse_dir(dst_var)).pack(side="left")

    tb.Checkbutton(win, text="Include Subfolders", variable=recursive_var, bootstyle="round-toggle").pack(anchor="w", padx=16, pady=8)

    tb.Label(win, text="Select Extensions to organize:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(8, 4))
    checkbox_frame = tb.Frame(win)
    checkbox_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8), anchor="n")
    checkbox_frame.columnconfigure((0,1,2), weight=1)

    ext_vars = {}  # ext -> IntVar

    def scan_and_render_exts():
        for child in checkbox_frame.winfo_children():
            child.destroy()
        ext_vars.clear()
        src = src_var.get().strip()
        if not os.path.isdir(src):
            messagebox.showwarning("Scan", "Please choose a valid source folder.")
            return
        found = set()
        for p in list_files(src, recursive_var.get()):
            ext = os.path.splitext(p)[1].lower()
            if ext:
                found.add(ext)
        if not found:
            tb.Label(checkbox_frame, text="No extensions found in the selected folder.", bootstyle="secondary")\
                .grid(row=0, column=0, sticky="w")
            return
        for i, ext in enumerate(sorted(found)):
            r, c = divmod(i, 3)
            ext_vars[ext] = IntVar(value=1)   # ✅ all selected by default
            tb.Checkbutton(checkbox_frame, text=ext, variable=ext_vars[ext]).grid(row=r, column=c, sticky="w", pady=4)

    # Scan button
    tb.Button(win, text="🔍 Scan Extensions", bootstyle="info-outline", command=scan_and_render_exts)\
        .pack(padx=16, pady=(0, 6), anchor="w")

    # Select / Deselect buttons
    control_frame = tb.Frame(win)
    control_frame.pack(anchor="w", padx=16, pady=(0, 6))

    def select_all():
        for v in ext_vars.values():
            v.set(1)

    def deselect_all():
        for v in ext_vars.values():
            v.set(0)

    tb.Button(control_frame, text="✅ Select All", bootstyle="success-outline", command=select_all)\
        .pack(side="left", padx=(0, 8))
    tb.Button(control_frame, text="🚫 Deselect All", bootstyle="danger-outline", command=deselect_all)\
        .pack(side="left")

    # Organize button
    tb.Button(win, text="🚀 Organize", bootstyle="success", width=16,
              command=lambda: _start_extension_organize(win, src_var, dst_var, recursive_var, ext_vars))\
        .pack(pady=(4, 12))


def _browse_dir(var):
    path = filedialog.askdirectory()
    if path:
        var.set(path)


def _start_extension_organize(win, src_var, dst_var, recursive_var, ext_vars):
    src = os.path.abspath(src_var.get().strip())
    dst = os.path.abspath(dst_var.get().strip() or src)
    recursive = bool(recursive_var.get())
    selected_exts = [ext for ext, v in ext_vars.items() if v.get() == 1]

    if not os.path.isdir(src):
        messagebox.showerror("Error", "Please select a valid Source folder.")
        return
    if not selected_exts:
        messagebox.showwarning("Select Extensions", "Choose at least one extension to organize.")
        return

    files = list_files(src, recursive)
    if not files:
        messagebox.showinfo("Info", "No files found to organize.")
        return

    # Preview counts
    counts = {}
    for p in files:
        e = os.path.splitext(p)[1].lower()
        if e in selected_exts:
            counts[e] = counts.get(e, 0) + 1
    if not counts:
        messagebox.showinfo("Preview", "No files match the selected extensions.")
        return

    summary = "\n".join(f"{ext} → {counts[ext]} files" for ext in sorted(counts))
    proceed = messagebox.askyesno("Confirm Organize", f"About to move:\n\n{summary}\n\nDestination:\n{dst}\n\nProceed?")
    if not proceed:
        return

    # Perform
    moved = {}
    undo_log.clear()
    wait, pb = show_progress_popup(len(files), title="Organizing by Extension")
    cleaned_dirs = set()

    try:
        for i, full in enumerate(files, start=1):
            ext = os.path.splitext(full)[1].lower()
            if ext in selected_exts:
                folder = os.path.join(dst, ext.lstrip(".").upper())
                os.makedirs(folder, exist_ok=True)
                new_path = safe_move(full, os.path.join(folder, os.path.basename(full)))
                undo_log.append((new_path, full))
                moved[ext] = moved.get(ext, 0) + 1
                cleaned_dirs.add(os.path.dirname(full))
            pb["value"] = i
            pb.update()
        wait.destroy()
        tidy_empty_dirs(cleaned_dirs)

        config["default_source"] = src
        config["default_destination"] = dst
        config["default_recursive"] = recursive
        save_config()

        if moved:
            done = "\n".join(f"✅ {ext}: {count} files" for ext, count in sorted(moved.items()))
            messagebox.showinfo("Done", f"Organized files:\n\n{done}")
            set_status("Organized by extension.")
        else:
            messagebox.showinfo("Done", "No matching files were moved.")
            set_status("No files matched.")
    except Exception as e:
        wait.destroy()
        messagebox.showerror("Error", f"Failed during organize:\n{e}")
        set_status("Error during organize.")
    open_folder(dst)


# ------------------ Keyword Flow ------------------
def open_keyword_window():
    win = tb.Toplevel(root)
    win.title("🔍 Organize by Keyword")
    win.geometry("560x420")
    win.resizable(False, False)

    src_var = tb.StringVar(value=config.get("default_source", ""))
    dst_var = tb.StringVar(value=config.get("default_destination", ""))
    recursive_var = tb.BooleanVar(value=bool(config.get("default_recursive", True)))
    kw_var = tb.StringVar()

    tb.Label(win, text="Source Folder:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
    f1 = tb.Frame(win); f1.pack(fill="x", padx=16)
    tb.Entry(f1, textvariable=src_var).pack(side="left", fill="x", expand=True, padx=(0,8))
    tb.Button(f1, text="Browse", bootstyle="primary-outline", command=lambda: _browse_dir(src_var)).pack(side="left")

    tb.Label(win, text="Destination Folder (optional):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
    f2 = tb.Frame(win); f2.pack(fill="x", padx=16)
    tb.Entry(f2, textvariable=dst_var).pack(side="left", fill="x", expand=True, padx=(0,8))
    tb.Button(f2, text="Browse", bootstyle="primary-outline", command=lambda: _browse_dir(dst_var)).pack(side="left")

    tb.Checkbutton(win, text="Include Subfolders", variable=recursive_var, bootstyle="round-toggle").pack(anchor="w", padx=16, pady=8)

    tb.Label(win, text="Keywords (comma separated):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(8, 2))
    tb.Entry(win, textvariable=kw_var).pack(fill="x", padx=16)

    tb.Button(win, text="🚀 Organize", bootstyle="success", width=16,
              command=lambda: _start_keyword_organize(win, src_var, dst_var, recursive_var, kw_var))\
        .pack(pady=(12, 10))

def _start_keyword_organize(win, src_var, dst_var, recursive_var, kw_var):
    src = os.path.abspath(src_var.get().strip())
    dst = os.path.abspath(dst_var.get().strip() or src)
    recursive = bool(recursive_var.get())
    kws = [k.strip().lower() for k in kw_var.get().split(",") if k.strip()]

    if not os.path.isdir(src):
        messagebox.showerror("Error", "Please select a valid Source folder.")
        return
    if not kws:
        messagebox.showwarning("Keywords", "Enter at least one keyword.")
        return

    files = list_files(src, recursive)
    if not files:
        messagebox.showinfo("Info", "No files found to organize.")
        return

    # Preview counts
    counts = {}
    for p in files:
        name = os.path.basename(p).lower()
        for kw in kws:
            if kw in name:
                counts[kw] = counts.get(kw, 0) + 1
                break
    if not counts:
        messagebox.showinfo("Preview", "No files matched your keywords.")
        return

    summary = "\n".join(f'"{kw}" → {counts[kw]} files' for kw in sorted(counts))
    proceed = messagebox.askyesno("Confirm Organize", f"About to move:\n\n{summary}\n\nDestination:\n{dst}\n\nProceed?")
    if not proceed:
        return

    # Perform
    moved = {}
    undo_log.clear()
    wait, pb = show_progress_popup(len(files), title="Organizing by Keyword")
    cleaned_dirs = set()

    try:
        for i, full in enumerate(files, start=1):
            name = os.path.basename(full).lower()
            matched = None
            for kw in kws:
                if kw in name:
                    matched = kw
                    break
            if matched:
                folder = os.path.join(dst, matched)
                os.makedirs(folder, exist_ok=True)
                new_path = safe_move(full, os.path.join(folder, os.path.basename(full)))
                undo_log.append((new_path, full))
                moved[matched] = moved.get(matched, 0) + 1
                cleaned_dirs.add(os.path.dirname(full))
            pb["value"] = i
            pb.update()
        wait.destroy()
        tidy_empty_dirs(cleaned_dirs)

        config["default_source"] = src
        config["default_destination"] = dst
        config["default_recursive"] = recursive
        save_config()

        if moved:
            done = "\n".join(f'✅ "{kw}": {count} files' for kw, count in sorted(moved.items()))
            messagebox.showinfo("Done", f"Organized files:\n\n{done}")
            set_status("Organized by keyword.")
        else:
            messagebox.showinfo("Done", "No matching files were moved.")
            set_status("No files matched.")
    except Exception as e:
        wait.destroy()
        messagebox.showerror("Error", f"Failed during organize:\n{e}")
        set_status("Error during organize.")
    open_folder(dst)

# ------------------ Undo ------------------
def undo_last_operation():
    if not undo_log:
        messagebox.showinfo("Undo", "Nothing to undo.")
        return
    set_status("Undoing last operation...")
    cleaned = set()
    restored = 0
    while undo_log:
        new_path, original_path = undo_log.pop()
        if os.path.exists(new_path):
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(new_path, original_path)
            cleaned.add(os.path.dirname(new_path))
            restored += 1
    tidy_empty_dirs(cleaned)
    messagebox.showinfo("Undo", f"Restored {restored} file(s) to original locations.")
    set_status("Undo completed.")
    

# ------------------ Settings ------------------
def open_settings_window():
    win = tb.Toplevel(root)
    win.title("⚙️ Settings")
    win.geometry("440x260")
    win.resizable(False, False)

    tb.Label(win, text="Default Source Folder:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
    f1 = tb.Frame(win); f1.pack(fill="x", padx=16)
    src_entry = tb.Entry(f1)
    src_entry.insert(0, config.get("default_source", ""))
    src_entry.pack(side="left", fill="x", expand=True, padx=(0,8))
    tb.Button(f1, text="Browse", bootstyle="primary-outline",
              command=lambda: _browse_into_entry(src_entry)).pack(side="left")

    tb.Label(win, text="Default Destination Folder:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
    f2 = tb.Frame(win); f2.pack(fill="x", padx=16)
    dst_entry = tb.Entry(f2)
    dst_entry.insert(0, config.get("default_destination", ""))
    dst_entry.pack(side="left", fill="x", expand=True, padx=(0,8))
    tb.Button(f2, text="Browse", bootstyle="primary-outline",
              command=lambda: _browse_into_entry(dst_entry)).pack(side="left")

    rec_var = tb.BooleanVar(value=bool(config.get("default_recursive", True)))
    tb.Checkbutton(win, text="Default: Include Subfolders", variable=rec_var, bootstyle="round-toggle")\
        .pack(anchor="w", padx=16, pady=10)

    def save_and_close():
        config["default_source"] = src_entry.get().strip()
        config["default_destination"] = dst_entry.get().strip()
        config["default_recursive"] = bool(rec_var.get())
        save_config()
        messagebox.showinfo("Settings", "Settings saved.")
        win.destroy()

    tb.Button(win, text="Save Settings", bootstyle="success", command=save_and_close).pack(pady=10)

def _browse_into_entry(entry):
    path = filedialog.askdirectory()
    if path:
        entry.delete(0, "end")
        entry.insert(0, path)

# ================== Main Window UI ==================
# Header
header = tb.Label(
    root, text="🧠 Smart File Organizer",
    font=("Segoe UI", 18, "bold"),
    bootstyle="inverse-primary", anchor="center"
)
header.pack(fill="x", pady=(12, 4))

subheader = tb.Label(
    root,
    text="Organize your messy folders by file extensions\nor by keywords — with preview & undo.",
    font=("Segoe UI", 11), anchor="center"
)
subheader.pack(pady=(0, 10))

# Main cards
main_frame = tb.Frame(root, padding=20)
main_frame.pack(fill="both", expand=True)

org_card = tb.Labelframe(main_frame, text="📂 Organize Options", bootstyle="primary")
org_card.pack(side="left", fill="both", expand=True, padx=12, pady=10)

tb.Button(org_card, text="🗂️ Organize by Extension", width=28, bootstyle="success-outline",
          command=open_extension_window).pack(pady=12)
tb.Button(org_card, text="🔍 Organize by Keyword", width=28, bootstyle="success-outline",
          command=open_keyword_window).pack(pady=12)

act_card = tb.Labelframe(main_frame, text="⚡ Quick Actions", bootstyle="info")
act_card.pack(side="left", fill="both", expand=True, padx=12, pady=10)

tb.Button(act_card, text="↩️ Undo Last Operation", width=28, bootstyle="danger-outline",
          command=undo_last_operation).pack(pady=12)
tb.Button(act_card, text="⚙️ Settings", width=28, bootstyle="secondary-outline",
          command=open_settings_window).pack(pady=12)

# Status bar
status_frame = tb.Frame(root, bootstyle="secondary")
status_frame.pack(side="bottom", fill="x")

status_label = tb.Label(status_frame, textvariable=status_text, anchor="w")
status_label.pack(side="left", padx=12, pady=6)

progress = tb.Progressbar(status_frame, orient=HORIZONTAL, mode="determinate", length=220)
progress.pack(side="right", padx=12, pady=6)

set_status("Ready.")
root.mainloop()
