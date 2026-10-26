
import csv
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


# ============================================================
# FILE INTEGRITY MONITOR - ENHANCED VERSION
# SHA-256, baseline, change detection, SQLite history,
# CSV export, search/filter, detailed reports, auto-scanning,
# and baseline HMAC verification.
# ============================================================

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "file_monitor_data"
BASELINE_FILE = DATA_DIR / "baseline.json"
DATABASE_FILE = DATA_DIR / "history.db"
REPORTS_DIR = DATA_DIR / "reports"

DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Store the signing key separately from the baseline.
if os.name == "nt":
    KEY_ROOT = Path(os.environ.get("APPDATA", str(Path.home())))
    KEY_ROOT = KEY_ROOT / "FileIntegrityMonitor"
else:
    KEY_ROOT = Path.home() / ".file_integrity_monitor"

KEY_FILE = KEY_ROOT / "baseline.key"


def timestamp():
    return datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )


def timestamp_filename():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ============================================================
# BASELINE SIGNING
# ============================================================

def get_signing_key():
    """Create or load the local key used to sign baselines."""
    KEY_ROOT.mkdir(parents=True, exist_ok=True)

    if not KEY_FILE.exists():
        try:
            with KEY_FILE.open("xb") as file:
                file.write(secrets.token_bytes(32))
        except FileExistsError:
            pass

    key = KEY_FILE.read_bytes()

    if len(key) != 32:
        raise RuntimeError(
            "The baseline signing key is invalid.\n"
            f"Key location: {KEY_FILE}\n"
            "Restore the original key before verifying old baselines."
        )

    return key


def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_baseline(data):
    return hmac.new(
        get_signing_key(),
        canonical_json(data),
        hashlib.sha256,
    ).hexdigest()


# ============================================================
# FILE HASHING AND COMPARISON
# ============================================================

def sha256_file(file_path):
    """Calculate a file's SHA-256 hash."""
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def scan_folder(folder):
    """Return relative file paths mapped to SHA-256 hashes."""
    folder = Path(folder).resolve()
    data_dir = DATA_DIR.resolve()

    files = {}
    errors = []

    for path in folder.rglob("*"):
        try:
            resolved = path.resolve()

            # Never include this application's own data.
            try:
                resolved.relative_to(data_dir)
                continue
            except ValueError:
                pass

            # Ignore symbolic links that point outside the folder.
            try:
                resolved.relative_to(folder)
            except ValueError:
                continue

            if resolved.is_file():
                relative_path = str(path.relative_to(folder))
                files[relative_path] = sha256_file(resolved)

        except (OSError, RuntimeError) as exc:
            errors.append(f"{path}: {exc}")

    return files, errors


def compare_files(old_files, new_files):
    """Detect NEW, DELETED, and MODIFIED files."""
    changes = []

    for path in sorted(new_files.keys() - old_files.keys()):
        changes.append((path, "NEW", "", new_files[path]))

    for path in sorted(old_files.keys() - new_files.keys()):
        changes.append((path, "DELETED", old_files[path], ""))

    for path in sorted(old_files.keys() & new_files.keys()):
        if old_files[path] != new_files[path]:
            changes.append(
                (path, "MODIFIED", old_files[path], new_files[path])
            )

    return changes


# ============================================================
# APPLICATION
# ============================================================

class FileIntegrityMonitor:

    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor")
        self.root.geometry("1250x780")
        self.root.minsize(900, 600)

        self.folder_var = tk.StringVar()
        self.status_var = tk.StringVar(
            value="Choose a folder and save a baseline."
        )
        self.search_var = tk.StringVar()
        self.type_var = tk.StringVar(value="ALL")
        self.auto_var = tk.BooleanVar(value=False)
        self.interval_var = tk.StringVar(value="60")

        self.auto_job = None

        self.setup_database()
        self.build_interface()
        self.refresh_history()

        self.root.protocol("WM_DELETE_WINDOW", self.close_app)

    # ========================================================
    # DATABASE
    # ========================================================

    def setup_database(self):
        with sqlite3.connect(DATABASE_FILE) as connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_time TEXT NOT NULL DEFAULT '',
                    timestamp TEXT NOT NULL DEFAULT '',
                    folder TEXT NOT NULL DEFAULT '',
                    scan_type TEXT NOT NULL DEFAULT '',
                    change_count INTEGER NOT NULL DEFAULT 0,
                    summary TEXT NOT NULL DEFAULT ''
                )
            """)

            scan_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(scans)"
                ).fetchall()
            }

            scan_definitions = {
                "scan_time": "TEXT NOT NULL DEFAULT ''",
                "timestamp": "TEXT NOT NULL DEFAULT ''",
                "folder": "TEXT NOT NULL DEFAULT ''",
                "scan_type": "TEXT NOT NULL DEFAULT ''",
                "change_count": "INTEGER NOT NULL DEFAULT 0",
                "summary": "TEXT NOT NULL DEFAULT ''",
            }

            for column, definition in scan_definitions.items():
                if column not in scan_columns:
                    connection.execute(
                        f"ALTER TABLE scans ADD COLUMN "
                        f"{column} {definition}"
                    )

            # Synchronize timestamps in existing records.
            connection.execute("""
                UPDATE scans
                SET timestamp = scan_time
                WHERE timestamp = '' AND scan_time != ''
            """)

            connection.execute("""
                UPDATE scans
                SET scan_time = timestamp
                WHERE scan_time = '' AND timestamp != ''
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    change_type TEXT NOT NULL DEFAULT '',
                    file_path TEXT NOT NULL DEFAULT '',
                    old_hash TEXT,
                    new_hash TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
            """)

            change_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(changes)"
                ).fetchall()
            }

            change_definitions = {
                "scan_id": "INTEGER NOT NULL DEFAULT 0",
                "change_type": "TEXT NOT NULL DEFAULT ''",
                "file_path": "TEXT NOT NULL DEFAULT ''",
                "old_hash": "TEXT",
                "new_hash": "TEXT",
            }

            for column, definition in change_definitions.items():
                if column not in change_columns:
                    connection.execute(
                        f"ALTER TABLE changes ADD COLUMN "
                        f"{column} {definition}"
                    )

    def record_scan(
        self, folder, scan_type, changes, summary, errors=None
    ):
        current_time = timestamp()

        with sqlite3.connect(DATABASE_FILE) as connection:
            cursor = connection.execute("""
                INSERT INTO scans (
                    scan_time,
                    timestamp,
                    folder,
                    scan_type,
                    change_count,
                    summary
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                current_time,
                current_time,
                str(folder),
                scan_type,
                len(changes),
                summary,
            ))

            scan_id = cursor.lastrowid

            if changes:
                connection.executemany("""
                    INSERT INTO changes (
                        scan_id,
                        file_path,
                        change_type,
                        old_hash,
                        new_hash
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, [
                    (
                        scan_id,
                        path,
                        kind,
                        old_hash,
                        new_hash,
                    )
                    for path, kind, old_hash, new_hash in changes
                ])

        self.write_report(
            scan_id,
            current_time,
            folder,
            scan_type,
            changes,
            summary,
            errors or [],
        )

        return scan_id

    # ========================================================
    # GUI
    # ========================================================

    def build_interface(self):
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        ttk.Label(
            outer,
            text="File Integrity Monitor",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            outer,
            text=(
                "SHA-256 monitoring | Change detection | "
                "Scan history | Security reports"
            ),
        ).pack(anchor="w", pady=(2, 10))

        folder_frame = ttk.LabelFrame(
            outer,
            text="Folder to monitor",
            padding=8,
        )
        folder_frame.pack(fill="x", pady=(0, 8))

        ttk.Entry(
            folder_frame,
            textvariable=self.folder_var,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Button(
            folder_frame,
            text="Browse...",
            command=self.browse_folder,
        ).pack(side="left")

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(0, 8))

        button_items = [
            ("Save Baseline", self.save_baseline),
            ("Scan for Changes", self.scan_for_changes),
            ("Refresh History", self.refresh_history),
            ("Export History to CSV", self.export_history_csv),
            ("Export Selected Report", self.export_selected_report),
        ]

        for text, command in button_items:
            ttk.Button(
                buttons,
                text=text,
                command=command,
            ).pack(side="left", padx=(0, 5))

        # Automatic monitoring controls.
        auto_frame = ttk.LabelFrame(
            outer,
            text="Automatic monitoring",
            padding=7,
        )
        auto_frame.pack(fill="x", pady=(0, 8))

        ttk.Checkbutton(
            auto_frame,
            text="Enable periodic scans",
            variable=self.auto_var,
            command=self.toggle_auto,
        ).pack(side="left")

        ttk.Label(
            auto_frame,
            text="Interval (seconds):",
        ).pack(side="left", padx=(12, 4))

        ttk.Entry(
            auto_frame,
            textvariable=self.interval_var,
            width=7,
        ).pack(side="left")

        ttk.Label(
            auto_frame,
            text="Minimum interval: 10 seconds",
        ).pack(side="left", padx=10)

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        results_tab = ttk.Frame(self.notebook, padding=7)
        history_tab = ttk.Frame(self.notebook, padding=7)

        self.notebook.add(results_tab, text="Current Results")
        self.notebook.add(history_tab, text="Scan History")

        # Current results with colors.
        result_columns = (
            "file",
            "status",
            "old_hash",
            "new_hash",
        )

        self.results_tree = ttk.Treeview(
            results_tab,
            columns=result_columns,
            show="headings",
        )

        result_headings = [
            ("file", "File", 300),
            ("status", "Change", 100),
            ("old_hash", "Previous SHA-256", 350),
            ("new_hash", "Current SHA-256", 350),
        ]

        for column, heading, width in result_headings:
            self.results_tree.heading(column, text=heading)
            self.results_tree.column(
                column,
                width=width,
                anchor="w",
            )

        self.results_tree.tag_configure(
            "NEW", foreground="#087f23"
        )
        self.results_tree.tag_configure(
            "MODIFIED", foreground="#b36b00"
        )
        self.results_tree.tag_configure(
            "DELETED", foreground="#c62828"
        )

        self.results_tree.pack(fill="both", expand=True)

        # Search and filter controls.
        filter_frame = ttk.Frame(history_tab)
        filter_frame.pack(fill="x", pady=(0, 7))

        ttk.Label(
            filter_frame,
            text="Search:",
        ).pack(side="left")

        search_entry = ttk.Entry(
            filter_frame,
            textvariable=self.search_var,
            width=30,
        )
        search_entry.pack(side="left", padx=5)
        search_entry.bind(
            "<KeyRelease>",
            lambda _event: self.refresh_history(),
        )

        ttk.Label(
            filter_frame,
            text="Scan type:",
        ).pack(side="left", padx=(10, 3))

        type_box = ttk.Combobox(
            filter_frame,
            textvariable=self.type_var,
            values=("ALL", "BASELINE", "SCAN", "AUTO"),
            state="readonly",
            width=12,
        )
        type_box.pack(side="left")
        type_box.bind(
            "<<ComboboxSelected>>",
            lambda _event: self.refresh_history(),
        )

        ttk.Button(
            filter_frame,
            text="Clear filters",
            command=self.clear_history_filters,
        ).pack(side="left", padx=8)

        history_columns = (
            "id",
            "timestamp",
            "folder",
            "scan_type",
            "count",
            "summary",
        )

        self.history_tree = ttk.Treeview(
            history_tab,
            columns=history_columns,
            show="headings",
            selectmode="browse",
        )

        history_headings = [
            ("id", "ID", 55),
            ("timestamp", "Timestamp", 175),
            ("folder", "Folder", 270),
            ("scan_type", "Type", 85),
            ("count", "Changes", 75),
            ("summary", "Summary", 360),
        ]

        for column, heading, width in history_headings:
            self.history_tree.heading(column, text=heading)
            self.history_tree.column(
                column,
                width=width,
                anchor="w",
            )

        self.history_tree.pack(fill="both", expand=True)

        self.history_tree.bind(
            "<Double-1>",
            lambda _event: self.export_selected_report(),
        )

        ttk.Label(
            outer,
            textvariable=self.status_var,
            wraplength=1150,
        ).pack(anchor="w", pady=(8, 0))

        ttk.Label(
            outer,
            text=f"App data: {DATA_DIR} | Reports: {REPORTS_DIR}",
            foreground="gray",
            wraplength=1150,
        ).pack(anchor="w", pady=(3, 0))

    # ========================================================
    # FOLDER SELECTION
    # ========================================================

    def browse_folder(self):
        selected = filedialog.askdirectory(
            title="Choose a folder to monitor"
        )

        if selected:
            self.folder_var.set(selected)

    def get_folder(self):
        raw = self.folder_var.get().strip().strip('"')

        if not raw:
            messagebox.showwarning(
                "Folder required",
                "Please choose a folder first.",
            )
            return None

        try:
            folder = Path(raw).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            messagebox.showerror(
                "Invalid folder",
                "The selected folder could not be found or opened.",
            )
            return None

        if not folder.is_dir():
            messagebox.showerror(
                "Invalid folder",
                "The selected path is not a folder.",
            )
            return None

        # Do not allow a folder that contains the application's data.
        try:
            DATA_DIR.resolve().relative_to(folder)
            contains_data = True
        except ValueError:
            contains_data = False

        if contains_data:
            messagebox.showerror(
                "Choose another folder",
                "Choose your testfiles folder or another folder "
                "that does not contain the application data directory.",
            )
            return None

        return folder

    # ========================================================
    # BASELINE
    # ========================================================

    def save_baseline(self):
        folder = self.get_folder()

        if folder is None:
            return

        try:
            self.status_var.set("Creating and signing baseline...")
            self.root.update_idletasks()

            files, errors = scan_folder(folder)

            data = {
                "folder": str(folder),
                "created_at": timestamp(),
                "files": files,
            }

            signature = sign_baseline(data)
            saved_data = dict(data)
            saved_data["hmac_sha256"] = signature

            temporary_file = BASELINE_FILE.with_suffix(".tmp")
            temporary_file.write_text(
                json.dumps(saved_data, indent=2),
                encoding="utf-8",
            )
            temporary_file.replace(BASELINE_FILE)

            summary = (
                f"Baseline saved for {len(files)} files. "
                "HMAC signature added."
            )

            if errors:
                summary += (
                    f" {len(errors)} file(s) could not be read."
                )

            self.record_scan(
                folder, "BASELINE", [], summary, errors
            )
            self.clear_results()
            self.refresh_history()
            self.status_var.set(summary)

            messagebox.showinfo(
                "Baseline saved",
                f"Folder: {folder}\n"
                f"Files recorded: {len(files)}\n"
                "Baseline tamper check: enabled"
                + (
                    f"\nFiles with errors: {len(errors)}"
                    if errors else ""
                ),
            )

        except (
            OSError,
            sqlite3.Error,
            ValueError,
            TypeError,
            RuntimeError,
        ) as exc:
            messagebox.showerror("Baseline error", str(exc))

    def load_verified_baseline(self):
        try:
            saved = json.loads(
                BASELINE_FILE.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Could not read baseline: {exc}"
            ) from exc

        signature = saved.pop("hmac_sha256", None)

        if not signature:
            raise ValueError(
                "This baseline was created by an older version "
                "and is not signed.\n\n"
                "Click Save Baseline again to create a signed baseline."
            )

        expected = sign_baseline(saved)

        if not hmac.compare_digest(signature, expected):
            raise ValueError(
                "BASELINE INTEGRITY CHECK FAILED!\n\n"
                "The baseline contents or signing key may have changed. "
                "Investigate before saving a new baseline."
            )

        return saved

    # ========================================================
    # SCANNING
    # ========================================================

    def scan_for_changes(self, automatic=False):
        folder = self.get_folder()

        if folder is None:
            return

        if not BASELINE_FILE.exists():
            if not automatic:
                messagebox.showwarning(
                    "No baseline",
                    "Click Save Baseline before scanning.",
                )
            self.status_var.set("No baseline exists. Save one first.")
            return

        try:
            data = self.load_verified_baseline()
            baseline_folder = Path(
                data.get("folder", "")
            ).resolve()

            if baseline_folder != folder:
                if not automatic:
                    messagebox.showwarning(
                        "Baseline mismatch",
                        "The baseline belongs to a different folder. "
                        "Save a baseline for this folder first.",
                    )
                self.status_var.set("Baseline mismatch.")
                return

            self.status_var.set(
                "Scanning files and comparing SHA-256 hashes..."
            )
            self.root.update_idletasks()

            old_files = data.get("files", {})
            new_files, errors = scan_folder(folder)
            changes = compare_files(old_files, new_files)

            self.clear_results()

            for path, kind, old_hash, new_hash in changes:
                self.results_tree.insert(
                    "",
                    "end",
                    values=(path, kind, old_hash, new_hash),
                    tags=(kind,),
                )

            counts = {
                "NEW": 0,
                "DELETED": 0,
                "MODIFIED": 0,
            }

            for _, kind, _, _ in changes:
                counts[kind] += 1

            summary = (
                f"New: {counts['NEW']}, "
                f"Deleted: {counts['DELETED']}, "
                f"Modified: {counts['MODIFIED']}"
            )

            if not changes:
                summary = "No changes detected."

            if errors:
                summary += (
                    f" {len(errors)} file(s) could not be read."
                )

            scan_type = "AUTO" if automatic else "SCAN"

            self.record_scan(
                folder, scan_type, changes, summary, errors
            )
            self.refresh_history()
            self.notebook.select(0)
            self.status_var.set(
                ("Automatic scan: " if automatic else "") + summary
            )

            if not automatic:
                if errors:
                    messagebox.showwarning(
                        "Scan completed with warnings",
                        summary,
                    )
                elif changes:
                    messagebox.showinfo("Scan completed", summary)
                else:
                    messagebox.showinfo(
                        "Scan completed",
                        "No changes detected.",
                    )
            elif changes:
                self.root.bell()
                messagebox.showwarning(
                    "Automatic scan detected changes",
                    summary,
                )

        except (
            OSError,
            sqlite3.Error,
            json.JSONDecodeError,
            ValueError,
            TypeError,
            RuntimeError,
        ) as exc:
            self.status_var.set(f"Scan failed: {exc}")

            if not automatic:
                messagebox.showerror("Scan error", str(exc))

    def clear_results(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

    # ========================================================
    # SEARCH AND FILTER HISTORY
    # ========================================================

    def clear_history_filters(self):
        self.search_var.set("")
        self.type_var.set("ALL")
        self.refresh_history()

    def refresh_history(self):
        if not hasattr(self, "history_tree"):
            return

        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        search_text = self.search_var.get().strip().casefold()
        selected_type = self.type_var.get()

        try:
            with sqlite3.connect(DATABASE_FILE) as connection:
                rows = connection.execute("""
                    SELECT
                        id,
                        COALESCE(NULLIF(timestamp, ''), scan_time),
                        folder,
                        scan_type,
                        change_count,
                        summary
                    FROM scans
                    ORDER BY id DESC
                """).fetchall()

            shown = 0

            for row in rows:
                searchable = " ".join(
                    str(value or "") for value in row
                ).casefold()

                if search_text and search_text not in searchable:
                    continue

                if selected_type != "ALL" and row[3] != selected_type:
                    continue

                self.history_tree.insert(
                    "", "end", values=row
                )
                shown += 1

            self.status_var.set(
                f"History displayed: {shown} of {len(rows)} records."
            )

        except sqlite3.Error as exc:
            messagebox.showerror("History error", str(exc))

    # ========================================================
    # DETAILED REPORTS
    # ========================================================

    def write_report(
        self, scan_id, scan_time, folder, scan_type,
        changes, summary, errors
    ):
        report_path = (
            REPORTS_DIR
            / f"scan_{scan_id}_{timestamp_filename()}.txt"
        )

        lines = [
            "FILE INTEGRITY MONITOR - SCAN REPORT",
            "=" * 52,
            f"Scan ID: {scan_id}",
            f"Timestamp: {scan_time}",
            f"Folder: {folder}",
            f"Scan type: {scan_type}",
            f"Change count: {len(changes)}",
            f"Summary: {summary}",
            "",
            "FILE CHANGES",
            "-" * 52,
        ]

        if changes:
            for path, kind, old_hash, new_hash in changes:
                lines.extend([
                    f"File: {path}",
                    f"Change: {kind}",
                    f"Previous SHA-256: {old_hash or '(not available)'}",
                    f"Current SHA-256: {new_hash or '(not available)'}",
                    "",
                ])
        else:
            lines.append("No file changes recorded.")

        if errors:
            lines.extend([
                "",
                "READ ERRORS",
                "-" * 52,
                *errors,
            ])

        lines.extend([
            "",
            "Security note:",
            "SHA-256 hashes help identify file-content changes.",
            "The HMAC checks baseline changes while the signing key remains trusted.",
            "This local application cannot protect against an attacker "
            "who controls this Windows account.",
        ])

        report_path.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

    def export_selected_report(self):
        selection = self.history_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select a scan",
                "Select a record in Scan History first, then "
                "click Export Selected Report.",
            )
            return

        scan_id = int(
            self.history_tree.item(selection[0], "values")[0]
        )

        try:
            with sqlite3.connect(DATABASE_FILE) as connection:
                scan = connection.execute("""
                    SELECT
                        COALESCE(NULLIF(timestamp, ''), scan_time),
                        folder,
                        scan_type,
                        change_count,
                        summary
                    FROM scans
                    WHERE id = ?
                """, (scan_id,)).fetchone()

                changes = connection.execute("""
                    SELECT file_path, change_type, old_hash, new_hash
                    FROM changes
                    WHERE scan_id = ?
                    ORDER BY id
                """, (scan_id,)).fetchall()

            if scan is None:
                messagebox.showerror(
                    "Report error",
                    "The selected scan record no longer exists.",
                )
                return

            scan_time, folder, scan_type, count, summary = scan

            destination = filedialog.asksaveasfilename(
                title="Save detailed scan report",
                defaultextension=".txt",
                initialfile=f"file_monitor_scan_{scan_id}.txt",
                filetypes=[
                    ("Text reports", "*.txt"),
                    ("All files", "*.*"),
                ],
            )

            if not destination:
                return

            lines = [
                "FILE INTEGRITY MONITOR - SCAN REPORT",
                "=" * 52,
                f"Scan ID: {scan_id}",
                f"Timestamp: {scan_time}",
                f"Folder: {folder}",
                f"Scan type: {scan_type}",
                f"Change count: {count}",
                f"Summary: {summary}",
                "",
                "FILE CHANGES",
                "-" * 52,
            ]

            if changes:
                for path, kind, old_hash, new_hash in changes:
                    lines.extend([
                        f"File: {path}",
                        f"Change: {kind}",
                        f"Previous SHA-256: {old_hash or '(not available)'}",
                        f"Current SHA-256: {new_hash or '(not available)'}",
                        "",
                    ])
            else:
                lines.append("No file changes recorded for this scan.")

            Path(destination).write_text(
                "\n".join(lines),
                encoding="utf-8",
            )

            messagebox.showinfo(
                "Report exported",
                f"Detailed report saved to:\n{destination}",
            )

        except (OSError, sqlite3.Error, ValueError) as exc:
            messagebox.showerror("Report export error", str(exc))

    # ========================================================
    # CSV EXPORT
    # ========================================================

    def export_history_csv(self):
        try:
            with sqlite3.connect(DATABASE_FILE) as connection:
                rows = connection.execute("""
                    SELECT
                        scans.id,
                        COALESCE(
                            NULLIF(scans.timestamp, ''),
                            scans.scan_time
                        ),
                        scans.folder,
                        scans.scan_type,
                        scans.change_count,
                        scans.summary,
                        changes.file_path,
                        changes.change_type,
                        changes.old_hash,
                        changes.new_hash
                    FROM scans
                    LEFT JOIN changes
                        ON changes.scan_id = scans.id
                    ORDER BY scans.id DESC, changes.id ASC
                """).fetchall()

            if not rows:
                messagebox.showinfo(
                    "No history",
                    "There is no scan history to export yet.",
                )
                return

            destination = filedialog.asksaveasfilename(
                title="Export scan history",
                defaultextension=".csv",
                initialfile=(
                    f"file_monitor_history_{timestamp_filename()}.csv"
                ),
                filetypes=[
                    ("CSV files", "*.csv"),
                    ("All files", "*.*"),
                ],
            )

            if not destination:
                return

            headers = [
                "Scan ID",
                "Timestamp",
                "Folder",
                "Scan Type",
                "Change Count",
                "Summary",
                "File Path",
                "Change Type",
                "Previous SHA-256",
                "Current SHA-256",
            ]

            # UTF-8 BOM helps Excel display text correctly.
            with open(
                destination,
                "w",
                newline="",
                encoding="utf-8-sig",
            ) as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(headers)
                writer.writerows(rows)

            self.status_var.set(f"CSV exported: {destination}")

            messagebox.showinfo(
                "Export successful",
                f"Scan history exported successfully.\n\n"
                f"{destination}\n\nRows exported: {len(rows)}",
            )

        except (OSError, sqlite3.Error, csv.Error) as exc:
            messagebox.showerror("CSV export error", str(exc))

    # ========================================================
    # AUTOMATIC MONITORING
    # ========================================================

    def toggle_auto(self):
        if self.auto_var.get():
            try:
                interval = int(self.interval_var.get())

                if interval < 10:
                    raise ValueError

            except ValueError:
                self.auto_var.set(False)
                messagebox.showwarning(
                    "Invalid interval",
                    "Enter a whole number of at least 10 seconds.",
                )
                return

            if self.get_folder() is None:
                self.auto_var.set(False)
                return

            if not BASELINE_FILE.exists():
                self.auto_var.set(False)
                messagebox.showwarning(
                    "No baseline",
                    "Save a baseline before enabling automatic scans.",
                )
                return

            self.status_var.set(
                f"Automatic monitoring enabled: every {interval} seconds."
            )
            self.schedule_auto_scan(interval)

        else:
            if self.auto_job is not None:
                self.root.after_cancel(self.auto_job)
                self.auto_job = None

            self.status_var.set("Automatic monitoring stopped.")

    def schedule_auto_scan(self, interval):
        if self.auto_job is not None:
            self.root.after_cancel(self.auto_job)

        self.auto_job = self.root.after(
            interval * 1000,
            self.run_auto_scan,
        )

    def run_auto_scan(self):
        self.auto_job = None

        if not self.auto_var.get():
            return

        try:
            interval = int(self.interval_var.get())

            if interval < 10:
                raise ValueError

        except ValueError:
            self.auto_var.set(False)
            messagebox.showwarning(
                "Invalid interval",
                "Automatic monitoring stopped. "
                "The interval must be at least 10 seconds.",
            )
            return

        self.scan_for_changes(automatic=True)

        if self.auto_var.get():
            self.schedule_auto_scan(interval)

    def close_app(self):
        if self.auto_job is not None:
            try:
                self.root.after_cancel(self.auto_job)
            except tk.TclError:
                pass

        self.root.destroy()


def main():
    root = tk.Tk()
    FileIntegrityMonitor(root)
    root.mainloop()


if __name__ == "__main__":
    main()
