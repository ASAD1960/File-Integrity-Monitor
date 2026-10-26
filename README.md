# File Integrity Monitor

A Python-based cybersecurity application that monitors files and detects unauthorized or unexpected changes using SHA-256 hashing.

## Features

- **File Integrity Checking:** Uses SHA-256 hashes to identify file changes.
- **Baseline Management:** Saves a reference state of monitored files.
- **Change Detection:** Detects new, modified, and deleted files.
- **Graphical User Interface:** Built with Python Tkinter.
- **Scan History:** Stores scan records in an SQLite database.
- **Search and Filtering:** Search scan history and filter by scan type.
- **Color-Coded Results:** Displays different file changes with distinct colors.
- **Text Reports:** Generates detailed scan reports.
- **CSV Export:** Exports scan history for use in spreadsheet applications.
- **Automatic Monitoring:** Supports periodic scans at a configurable interval.
- **Baseline Verification:** Uses HMAC signatures to detect baseline tampering.

## Technologies Used

- Python
- Tkinter
- SQLite
- SHA-256
- HMAC
- JSON
- CSV

## Requirements

- Windows, macOS, or Linux with a compatible Python installation.
- Python 3.
- No external Python packages are required if the application uses only Python's standard library.

## How to Run

1. Download or clone this repository.
2. Open the project folder in Visual Studio Code.
3. Open a terminal in the project folder.
4. Run:

   ```bash
   python file_monitor.py
   ```

   On Windows, you can also use:

   ```powershell
   py file_monitor.py
   ```

5. Select the folder you want to monitor.
6. Save a baseline before scanning for changes.
7. Run a scan to identify new, modified, or deleted files.

## Project Structure

```text
file_monitor/
├── file_monitor.py
├── README.md
└── file_monitor_data/
    ├── baseline.json
    ├── history.db
    └── reports/
```

The exact contents of the data folder may vary depending on your configuration and scan history.

## Security Notes

- SHA-256 hashes help detect file content changes.
- HMAC signatures help verify that the saved baseline has not been modified without detection.
- Protect the HMAC signing key. If an attacker can modify both the baseline and its signing key, they may be able to bypass this protection.
- This project is intended for learning and demonstration, not as a substitute for an independently audited security product.

## Future Improvements

- Add automated unit tests.
- Improve error handling and logging.
- Add configurable monitoring rules.
- Package the application as a Windows executable.

## Author
Asad Yar
Developed as a Python and cybersecurity learning project.

## Screenshots

### Home Window
![Home Window](screenshots/Home%20Window.png)

###  Scan for Changes
![ Scan for Changes](screenshots/New%20sacn%20for%20changes.png)

### Scan for Changes
![Scan for Changes](screenshots/Sran%20For%20Changes.png)

### CSV Exporting
![CSV Exporting](screenshots/CSV%20Exporting.png)

### CSV File
![CSV File](screenshots/csv%20file.png)

### Deleting
![Deleting](screenshots/Deleing.png)
