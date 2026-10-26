# Python File Integrity Monitor

A Python-based cybersecurity application that monitors files and detects unauthorized or unexpected changes using SHA-256 hashing. The application provides a graphical interface for scanning files, managing baselines, reviewing scan history, and exporting reports.

Developed as a practical project to explore Python programming and fundamental cybersecurity concepts.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [How It Works](#how-it-works)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [How to Use](#how-to-use)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Author](#author)
- [License](#license)

## Overview

File integrity monitoring helps identify changes to files by comparing their current cryptographic hashes with previously recorded reference values.

This project implements a baseline-based monitoring approach using Python, SHA-256 hashing, and a graphical user interface built with Tkinter. Users can select a directory, establish a baseline, scan for changes, and review the results through the application.

The project is intended for educational purposes, cybersecurity demonstrations, and portfolio development.

## Features

- **File Integrity Checking:** Calculates SHA-256 hashes to identify changes in file contents.
- **Baseline Management:** Saves a reference state of monitored files for future comparisons.
- **Change Detection:** Identifies new, modified, and deleted files.
- **Graphical User Interface:** Provides a desktop interface built with Python Tkinter.
- **Scan History:** Stores scan records in an SQLite database.
- **Search and Filtering:** Supports searching scan history and filtering records by scan type.
- **Color-Coded Results:** Uses distinct colors to make different file changes easier to identify.
- **Text Reports:** Generates detailed reports of scan results.
- **CSV Export:** Exports scan history for analysis in spreadsheet applications.
- **Automatic Monitoring:** Supports recurring scans at a configurable interval.
- **Baseline Integrity Verification:** Uses HMAC signatures to help detect unauthorized modifications to saved baseline data.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Application logic |
| Tkinter | Graphical user interface |
| SHA-256 | File integrity verification |
| HMAC | Baseline signature verification |
| SQLite | Scan history storage |
| JSON | Baseline data storage |
| CSV | Exporting scan records |
| Git | Version control |
| GitHub | Source code hosting |

The application is designed to use Python's standard library without requiring third-party packages, provided the implementation uses only the listed standard-library functionality.

## How It Works

The application follows a baseline-and-comparison workflow:

1. **Directory Selection:** The user selects a directory to monitor.
2. **Baseline Creation:** The application calculates and stores reference hashes for the monitored files.
3. **File Scanning:** The application calculates current file hashes.
4. **Comparison:** Current hashes are compared with the saved baseline.
5. **Change Identification:** The application reports new, modified, and deleted files.
6. **History and Reporting:** Scan records can be reviewed, searched, filtered, and exported.

### File Change Categories

| Status | Description |
|---|---|
| NEW | A file exists in the current scan but was not present in the baseline. |
| MODIFIED | A file's current hash differs from its saved baseline hash. |
| DELETED | A file recorded in the baseline is no longer found during the scan. |

## Screenshots

### Home Window

The main interface of the application.

![Home Window](file_monitor_data/screenshots/Home%20Window.png)

### Scan for Changes

The scanning interface used to check monitored files.

![Scan for Changes](file_monitor_data/screenshots/sacn%20for%20changes%20.png)

### Scan Results

An example of the scan results interface.

![Scan Results](file_monitor_data/screenshots/Sran%20For%20Changes.png)

### CSV Exporting

The interface for exporting scan history.

![CSV Exporting](file_monitor_data/screenshots/CSV%20Exporting.png)

### CSV File

An example of exported scan history.

![CSV File](file_monitor_data/screenshots/csv%20file.png)

### Deleted File Detection

An example of file deletion detection.

![Deleting Files](file_monitor_data/screenshots/Deleing.png)

## Requirements

- Windows, macOS, or Linux.
- Python 3.
- A compatible graphical desktop environment for Tkinter.
- No third-party packages are required if the application uses only Python's standard library.

## Installation

### Option 1: Download the Project

1. Open the [project repository](https://github.com/ASAD1960/file_monitor).
2. Select **Code**.
3. Choose **Download ZIP**.
4. Extract the downloaded archive.
5. Open the extracted folder in Visual Studio Code or another Python-compatible editor.

### Option 2: Clone the Repository

Run the following commands in a terminal:

```bash
git clone https://github.com/ASAD1960/file_monitor.git
cd file_monitor
```

Verify that Python is installed:

```bash
python --version
```

On Windows, you can also use:

```powershell
py --version
```

## How to Run

Open a terminal in the project directory and execute:

```bash
python file_monitor.py
```

On Windows, the application can also be launched using:

```powershell
py file_monitor.py
```

The graphical interface should open if Python and Tkinter are installed correctly.

## How to Use

1. Launch the application.
2. Select the directory you want to monitor.
3. Create or save a baseline for the selected directory.
4. Run a scan to compare the current files against the baseline.
5. Review any new, modified, or deleted files.
6. Use the scan history to examine previous results.
7. Search or filter historical records as needed.
8. Export scan history to CSV or generate a text report.
9. Configure automatic monitoring if recurring scans are required.

For initial testing, use a separate directory containing sample files rather than important personal or system files.

## Project Structure

The main repository files are organized as follows:

```text
file_monitor/
├── file_monitor.py
├── README.md
├── .gitignore
└── file_monitor_data/
    └── screenshots/
        ├── Home Window.png
        ├── sacn for changes .png
        ├── Sran For Changes.png
        ├── CSV Exporting.png
        ├── csv file.png
        └── Deleing.png
```

The application may create additional runtime files, including baseline data, an SQLite database, and generated reports. The exact contents depend on the application configuration and usage. Runtime data is excluded from version control where configured in `.gitignore`.

## Security Considerations

- **SHA-256 Hashing:** Helps detect file content changes by comparing cryptographic hashes.
- **HMAC Verification:** Helps verify baseline integrity when the signing key remains protected.
- **Signing Key Protection:** The HMAC key should be stored securely and separately from data that an attacker could modify. If an attacker can change both the baseline and its trusted signing key, baseline verification may be bypassed.
- **Baseline Protection:** Reference data should be protected against unauthorized modification.
- **Testing:** Detection behavior should be tested with sample files before the application is used to monitor important data.

This project is an educational implementation and has not been presented as an independently audited security product.

## Limitations

- Detection depends on the accuracy and integrity of the baseline.
- A file that is changed and later restored to its original contents may produce the same hash as before.
- Automatic monitoring depends on the configured scan interval and application availability.
- HMAC verification relies on proper protection of the signing key.
- This application is not a replacement for antivirus software, endpoint detection and response systems, or enterprise security monitoring solutions.

## Future Improvements

Potential improvements include:

- Automated unit and integration testing.
- More comprehensive error handling and logging.
- Configurable file exclusion and monitoring rules.
- Additional reporting and export options.
- Packaging the application as a Windows executable.
- Expanded monitoring and notification capabilities.

## Author

**Asad Yar**

Developed as a Python programming and cybersecurity learning project.

- **GitHub Profile:** [ASAD1960](https://github.com/ASAD1960)
- **Project Repository:** [Python File Integrity Monitor](https://github.com/ASAD1960/file_monitor)

## License

No license has been specified for this repository. If the project is intended for public reuse, modification, or redistribution, consider adding an appropriate open-source license.
