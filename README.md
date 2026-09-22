#  Python TCP Port Scanner

A simple and efficient **TCP Port Scanner** built using **Python**. This tool scans a target host for open TCP ports, identifies common services, and optionally performs banner grabbing to retrieve basic service information.

> **Disclaimer:** This project is intended for educational purposes and should only be used on systems you own or have explicit permission to scan.

---

##  Features

- Scan TCP ports on a target host
- Scan a custom range of ports
- Scan specific ports
- Multi-threaded scanning for faster performance
- Optional banner grabbing
- Displays common service names
- Uses only Python's built-in libraries (no external dependencies)

---

##  Technologies Used

- Python 3
- Socket Programming
- Threading
- Queue
- Argparse

---

##  Project Structure

```
Port_scanner/
│── port_scanner.py
│── README.md
```

---

##  Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/Port_scanner.git
```

### 2. Navigate to the project folder

```bash
cd Port_scanner
```

### 3. Verify Python installation

```bash
python --version
```

or

```bash
python3 --version
```

---

##  Sample Output

```text
Scanning target: localhost (127.0.0.1)
Ports to scan:   1024
Threads:         100
Started at:      2026-07-21 22:52:00

PORT      STATE   SERVICE      BANNER
------------------------------------------------------------
135       open    unknown
445       open    SMB
903       open    unknown
913       open    unknown

Scan completed in 11.10 seconds.
```

