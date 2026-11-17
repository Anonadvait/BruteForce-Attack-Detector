# BruteForce Attack Detector

A minimal, premium cybersecurity application designed for **Data Structures & Algorithms (DSA)** practical demonstration and college viva evaluation.

The system monitors authentication attempts, maintains an active FIFO queue and LIFO activity stack, and detects potential brute-force attacks by flagging consecutive failed login attempts originating from the same IP address.

All core DSA logic, data structures, detection algorithms, and persistent attempt logging are strictly implemented in **C (C11)**. The user interface is built using **Python Tkinter** with a **Premium Cyberpunk Design System**, offering a clean two-stage user experience:
1. **Dedicated Authentication Gateway**: Clean, minimal login and registration interface (no monitoring visible before authentication).
2. **Post-Login Threat Monitoring Dashboard**: System metrics, active alert banners, persistent audit history, live Queue/Stack visualization, and network diagnostics.

---

## 1. Quick Start & Execution

### Option A: One-Click Desktop Launch (Windows)
Double-click:
```cmd
run.bat
```
This automatically verifies the C executable, ensures databases are initialized, and opens the Tkinter application directly.

### Option B: Command Line (Python Entry Point)
```bash
python gui/app.py
```

### Option C: Run 12-Point Automated Verification Suite
```bash
python test_verification.py
```

### Option D: Run C Core Tests Directly
```bash
./bruteforce_detector.exe test
```

---

## 2. Default Demonstration Accounts

Pre-populated in `database/users.txt` using salted PBKDF2-HMAC-SHA256:

| Username | Full Name | Password | Role |
|---|---|---|---|
| `admin` | System Administrator | `cyber2026!` | Admin Access |
| `advait` | Advait Sharma | `matrix99` | Developer / Lead |
| `student` | DSA Student | `dsa123` | Academic Demo |

*Users can also register brand-new accounts through the Registration screen.*

---

## 3. Premium Cyberpunk Design System

| Element | Color Hex | Visual Purpose |
|---|---|---|
| **Root Background** | `#0B0D13` | Deep charcoal / near-black canvas |
| **Panel Surface** | `#131622` | Secondary panel container |
| **Card Surface** | `#181C2C` | Metric cards and elevated modules |
| **Input Fields** | `#0F121D` | Form inputs with subtle border focus |
| **Primary Accent** | `#00E5FF` | Muted electric cyan (Queue indicators, highlights, active tabs) |
| **Secondary Accent** | `#8B5CF6` | Subtle violet (Stack indicators, action buttons) |
| **Restrained Alert** | `#EF4444` | Brute-force alarm banners, failed login feedback |
| **Success Emerald** | `#10B981` | Successful authentications, verified status |
| **Typography** | `Segoe UI` / `Consolas` | Clean modern typography; monospaced strictly for technical data |

---

## 4. Application Flow & Architecture

```
[ Application Launch ]
         │
         ▼
[ Dedicated Authentication Screen ] (gui/app.py)
   ├── Login Form (Username, Password, IP Mode, Show/Hide Password)
   └── Registration Form (Full Name, Username, Salted PBKDF2 Hashing)
         │
         │ (Successful Authentication)
         ▼
[ Post-Login Dashboard ] (Unlocked)
   ├── 01. Main Dashboard: Real-time Metrics, Active Threat Banners, Suspicious IPs Table
   ├── 02. Login History: Persistent Audit Trail (database/login_database.txt)
   ├── 03. DSA Visualization: Live in-memory C Queue (FIFO) & Stack (LIFO)
   ├── 04. Settings: Active Route Local IP, HTTPS Public IP, Architecture Notice
   └── 05. Sign Out: Clears session and returns to Login Screen
```

### Architectural Division of Responsibility

| Component | Technology | Responsibility |
|---|---|---|
| **Queue (FIFO)** | C11 (`queue.c/h`) | Circular array storing pending login attempts in memory ($O(1)$) |
| **Stack (LIFO)** | C11 (`stack.c/h`) | Array storing processed login attempts in reverse chronological order ($O(1)$) |
| **Brute-Force Detector** | C11 (`detector.c/h`) | Tracks failed attempts per IP; flags when consecutive failures $\ge 3$; resets on success |
| **Audit Database** | C11 (`database.c/h`) | Appends structured records to `database/login_database.txt` (Zero password leakage) |
| **User Authentication** | Python (`UserManager`) | Salted PBKDF2-HMAC-SHA256 (100k iterations) stored in `database/users.txt` |
| **Network IP Engine** | Python (`NetworkManager`) | Active route UDP socket detection (avoiding loopback/virtual adapters) + HTTPS WAN lookup |
| **Desktop UI** | Python Tkinter | Presentation layer, page transitions, responsive layouts, subprocess execution |

---

## 5. Accurate IP Address Detection

### 1. Active Route-Based Local IP Detection
- Traditional `socket.gethostbyname(socket.gethostname())` frequently resolves to inactive virtual adapters (Hyper-V / WSL / VMware) or loopback addresses.
- This application uses **kernel routing table queries** via UDP socket connects to public DNS targets (`8.8.8.8:80`, `1.1.1.1:80`, `9.9.9.9:80`).
- This queries the Windows IP stack to determine the exact network adapter currently holding the active default gateway, returning the genuine local LAN IP (e.g., `10.9.113.26` or `192.168.1.x`).

### 2. Public WAN IP Detection
- Resolves external gateway IP via reputable HTTPS providers (`api.ipify.org`, `icanhazip.com`, `checkip.amazonaws.com`) with a short 1.8-second timeout.
- Gracefully indicates "Unavailable (Offline)" if internet access is interrupted, continuing without interruption.

### 3. Clear IP Distinction & Operational Principle
- **Local Network IP**: Machine's interface on the private subnet.
- **Public WAN IP**: External gateway visible to the internet.
- **Simulated Test IP**: Configurable test IP address for simulating multi-client brute-force attacks.
- *Notice*: As a local desktop application, automatic detection inspects the host running the software. Multi-device remote brute-force testing can be performed using the "Simulated Test IP" feature.

---

## 6. DSA Viva Preparation Guide

### A. Core Data Structures

#### 1. Why use a Queue for Login Requests?
- **Concept**: A Queue operates on **FIFO (First In, First Out)**.
- **Application**: Incoming authentication requests are buffered in the order they arrive. This ensures fairness and prevents race conditions under traffic bursts.
- **Implementation**: Circular array using `front`, `rear`, and `count` with modulo arithmetic `(index + 1) % MAX_QUEUE`, achieving $O(1)$ enqueue and dequeue operations without memory drift.

#### 2. Why use a Stack for Activity History?
- **Concept**: A Stack operates on **LIFO (Last In, First Out)**.
- **Application**: Security administrators need to inspect recent events starting from the most recent. The latest attempt is pushed to `top`, allowing immediate $O(1)$ inspection via `peek()` or `pop()`.

#### 3. How does the Brute-Force Detection Algorithm work?
- For each attempt, C searches or creates an entry in an array of `IpRecord` structures.
- If status is **Failed**:
  - `consecutive_failures++`
  - If `consecutive_failures >= 3`:
    - Flags `is_suspicious = true`.
    - Triggers an alert if `!alert_reported` (preventing redundant repeated pop-ups for the same ongoing streak).
- If status is **Success**:
  - `consecutive_failures = 0` (resets consecutive counter).
  - Clears active threat status.

---

### B. High-Probability Viva Questions & Concise Answers

1. **Q: Why are there two separate text database files?**
   *A:* `database/users.txt` stores user account credentials with individual cryptographic salts and PBKDF2 hashes. `database/login_database.txt` stores the audit trail of login attempts (without passwords) for security compliance.

2. **Q: How are passwords stored and verified?**
   *A:* Passwords are never stored in plaintext. They are hashed using PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte random salt generated via `os.urandom(16)`. Verification uses constant-time comparison (`secrets.compare_digest`) to prevent timing attacks.

3. **Q: How does the application prevent duplicate username registrations?**
   *A:* When creating an account, `UserManager.register_user()` performs a case-insensitive lookup across existing records in `database/users.txt` and rejects duplicates.

4. **Q: Why does standard `gethostbyname()` sometimes return the wrong IP on Windows?**
   *A:* Machines with virtual network adapters (Docker, WSL, Hyper-V) or VPNs often register multiple interfaces. `gethostbyname()` may return the first adapter enumerated rather than the active interface routing internet traffic.

5. **Q: How did you solve the local IP detection problem?**
   *A:* By creating a UDP socket connection to an external address (`8.8.8.8:80`). The operating system routing table selects the socket's local address based on the active default route.

6. **Q: Where does the brute-force detection logic execute?**
   *A:* Exclusively in the C backend (`src/detector.c`). Python only collects input and displays the returned alert state.

7. **Q: What is the time complexity of enqueuing and dequeuing in your Queue?**
   *A:* Both are $O(1)$ because the circular array uses direct index pointer manipulation with modulo arithmetic without shifting array elements.

8. **Q: What is the time complexity of pushing and popping in your Stack?**
   *A:* Both are $O(1)$ as they only increment or decrement the top index and access a fixed array index.

9. **Q: How does C communicate with Python without opening console windows?**
   *A:* Python launches the compiled C binary via `subprocess.run()` using the `CREATE_NO_WINDOW` flag, capturing structured JSON output from `stdout`.

10. **Q: What happens if `users.txt` or `login_database.txt` is missing on startup?**
    *A:* The application automatically creates the files. `users.txt` is pre-populated with standard demo accounts (`admin`, `advait`, `student`) so the app is immediately usable.

---

## 7. Automated Test Suite Verification

Run the verification test script anytime:
```cmd
python test_verification.py
```
Output:
```
=== STARTING 12-POINT SYSTEM VERIFICATION ===
Test 1 - User Registration: ok=True
Test 2 - Existing User Login: auth_ok=True
Test 3 - Incorrect Credentials Rejected: not auth_fail=True
Test 4 - Duplicate Username Blocked: dup_ok=False
Test 5 - Active Local IP: 10.9.113.26 | Public IP: 103.4.221.252
Test 6 - Manual IP Recorded: IP=198.51.100.44, Source=Manual
Test 7 - 3 Failed Attempts Trigger Alert: Alert='ALERT: Brute-force pattern detected!...'
Test 8 - Success Resets Consecutive Counter: consecutive_failures=0
Test 9 - TXT Databases Active: login_database.txt, users.txt
Test 10a - Queue Enqueue in C: Queue count=1
Test 10b - Queue Dequeue in C: Last processed=queue_user
Test 10c - Stack Pop in C: Popped user=queue_user
Test 11 - Security Check: Passwords strictly hashed (PBKDF2) and never present in login_database.txt
Test 12 - App Launches Directly into Dedicated Login Page: AuthView active, Dashboard locked.
========================================================
  ALL 12 VERIFICATION TESTS PASSED SUCCESSFULLY (100%)!
========================================================
```
