# Secure System Call Interface (CSE 316 - Operating Systems)

## Project Overview
This project implements a secure Graphical User Interface (GUI) to restrict and audit system command execution, addressing fundamental concepts of access control and process management within an Operating System environment.

**Student ID:** NIRAJ-0007
**Project Status:** FINALIZED (Revision 7 Complete)

## Security Features & Principles
The application incorporates several layers of security:

1.  **Access Control (Whitelisting):** All commands are filtered against a strict **Command Whitelist** (e.g., allows `ls`, `date`, `pwd`, `cat` but blocks critical system commands).
2.  **Multi-Factor Authentication (MFA) Readiness:**
    * **Password:** Uses secure `bcrypt` hashing for PIN verification.
    * **CAPTCHA:** Implements an arithmetic challenge to prevent basic brute-force attempts.
    * **Biometrics:** Includes a UI placeholder for future Facial Recognition integration.
3.  **Auditing & Non-Repudiation:** Every command attempt, whether successful or unauthorized, is logged to `secure_call_log.txt` with a timestamp.

## How to Run the Project
1.  **Prerequisites:** You need Python 3 installed. The application uses only standard Python libraries (`tkinter`, `subprocess`, `bcrypt`, etc.).
2.  **Execution:** Run the main script from your terminal:
    ```bash
    python3 secure_syscall_tkinter.py
    ```
3.  **Login PIN:** `1234` (This PIN is stored as a bcrypt hash in the code).

## Revision Tracking (Git Workflow)
This project was developed using a branch-based workflow (simulated for features) and finalized through **7 distinct, verifiable revisions**, demonstrating adherence to the project submission guidelines.

---
