#!/usr/bin/env python3
"""
Secure System Call Demo - Tkinter GUI

This is a self-contained demo GUI that shows a simple secure syscall interface:
- Connects to an `authd` (Unix-domain socket) using length-prefixed JSON RPC
- Sends `inspect` and `revoked` requests
- If allowed, performs a very small set of operations (SC_OP_LIST_DATA, SC_OP_READ_FILE)
- Writes a signed audit line to a log file using HMAC-SHA256

NOTES
- This is a demo. Do NOT use as-is in production.
- Default paths (configurable in the app):
    AUTHD_SOCK = "/tmp/authd.sock"
    SECRET_PATH = "/tmp/authd_secret.key"
    AUDIT_LOG = "/var/log/secure_syscalls_demo.log"
- The app can optionally start an internal lightweight authd stub for local testing.

Run: python3 secure_syscall_tkinter.py

"""

import os
import sys
import json
import struct
import socket
import threading
import subprocess
import time
import hmac
import hashlib
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

# ----------------- Configuration -----------------
AUTHD_SOCK = "/tmp/authd.sock"
SECRET_PATH = "/tmp/authd_secret.key"
AUDIT_LOG = "/var/log/secure_syscalls_demo.log"
# Allowed operations in this demo
OPS = ["SC_OP_LIST_DATA", "SC_OP_READ_FILE"]

# ----------------- Helper functions -----------------

def send_length_prefixed(sockpath, reqobj, timeout=1.0):
    """Send JSON request (length-prefixed) to unix socket and return parsed JSON or raise."""
    data = json.dumps(reqobj).encode("utf-8")
    n = struct.pack("!I", len(data))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sockpath)
        s.sendall(n + data)
        # read 4 bytes length
        hdr = s.recv(4)
        if len(hdr) < 4:
            raise RuntimeError("short response header")
        resp_len = struct.unpack("!I", hdr)[0]
        buf = b""
        while len(buf) < resp_len:
            chunk = s.recv(resp_len - len(buf))
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf.decode("utf-8"))
    finally:
        try:
            s.close()
        except Exception:
            pass


def compute_hmac_hex(secret_bytes, payload_str):
    return hmac.new(secret_bytes, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()


def append_signed_audit(payload_obj, secret_path=SECRET_PATH, audit_path=AUDIT_LOG):
    # compact JSON
    payload_str = json.dumps(payload_obj, separators=(",", ":"))
    try:
        secret_bytes = Path(secret_path).read_bytes().strip()
        sig = compute_hmac_hex(secret_bytes, payload_str)
        entry = {"payload": payload_obj, "sig": sig}
    except Exception:
        # fallback: unsigned
        entry = payload_obj
    # ensure directory
    audit_dir = Path(audit_path).parent
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    # append
    try:
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        # On failure, ignore (GUI will show message)
        raise

# ----------------- Simple internal authd stub (for demo) -----------------
class AuthDStub(threading.Thread):
    """A minimal authd stub that responds to inspect and revoked.
       It runs in-process and writes to authd_log.
    """
    def __init__(self, sockpath=AUTHD_SOCK, allowed_ops=None):
        super().__init__(daemon=True)
        self.sockpath = sockpath
        self.allowed_ops = allowed_ops or ["SC_OP_LIST_DATA"]
        self._stop = threading.Event()
        self.log = []

    def run(self):
        try:
            try:
                os.unlink(self.sockpath)
            except FileNotFoundError:
                pass
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(self.sockpath)
            os.chmod(self.sockpath, 0o660)
            srv.listen(1)
            while not self._stop.is_set():
                try:
                    srv.settimeout(0.5)
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                try:
                    hdr = conn.recv(4)
                    if len(hdr) < 4:
                        conn.close(); continue
                    n = struct.unpack("!I", hdr)[0]
                    data = b""
                    while len(data) < n:
                        chunk = conn.recv(n - len(data))
                        if not chunk:
                            break
                        data += chunk
                    try:
                        req = json.loads(data.decode("utf-8"))
                    except Exception:
                        resp = {"valid": False}
                        out = json.dumps(resp).encode("utf-8")
                        conn.sendall(struct.pack("!I", len(out)) + out)
                        conn.close(); continue
                    # record
                    self.log.append(req)
                    cmd = req.get("cmd")
                    if cmd == "inspect":
                        resp = {"valid": True, "token": {"nonce": "demo-nonce", "allowed_ops": self.allowed_ops}}
                    elif cmd == "revoked":
                        resp = {"revoked": False}
                    else:
                        resp = {"valid": False}
                    out = json.dumps(resp).encode("utf-8")
                    conn.sendall(struct.pack("!I", len(out)) + out)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            try:
                os.unlink(self.sockpath)
            except Exception:
                pass

    def stop(self):
        self._stop.set()

# ----------------- GUI Application -----------------
class SecureSyscallGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure System Call - Demo GUI")
        self.geometry("800x520")
        self.authd = None

        # top frame for inputs
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill=tk.X)

        ttk.Label(frm, text="Token:").grid(row=0, column=0, sticky=tk.W)
        self.token_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.token_var, width=80).grid(row=0, column=1, columnspan=3, sticky=tk.W)

        ttk.Label(frm, text="Op:").grid(row=1, column=0, sticky=tk.W, pady=(6,0))
        self.op_var = tk.StringVar(value=OPS[0])
        ttk.Combobox(frm, textvariable=self.op_var, values=OPS, state="readonly", width=30).grid(row=1, column=1, sticky=tk.W, pady=(6,0))

        ttk.Label(frm, text="Arg:").grid(row=1, column=2, sticky=tk.W, pady=(6,0))
        self.arg_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.arg_var, width=30).grid(row=1, column=3, sticky=tk.W, pady=(6,0))

        # buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Inspect Token", command=self.inspect_token).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Execute", command=self.execute_op).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Generate Token (HMAC)", command=self.generate_token_from_payload).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Start AuthD Stub", command=self.start_authd_stub).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Stop AuthD Stub", command=self.stop_authd_stub).pack(side=tk.LEFT, padx=6)

        # result area
        res_frame = ttk.Frame(self)
        res_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(res_frame, text="Output / Audit Log / AuthD Log:").pack(anchor=tk.W)

        self.output = scrolledtext.ScrolledText(res_frame, wrap=tk.WORD, height=18)
        self.output.pack(fill=tk.BOTH, expand=True)

        # status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.BOTTOM, fill=tk.X)

        # ensure secret exists for demo
        if not Path(SECRET_PATH).exists():
            try:
                Path(SECRET_PATH).write_text("demo-secret")
                os.chmod(SECRET_PATH, 0o600)
                self.log("Created demo secret at %s" % SECRET_PATH)
            except Exception:
                pass

    # utility logging
    def log(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.output.insert(tk.END, f"[{ts}] {msg}\n")
        self.output.see(tk.END)

    # authd stub controls
    def start_authd_stub(self):
        if self.authd and self.authd.is_alive():
            self.log("AuthD stub already running")
            return
        self.authd = AuthDStub(allowed_ops=OPS)
        self.authd.start()
        self.log("Started internal AuthD stub on %s" % AUTHD_SOCK)
        self.status_var.set("AuthD: running")

    def stop_authd_stub(self):
        if self.authd:
            self.authd.stop()
            self.authd = None
            self.log("Stopped AuthD stub")
            self.status_var.set("AuthD: stopped")

    # GUI actions
    def inspect_token(self):
        token = self.token_var.get().strip()
        op = self.op_var.get()
        if not token:
            messagebox.showwarning("Input needed", "Token required")
            return
        req = {"cmd": "inspect", "token": token}
        try:
            resp = send_length_prefixed(AUTHD_SOCK, req)
            self.log(f"inspect -> {resp}")
            valid = resp.get("valid", False)
            if not valid:
                messagebox.showerror("Inspect failed", "Token invalid")
                return
            token_obj = resp.get("token", {})
            nonce = token_obj.get("nonce")
            allowed = token_obj.get("allowed_ops", [])
            if op in allowed:
                messagebox.showinfo("Inspect OK", f"Token valid for op {op}. nonce={nonce}")
            else:
                messagebox.showwarning("Not allowed", f"Token not allowed for op {op}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log(f"inspect error: {e}")

    def execute_op(self):
        token = self.token_var.get().strip()
        op = self.op_var.get()
        arg = self.arg_var.get().strip()
        if not token:
            messagebox.showwarning("Input needed", "Token required")
            return
        # Inspect first
        try:
            resp = send_length_prefixed(AUTHD_SOCK, {"cmd": "inspect", "token": token})
        except Exception as e:
            messagebox.showerror("AuthD error", f"inspect failed: {e}")
            self.log(f"inspect failed: {e}")
            return
        if not resp.get("valid"):
            messagebox.showerror("Denied", "Token invalid")
            return
        token_obj = resp.get("token", {})
        nonce = token_obj.get("nonce")
        allowed = token_obj.get("allowed_ops", [])
        if op not in allowed:
            messagebox.showerror("Denied", f"Op {op} not allowed by token")
            return
        # Check revocation
        try:
            rresp = send_length_prefixed(AUTHD_SOCK, {"cmd": "revoked", "nonce": nonce})
        except Exception as e:
            messagebox.showerror("AuthD error", f"revoked check failed: {e}")
            self.log(f"revoked check failed: {e}")
            return
        if rresp.get("revoked"):
            messagebox.showerror("Denied", "Token revoked")
            return

        # perform op (very small set)
        if op == "SC_OP_LIST_DATA":
            # sanitize arg
            clean = arg.lstrip("/")
            if ".." in clean:
                messagebox.showerror("Invalid arg", "Arg contains forbidden '..'")
                return
            target = os.path.join("/var/data", clean)
            if not target.startswith("/var/data"):
                messagebox.showerror("Invalid path", "Invalid path prefix")
                return
            # run ls safely
            try:
                out = subprocess.check_output(["ls", "-la", target], stderr=subprocess.STDOUT, timeout=5)
                self.log(f"Listing {target}\n{out.decode('utf-8')}")
                result = "OK"
                exitcode = 0
            except subprocess.CalledProcessError as e:
                self.log(f"ls failed: {e.output.decode('utf-8')}")
                result = f"LS_FAILED_{e.returncode}"
                exitcode = e.returncode
            except Exception as e:
                self.log(f"ls error: {e}")
                result = "LS_ERROR"
                exitcode = 255
        elif op == "SC_OP_READ_FILE":
            clean = arg.lstrip("/")
            if ".." in clean:
                messagebox.showerror("Invalid arg", "Arg contains forbidden '..'")
                return
            target = os.path.join("/var/data", clean)
            try:
                with open(target, "r", encoding="utf-8") as f:
                    contents = f.read()
                self.log(f"Read {target}:\n{contents}")
                result = "OK"
                exitcode = 0
            except Exception as e:
                self.log(f"read error: {e}")
                result = "READ_ERROR"
                exitcode = 255
        else:
            messagebox.showerror("Unsupported op", f"Op {op} not implemented in GUI")
            return

        # audit
        aud = {"ts": int(time.time()), "pid": os.getpid(), "op": op, "arg": arg, "nonce": nonce or "", "result": result}
        try:
            append_signed_audit(aud)
            self.log(f"Appended signed audit: {aud}")
        except Exception as e:
            self.log(f"Failed to append audit: {e}")

        self.status_var.set(f"Last op {op}: {result} (code {exitcode})")

    def generate_token_from_payload(self):
        # helper: generate HMAC hex token from payload (for demo)
        payload = json.dumps({"op": self.op_var.get(), "arg": self.arg_var.get()}, separators=(",", ":"))
        try:
            secret = Path(SECRET_PATH).read_bytes().strip()
            token = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
            self.token_var.set(token)
            self.log("Generated token (hex HMAC) from payload")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read secret: {e}")

# ----------------- main -----------------

def main():
    app = SecureSyscallGUI()
    app.mainloop()

if __name__ == '__main__':
    main()
