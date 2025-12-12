import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import datetime
import os
import bcrypt
import random
#import cv2 # You would need this for camera access
#import face_recognition # You would need this for facial recognition

# --- Configuration & Security ---

# 1. COMMAND WHITELISTING
WHITELISTED_COMMANDS = ["ls", "pwd", "date", "echo", "ping", "uptime"]

# 2. PASSWORD HASHING (PIN: 1234)
HASHED_PASSWORD = b'$2b$12$sr/FMB8Nn2b5OD2eTcXPauYGb//XWd/4LG/eXYCzB9CIy3QzwGUNG'
LOG_FILE = "secure_call_log.txt"
AUTHORIZED_USER = "SystemUser"

# --- Logging Function ---
def log_call(user, command, status):
    """Logs the system call attempt, status, and time to a file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] User: {user} | Command: '{command}' | Status: {status}"
    
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry + "\n")
        
    print(f"Logged: {status} for command: {command}")
    
    # Update the GUI log display
    app.update_log_display(log_entry, status)

# --- Main Application Class ---
class SecureCallInterface(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🌈 Secure System Call Interface")
        self.geometry("850x700")
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.current_user = None

        container = ttk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (LoginPage, MainInterface):
            page_name = F.__name__
            frame = F(parent=container, controller=self, style=self.style)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginPage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

    def login_successful(self):
        self.current_user = AUTHORIZED_USER
        self.show_frame("MainInterface")
        messagebox.showinfo("Login Success 🔓", f"Welcome, {self.current_user}! Security protocols engaged.")

    def update_log_display(self, new_entry, status="INFO"): 
        if "MainInterface" in self.frames and hasattr(self.frames["MainInterface"], 'log_text'):
            log_widget = self.frames["MainInterface"].log_text
            
            tag = 'info'
            if 'SUCCESS' in status:
                tag = 'success'
            elif 'Unauthorized' in status:
                tag = 'unauthorized'
            elif 'FAILED' in status:
                tag = 'error'
                
            log_widget.insert(tk.END, new_entry + "\n", tag)
            log_widget.see(tk.END)


# --- Login Page (Minimum Font 17) ---
class LoginPage(ttk.Frame):
    def __init__(self, parent, controller, style):
        ttk.Frame.__init__(self, parent)
        self.controller = controller
        
        # CAPTCHA Variables
        self.captcha_value = 0 
        self.captcha_expression = tk.StringVar() 

        style.configure('TFrame', background='#e8f0fe')
        # TLabels font size set to 17
        style.configure('TLabel', background='#e8f0fe', font=('Arial', 17)) 
        # Captcha Label font size set to 17
        style.configure('Captcha.TLabel', background='#f7f7f7', foreground='#2196F3', font=('Arial', 17, 'bold'), relief='raised')
        # Green Button font size set to 17
        style.configure('Green.TButton', background='#4CAF50', foreground='black', font=('Arial', 17, 'bold')) 
        style.map('Green.TButton', background=[('active', '#66BB6A')]) 
        # Blue Button font size set to 17
        style.configure('Blue.TButton', background='#03A9F4', foreground='black', font=('Arial', 17, 'bold'))
        style.map('Blue.TButton', background=[('active', '#4FC3F7')])
        
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        # Row 0: Title Label (18pt)
        ttk.Label(self, text="🔑 Secure Access System 🔑", font=("Arial", 18, "bold"), background='#2196F3', foreground='white', relief='raised').grid(row=0, column=0, columnspan=2, pady=(30, 20), sticky='ew', padx=20)

        # Row 1: PIN/Password Input
        ttk.Label(self, text="PIN/Password:", style='TLabel').grid(row=1, column=0, padx=10, pady=5, sticky="e")
        # Entry font size set to 17
        self.pin_entry = ttk.Entry(self, show="*", font=("Arial", 17), width=20) 
        self.pin_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Row 2: CAPTCHA Display
        ttk.Label(self, text="Security Check:", style='TLabel').grid(row=2, column=0, padx=10, pady=5, sticky="e")
        captcha_label = ttk.Label(self, textvariable=self.captcha_expression, style='Captcha.TLabel', width=20, anchor='center')
        captcha_label.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        
        # Row 3: CAPTCHA Input
        ttk.Label(self, text="Enter Answer:", style='TLabel').grid(row=3, column=0, padx=10, pady=5, sticky="e")
        # Entry font size set to 17
        self.captcha_entry = ttk.Entry(self, font=("Arial", 17), width=20) 
        self.captcha_entry.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        self.captcha_entry.bind('<Return>', lambda event: self.attempt_login())

        # Row 4: Login Options
        login_frame = ttk.Frame(self, style='TFrame')
        login_frame.grid(row=4, column=0, columnspan=2, pady=30)
        
        # Option A: PIN/CAPTCHA Login
        login_btn = ttk.Button(login_frame, text="🚀 Login via PIN/CAPTCHA", command=self.attempt_login, style='Green.TButton', cursor="hand2")
        login_btn.pack(side=tk.LEFT, padx=10, ipadx=10, ipady=5)

        # Option B: Facial Recognition Login
        face_btn = ttk.Button(login_frame, text="👤 Facial Scan Login (BETA)", command=self.attempt_face_login, style='Blue.TButton', cursor="hand2")
        face_btn.pack(side=tk.LEFT, padx=10, ipadx=10, ipady=5)
        
        self.generate_captcha()

    def generate_captcha(self):
        """Generates a simple arithmetic CAPTCHA (e.g., 5 + 3)."""
        num1 = random.randint(1, 9)
        num2 = random.randint(1, 9)
        operator = random.choice(['+', '-'])
        
        if operator == '+':
            self.captcha_value = num1 + num2
            expression = f"{num1} + {num2} = ?"
        else: # Subtraction
            if num1 < num2:
                num1, num2 = num2, num1
            self.captcha_value = num1 - num2
            expression = f"{num1} - {num2} = ?"
            
        self.captcha_expression.set(expression)

    def attempt_login(self):
        entered_pin = self.pin_entry.get().encode('utf-8')
        entered_captcha_str = self.captcha_entry.get().strip()
        
        try:
            entered_captcha = int(entered_captcha_str)
        except ValueError:
            messagebox.showerror("🛑 Access Denied", "Invalid CAPTCHA format. Please enter a number.")
            self.pin_entry.delete(0, tk.END)
            self.captcha_entry.delete(0, tk.END)
            self.generate_captcha()
            return
            
        # 1. CAPTCHA Check
        if entered_captcha != self.captcha_value:
            messagebox.showerror("🛑 Access Denied", "Invalid CAPTCHA answer. Security Alert Issued.")
            self.pin_entry.delete(0, tk.END)
            self.captcha_entry.delete(0, tk.END)
            self.generate_captcha() 
            return

        # 2. Password Check
        if bcrypt.checkpw(entered_pin, HASHED_PASSWORD):
            self.controller.login_successful()
        else:
            messagebox.showerror("🛑 Access Denied", "Invalid PIN/Password. Security Alert Issued.")
            self.pin_entry.delete(0, tk.END)
            self.captcha_entry.delete(0, tk.END)
            self.generate_captcha()

    def attempt_face_login(self):
        """Placeholder for actual facial recognition logic using OpenCV/face_recognition."""
        messagebox.showinfo("Facial Scan", "Starting camera... Please look at the camera for authentication.")
        
        # --- PLACEHOLDER LOGIC ---
        if random.random() > 0.5:
            messagebox.showinfo("Face Recognition", "Authentication successful! Face match confirmed.")
            self.controller.login_successful()
        else:
            messagebox.showerror("Face Recognition", "Face not recognized or verification failed. Access denied.")
            self.generate_captcha() 

# --- Main Interface (Minimum Font 17) ---
class MainInterface(ttk.Frame):
    def __init__(self, parent, controller, style):
        ttk.Frame.__init__(self, parent)
        self.controller = controller
        
        self.command_history = []
        self.history_index = -1 

        style.configure('Main.TFrame', background='#F5F5F5')
        style.configure('Red.TButton', background='#F44336', foreground='black')
        style.map('Red.TButton', background=[('active', '#E57373')])
        
        # --- Interactive Status Bar ---
        self.status_var = tk.StringVar(value="Ready to accept secure commands...")
        self.status_label = ttk.Label(
            self, 
            textvariable=self.status_var, 
            font=('Arial', 17, 'italic'), # Font size set to 17
            foreground='blue', 
            anchor='w'
        )
        self.status_label.pack(fill='x', padx=10, pady=(5, 0))

        # --- Command Execution Section ---
        cmd_frame = ttk.LabelFrame(self, text="💻 Execute System Command (Whitelist Active)", padding=10, style='Main.TFrame')
        cmd_frame.pack(padx=10, pady=5, fill="x")

        # Label font size set to 17
        ttk.Label(cmd_frame, text="Command:", font=("Arial", 17, "bold")).grid(row=0, column=0, padx=5, pady=5, sticky="w") 
        
        # Entry font size set to 17
        self.command_entry = ttk.Entry(
            cmd_frame, 
            width=70,  
            font=("Courier", 17) 
        )
        self.command_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Bind Up/Down arrows for history
        self.command_entry.bind('<Up>', self.history_prev)
        self.command_entry.bind('<Down>', self.history_next)
        self.command_entry.bind('<Return>', lambda event: self.execute_command())


        # Execute Button font size set to 17
        ttk.Button(cmd_frame, text="✅ Execute & Log", command=self.execute_command, cursor="hand2", style='Green.TButton').grid(row=1, column=0, columnspan=2, pady=10, ipadx=20)
        
        cmd_frame.grid_columnconfigure(1, weight=1)

        # --- Output/Log Section ---
        output_frame = ttk.LabelFrame(self, text="📊 Command Output & Audit Trail", padding=10, style='Main.TFrame')
        output_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Label font size set to 17
        # First modified line (from previous turn): Removed "(Increased Area/Font)"
        ttk.Label(output_frame, text="Command Output:", font=("Arial", 17, "bold")).pack(anchor="w") 
        
        # Output font is 18
        self.output_text = tk.Text(
            output_frame, 
            height=10, 
            width=70, 
            font=("Courier", 18), 
            bg="#222222", 
            fg="#00FF00", 
            insertbackground="#00FF00"
        )
        self.output_text.pack(fill="x", pady=5)
        self.output_text.insert(tk.END, "System command output will appear here. Try 'ls; date'...\n")
        
        # Label font size set to 17
        # SECOND MODIFIED LINE: Removed "(Increased Font)" from the label text
        ttk.Label(output_frame, text="Security Audit Trail:", font=("Arial", 17, "bold")).pack(anchor="w", pady=(10, 0)) 
        
        # Log font is 17
        self.log_text = tk.Text(
            output_frame, 
            height=8, 
            width=70, 
            font=("Courier", 17), 
            bg="#1e3d59", 
            fg="#f0f0f0"
        )
        self.log_text.pack(fill="both", expand=True)
        
        # Configure tags for log styling
        self.log_text.tag_config('success', foreground='#00ff00') 	 # Bright Green for SUCCESS
        self.log_text.tag_config('error', foreground='#ff5555') 	 # Light Red for FAILED
        self.log_text.tag_config('unauthorized', foreground='#ffaa00')# Orange for Unauthorized
        self.log_text.tag_config('info', foreground='#f0f0f0') 	 # Default White/Grey for general info

        self.load_initial_log()
        
    def load_initial_log(self):
        """Loads the last few log entries on startup and applies tags."""
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()
            
            last_lines = [line.strip() for line in lines[-10:]]
            
            for line in last_lines:
                status = line.split("| Status: ")[-1]
                tag = 'info'
                if 'SUCCESS' in status: tag = 'success'
                elif 'Unauthorized' in status: tag = 'unauthorized'
                elif 'FAILED' in status: tag = 'error'
                
                self.log_text.insert(tk.END, line + "\n", tag)
            self.log_text.see(tk.END)


    def _is_command_whitelisted(self, command):
        """Checks if the command starts with one of the whitelisted prefixes."""
        first_word = command.split()[0].lower()
        
        for approved_cmd in WHITELISTED_COMMANDS:
            if first_word == approved_cmd:
                return True
        return False
        
    def history_prev(self, event):
        """Scrolls back through command history."""
        if not self.command_history:
            return
        
        if self.history_index == -1:
            self.history_index = len(self.command_history) - 1
        elif self.history_index > 0:
            self.history_index -= 1
        
        self.command_entry.delete(0, tk.END)
        self.command_entry.insert(0, self.command_history[self.history_index])
        return 'break' # Prevent default key binding action

    def history_next(self, event):
        """Scrolls forward through command history."""
        if not self.command_history:
            return
            
        if self.history_index != -1 and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index = -1 # Clear the entry at the end
            self.command_entry.delete(0, tk.END)
        
        return 'break' # Prevent default key binding action


    def execute_command(self):
        full_command_string = self.command_entry.get().strip()
        user = self.controller.current_user
        
        if not full_command_string:
            messagebox.showwarning("Input Error", "Please enter a command to execute.")
            return

        # Add to history
        if full_command_string not in self.command_history:
            self.command_history.append(full_command_string)
        self.history_index = -1 # Reset index after execution

        # Handle command chaining
        commands = [cmd.strip() for cmd in full_command_string.split(';') if cmd.strip()]
        
        self.output_text.delete(1.0, tk.END)
        overall_status = "SUCCESS"
        
        for i, command in enumerate(commands):
            # --- WHITELIST CHECK ---
            if not self._is_command_whitelisted(command):
                status = "FAILED (Unauthorized Command)"
                log_call(user, command, status)
                self.output_text.insert(tk.END, f"\n--- Command {i+1} of {len(commands)}: '{command}' ---\n")
                self.output_text.insert(tk.END, f"🚫 ERROR: The command '{command.split()[0]}' is not on the approved whitelist. Access denied.\n")
                overall_status = "FAILED (Unauthorized)"
                break # Stop execution on first unauthorized command

            self.output_text.insert(tk.END, f"\n$ Executing command {i+1} of {len(commands)}: {command}\n")

            try:
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    check=False
                )

                if result.returncode == 0:
                    status = "SUCCESS"
                    output_message = f"\t[OK] Return Code: 0\n{result.stdout.strip()}\n"
                    log_call(user, command, status)
                    self.output_text.insert(tk.END, output_message)
                else:
                    status = f"FAILED (Code: {result.returncode})"
                    output_message = f"\t[ERROR] Command FAILED. Code: {result.returncode}\n{result.stderr.strip()}\n"
                    log_call(user, command, status)
                    self.output_text.insert(tk.END, output_message, 'error')
                    overall_status = "FAILED (Execution)"
                    
            except Exception as e:
                status = f"FAILED (Internal Error)"
                log_call(user, command, status)
                self.output_text.insert(tk.END, f"🛑 An unexpected internal error occurred: {e}\n", 'error')
                overall_status = "FAILED (Internal)"
                break

        self.command_entry.delete(0, tk.END)
        
        # Update final status bar based on overall result
        if "SUCCESS" in overall_status:
            self.status_var.set(f"✅ All {len(commands)} commands executed successfully and logged.")
            self.status_label.configure(foreground='green')
        elif "Unauthorized" in overall_status:
            self.status_var.set("🚨 SECURITY ALERT: Unauthorized command blocked and logged.")
            self.status_label.configure(foreground='red')
        else: # FAILED (Execution) or FAILED (Internal)
            self.status_var.set("❌ Execution Failed. Check output for details.")
            self.status_label.configure(foreground='red')


if __name__ == "__main__":
    # Ensure all spaces are standard before running
    app = SecureCallInterface()
    app.mainloop()
