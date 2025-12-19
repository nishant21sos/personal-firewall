import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import os
import signal

LOG_FILE = "firewall_log.csv"
FIREWALL_CMD = ["sudo", "./venv/bin/python", "firewall.py"]

firewall_process = None

def start_firewall():
    global firewall_process
    if firewall_process is None:
        try:
            firewall_process = subprocess.Popen(FIREWALL_CMD)
            status_label.config(text="Status: Running", foreground="green")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showinfo("Info", "Firewall is already running")

def stop_firewall():
    global firewall_process
    if firewall_process:
        firewall_process.send_signal(signal.SIGTERM)
        firewall_process = None
        status_label.config(text="Status: Stopped", foreground="red")
    else:
        messagebox.showinfo("Info", "Firewall is not running")

def load_logs():
    log_box.config(state="normal")
    log_box.delete("1.0", tk.END)

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            log_box.insert(tk.END, f.read())
    else:
        log_box.insert(tk.END, "Log file not found.\nRun the firewall to generate logs.")

    log_box.config(state="disabled")

# ---------------- GUI WINDOW ---------------- #

root = tk.Tk()
root.title("Personal Firewall – Log Monitor")
root.geometry("900x520")
root.resizable(False, False)

style = ttk.Style()
style.theme_use("clam")

# ---------------- HEADER ---------------- #

header = ttk.Label(
    root,
    text="Personal Firewall Dashboard",
    font=("Segoe UI", 16, "bold")
)
header.pack(pady=15)

# ---------------- STATUS ---------------- #

status_label = ttk.Label(
    root,
    text="Status: Stopped",
    font=("Segoe UI", 11),
    foreground="red"
)
status_label.pack(pady=5)

# ---------------- BUTTONS ---------------- #

btn_frame = ttk.Frame(root)
btn_frame.pack(pady=10)

start_btn = ttk.Button(btn_frame, text="Start Firewall", command=start_firewall)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = ttk.Button(btn_frame, text="Stop Firewall", command=stop_firewall)
stop_btn.grid(row=0, column=1, padx=10)

refresh_btn = ttk.Button(btn_frame, text="Refresh Logs", command=load_logs)
refresh_btn.grid(row=0, column=2, padx=10)

# ---------------- LOG VIEWER ---------------- #

log_label = ttk.Label(root, text="Current Firewall Logs", font=("Segoe UI", 12, "bold"))
log_label.pack(pady=10)

log_box = scrolledtext.ScrolledText(
    root,
    width=100,
    height=18,
    font=("Consolas", 9),
    state="disabled"
)
log_box.pack(padx=10)

try:
    root.mainloop()
except KeyboardInterrupt:
    pass

