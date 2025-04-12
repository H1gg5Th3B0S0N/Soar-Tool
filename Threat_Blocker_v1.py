import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import re
from datetime import datetime
from time import time
from collections import defaultdict

class ThreatBlocker:
    def __init__(self, root):

        self.root = root
        self.root.title("Threat Blocker")
        self.root.geometry("1000x600")

        self.monitoring_state = False
        self.blocked_ips = set()
        self.failed_attempts = defaultdict(list)

        self.label = tk.Label(self.root, text="Threat Blocker Dashboard", font=("Arial", 20))
        self.label.pack(padx=10, pady=10)

        self.monitoring_button = tk.Button(self.root, text="Start Monitoring", font=("Arial", 15),
                                           command=self.toggle_monitoring, bg="green", fg="white")
        self.monitoring_button.pack(padx=10, pady=10)

        # Table
        frame = tk.Frame(self.root)
        frame.pack(pady=10, fill="both", expand=True)

        self.tree = ttk.Treeview(frame, columns=("Time", "IP", "Incident", "Status", "Action"), show="headings")
        for col in ("Time", "IP", "Incident", "Status", "Action"):
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER, width=180)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        self.tree.bind("<Button-1>", self.on_tree_click)

        self.process = None

    def toggle_monitoring(self):
        self.monitoring_state = not self.monitoring_state
        if self.monitoring_state:
            self.monitoring_button.config(text="Stop Monitoring", bg="red")
            threading.Thread(target=self.monitor_logs, daemon=True).start()
            print("[*] Monitoring started...")
        else:
            self.monitoring_button.config(text="Start Monitoring", bg="green")
            print("[*] Monitoring stopped.")
            if self.process:
                self.process.terminate()
                self.process = None

    def monitor_logs(self):
        self.process = subprocess.Popen(["journalctl", "-f", "-o", "cat"],
                                        stdout=subprocess.PIPE, text=True)
        ssh_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")

        while self.monitoring_state:
            line = self.process.stdout.readline()
            if not line:
                break

            match = ssh_pattern.search(line)
            if match:
                ip = match.group(1)
                if self.is_malicious(ip):
                    if ip not in self.blocked_ips:
                        print(f"[!!] Blocking IP {ip} for repeated failed attempts.")
                        self.block_ip(ip)
                        self.root.after(0, self.add_to_table, ip, "Brute Force", "Blocked")
                else:
                    print(f"[>] Failed login from {ip} (tracking)")

    def is_malicious(self, ip):
        now = time()
        self.failed_attempts[ip].append(now)
        # Keep only last 60 seconds
        self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if now - t < 60]
        return len(self.failed_attempts[ip]) >= 5

    def add_to_table(self, ip, incident, status):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        action = "Unblock" if status == "Blocked" else "Block"

        # Prevent duplicate rows for same IP
        for child in self.tree.get_children():
            if self.tree.item(child)["values"][1] == ip:
                return

        self.tree.insert("", "end", values=(timestamp, ip, incident, status, action))

    def block_ip(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            self.blocked_ips.add(ip)
            print(f"[+] Blocked IP: {ip}")
        except subprocess.CalledProcessError:
            print(f"[x] Failed to block {ip}")
            messagebox.showerror("Error", f"Failed to block {ip}")

    def unblock_ip(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            self.blocked_ips.discard(ip)
            print(f"[-] Unblocked IP: {ip}")
        except subprocess.CalledProcessError:
            print(f"[x] Failed to unblock {ip}")
            messagebox.showerror("Error", f"Failed to unblock {ip}")

    def on_tree_click(self, event):
        item_id = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)

        if column == "#5" and item_id:
            values = self.tree.item(item_id, "values")
            ip = values[1]
            current_status = values[3]

            if current_status == "Blocked":
                self.unblock_ip(ip)
                new_status = "Allowed"
                new_action = ""
            else:
                self.block_ip(ip)
                new_status = "Blocked"
                new_action = "Unblock"

            self.tree.item(item_id, values=(values[0], ip, values[2], new_status, new_action))

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatBlocker(root)
    root.mainloop()