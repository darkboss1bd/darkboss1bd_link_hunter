import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import re
import os
import platform
import time

# Main Application
class DarkBossLinkHunter:
    def __init__(self, root):
        self.root = root
        self.root.title("DarkBoss1BD - File Link Hunter")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#0e0e0e")

        # Icon (optional) - you can add a .ico file
        # root.iconbitmap('icon.ico')

        self.setup_gui()
        self.hacker_animation()

    def setup_gui(self):
        # Banner
        banner_frame = tk.Frame(self.root, bg="#00ff00", height=40)
        banner_frame.pack(fill="x")
        banner_label = tk.Label(banner_frame, text="DARKBOSS1BD", font=("Courier", 16, "bold"),
                                bg="#00ff00", fg="#000000")
        banner_label.pack()

        # Title
        title = tk.Label(self.root, text="File Link Hunter", font=("Consolas", 20, "bold"),
                         bg="#0e0e0e", fg="#00ff00")
        title.pack(pady=10)

        # Description
        desc = tk.Label(self.root, text="Detect hidden links in any file (Windows, Linux, Mac)",
                        font=("Arial", 10), bg="#0e0e0e", fg="#aaaaaa")
        desc.pack(pady=5)

        # Button Frame
        btn_frame = tk.Frame(self.root, bg="#0e0e0e")
        btn_frame.pack(pady=10)

        self.browse_btn = tk.Button(btn_frame, text="🔍 Browse File", font=("Arial", 12),
                                    bg="#1a1a1a", fg="#00ff00", activebackground="#00ff00",
                                    activeforeground="#000000", width=15, command=self.browse_file)
        self.browse_btn.grid(row=0, column=0, padx=10)

        self.scan_btn = tk.Button(btn_frame, text="⚡ Scan Now", font=("Arial", 12),
                                  bg="#1a1a1a", fg="#00ff00", activebackground="#00ff00",
                                  activeforeground="#000000", width=15, command=self.scan_file)
        self.scan_btn.grid(row=0, column=1, padx=10)

        # Output Area
        result_label = tk.Label(self.root, text="🔍 Scan Results:", font=("Consolas", 12),
                                bg="#0e0e0e", fg="#00ff00")
        result_label.pack(anchor="w", padx=20)

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=20,
                                                     bg="#111111", fg="#00ff00",
                                                     insertbackground="#00ff00",
                                                     font=("Consolas", 10),
                                                     selectbackground="#005500")
        self.result_text.pack(fill="both", expand=True, padx=20, pady=10)

        self.file_path = None

    def hacker_animation(self):
        lines = [
            "Initializing DarkBoss1BD System...",
            "Bypassing security protocols...",
            "Loading advanced link detection module...",
            "Connecting to deep file layers...",
            "Ready for stealth scanning...",
            ">> DarkBoss1BD - Active & Loaded\n"
        ]
        self.result_text.config(state=tk.NORMAL)
        for line in lines:
            self.result_text.insert(tk.END, line + "\n")
            self.result_text.see(tk.END)
            self.root.update()
            time.sleep(0.3)
        self.result_text.config(state=tk.DISABLED)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(
            title="Select a File",
            filetypes=(("All Files", "*.*"),)
        )
        if self.file_path:
            messagebox.showinfo("File Selected", f"File: {os.path.basename(self.file_path)}")
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"[✓] File loaded: {self.file_path}\n\n")
            self.result_text.config(state=tk.DISABLED)

    def scan_file(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a file first!")
            return

        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"🔍 Scanning: {self.file_path}\n")
        self.result_text.insert(tk.END, f"Platform: {platform.system()}\n")
        self.result_text.insert(tk.END, "-" * 50 + "\n\n")

        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()

            # Decode as text (utf-8 or fallback)
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = content.decode('latin-1', errors='ignore')

            findings = []

            # 1. URLs
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, text_content)
            if urls:
                findings.append(("🌐 URLs Found", urls))

            # 2. File Paths (Windows, Linux, Mac)
            win_path = r'[a-zA-Z]:\\[\\\S]+[\\\w.]+'
            linux_mac_path = r'/(?:[^/\s]+/)*[^/\s]*'
            win_paths = re.findall(win_path, text_content)
            linux_paths = re.findall(linux_mac_path, text_content)
            if win_paths:
                findings.append(("📁 Windows Paths", win_paths))
            if linux_paths:
                # Filter out common false positives
                filtered = [p for p in linux_paths if len(p) > 5 and p.count('/') > 1]
                if filtered:
                    findings.append(("📁 Unix/Mac Paths", filtered))

            # 3. Symbolic Links or Shortcuts (indicators)
            shortcut_indicators = [
                b'\x4C\x00\x00\x00',  # Windows .lnk magic bytes
                b'SICC',  # Possible Mac alias
            ]
            for magic in shortcut_indicators:
                if magic in content:
                    findings.append(("🔗 Hidden Shortcut Detected", [f"Binary signature: {magic.hex()}"]))

            # 4. System-specific clues
            system_clues = {
                "Windows": [r'\.exe', r'\.dll', r':\\Windows\\'],
                "Linux": [r'/bin/', r'/etc/', r'/home/'],
                "Mac": [r'/Applications/', r'/Users/', r'CFBundle']
            }

            for sys, patterns in system_clues.items():
                for pattern in patterns:
                    matches = re.findall(pattern, text_content, re.IGNORECASE)
                    if matches:
                        findings.append((f"🎯 Possible {sys} Traces", matches))

            # Display Findings
            if findings:
                for category, items in findings:
                    self.result_text.insert(tk.END, f"{category}:\n", "highlight")
                    for item in set(items):
                        self.result_text.insert(tk.END, f"  → {item}\n")
                    self.result_text.insert(tk.END, "\n")

                self.result_text.tag_config("highlight", foreground="#00ffff", font=("Consolas", 10, "bold"))
            else:
                self.result_text.insert(tk.END, "✅ No hidden links or system-specific paths found.\n")

        except Exception as e:
            self.result_text.insert(tk.END, f"❌ Error reading file: {str(e)}\n")

        self.result_text.config(state=tk.DISABLED)

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = DarkBossLinkHunter(root)
    root.mainloop()