import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
import socket
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import requests
import time
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

DISCOVERY_PORT = 9999
BROADCAST_INTERVAL = 5
class LocalDiscovery:
    def __init__(self, username, port, callback):
        self.username = username
        self.port = port
        self.callback = callback
        self.running = False
        self.peers = {} 
        self.sock = None
        
    def start(self):
        self.running = True
        
        broadcast_thread = threading.Thread(target=self.broadcast_presence, daemon=True)
        broadcast_thread.start()
        
        listen_thread = threading.Thread(target=self.listen_for_peers, daemon=True)
        listen_thread.start()
    
    def broadcast_presence(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        while self.running:
            try:
                message = json.dumps({
                    'type': 'presence',
                    'username': self.username,
                    'port': self.port
                })
                sock.sendto(message.encode(), ('<broadcast>', DISCOVERY_PORT))
            except Exception as e:
                pass
            time.sleep(BROADCAST_INTERVAL)
        
        sock.close()
    
    def listen_for_peers(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind(('', DISCOVERY_PORT))
        except:
            return
        
        self.sock.settimeout(1.0)
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                message = json.loads(data.decode())
                
                if message['type'] == 'presence':
                    peer_username = message['username']
                    peer_port = message['port']
                    peer_ip = addr[0]
                    
                    if peer_username != self.username:
                        self.peers[peer_username] = {
                            'ip': peer_ip,
                            'port': peer_port,
                            'last_seen': time.time()
                        }
                        self.callback(f"[DISCOVERY] Found peer: @{peer_username} at {peer_ip}:{peer_port}")
            except socket.timeout:
                continue
            except Exception as e:
                pass
        
        if self.sock:
            self.sock.close()
    
    def find_peer(self, username):
        current_time = time.time()
        self.peers = {u: p for u, p in self.peers.items() 
                     if current_time - p['last_seen'] < 30}
        
        if username in self.peers:
            return self.peers[username]
        return None
    
    def stop(self):
        self.running = False


class ChatServer:
    def __init__(self, port, callback):
        self.app = Flask(__name__)
        self.port = port
        self.callback = callback
        self.access_code = None
        self.cipher = None
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/', methods=['GET'])
        def index():
            return jsonify({'status': 'chat_server_running'}), 200
        
        @self.app.route('/ping', methods=['GET'])
        def ping():
            return jsonify({'status': 'online', 'service': 'encrypted_chat'}), 200
        
        @self.app.route('/send_message', methods=['POST'])
        def receive_message():
            try:
                data = request.json
                if not data:
                    return jsonify({'status': 'error', 'message': 'No data'}), 400
                
                encrypted_msg = data.get('message')
                sender = data.get('sender')
                
                if not encrypted_msg or not sender:
                    return jsonify({'status': 'error', 'message': 'Missing data'}), 400
                
                if not self.cipher:
                    return jsonify({'status': 'error', 'message': 'Not ready'}), 400
                
                decrypted = self.cipher.decrypt(encrypted_msg.encode()).decode()
                self.callback(f"@{sender}: {decrypted}")
                
                return jsonify({'status': 'success'}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 400
        
        @self.app.route('/verify_access', methods=['POST'])
        def verify_access():
            try:
                data = request.json
                code = data.get('code')
                
                if code == self.access_code:
                    return jsonify({'status': 'success', 'verified': True}), 200
                else:
                    return jsonify({'status': 'error', 'verified': False}), 401
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 400
    
    def set_access_code(self, code):
        self.access_code = code
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'encrypted_chat_salt',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(code.encode()))
        self.cipher = Fernet(key)
    
    def start(self):
        self.app.run(host='0.0.0.0', port=self.port, debug=False, use_reloader=False, threaded=True)


class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Encrypted Chat")
        self.root.geometry("900x750")
        
        self.username = None
        self.server_port = 5000
        self.server_thread = None
        self.chat_server = None
        self.discovery = None
        self.cipher = None
        self.connected_username = None
        self.connected_ip = None
        self.connected_port = None
        self.my_ip = self.get_local_ip()
        self.access_verified = False
        self.running = True
        
        self.setup_ui()
        self.show_account_setup()
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return " "
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        account_frame = ttk.LabelFrame(main_frame, text="My Account", padding="10")
        account_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(account_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.username_label = ttk.Label(account_frame, text="Not logged in", foreground="red", font=('Arial', 10, 'bold'))
        self.username_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(account_frame, text="Network:").grid(row=0, column=2, sticky=tk.W, padx=10)
        self.network_label = ttk.Label(account_frame, text=f"📶 {self.my_ip}", foreground="blue", font=('Arial', 9))
        self.network_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(account_frame, text="Status:").grid(row=0, column=4, sticky=tk.W, padx=10)
        self.status_label = ttk.Label(account_frame, text="● Offline", foreground="red", font=('Arial', 9, 'bold'))
        self.status_label.grid(row=0, column=5, sticky=tk.W, padx=5)
        
        self.change_account_btn = ttk.Button(account_frame, text="Change Account", command=self.show_account_setup)
        self.change_account_btn.grid(row=0, column=6, padx=10)

        server_frame = ttk.LabelFrame(main_frame, text="Server Control", padding="10")
        server_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(server_frame, text="Port:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.port_entry = ttk.Entry(server_frame, width=8)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(server_frame, text="Access Code:").grid(row=0, column=2, sticky=tk.W, padx=10)
        self.create_code_entry = ttk.Entry(server_frame, width=20, show="*")
        self.create_code_entry.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        self.show_code_var = tk.BooleanVar()
        ttk.Checkbutton(server_frame, text="Show", variable=self.show_code_var,
                       command=lambda: self.create_code_entry.config(show="" if self.show_code_var.get() else "*")).grid(row=0, column=4, padx=5)
        
        self.start_server_btn = ttk.Button(server_frame, text="🌐 Go Online", command=self.go_online, state='disabled')
        self.start_server_btn.grid(row=0, column=5, padx=10)
        
        self.server_status_label = ttk.Label(server_frame, text="● Server: Offline", foreground="red", font=('Arial', 9, 'bold'))
        self.server_status_label.grid(row=0, column=6, padx=5)
        
        peers_frame = ttk.LabelFrame(main_frame, text="📡 Discovered Peers", padding="10")
        peers_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        peers_container = ttk.Frame(peers_frame)
        peers_container.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.peers_listbox = tk.Listbox(peers_container, height=4, font=('Consolas', 9))
        self.peers_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        scrollbar = ttk.Scrollbar(peers_container, orient="vertical", command=self.peers_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.peers_listbox.configure(yscrollcommand=scrollbar.set)
        
        peers_container.columnconfigure(0, weight=1)
        
        self.refresh_peers_btn = ttk.Button(peers_frame, text="🔄 Refresh", command=self.refresh_peers)
        self.refresh_peers_btn.grid(row=1, column=0, pady=5, sticky=tk.W)
        
        connect_frame = ttk.LabelFrame(main_frame, text="Connect to Friend", padding="10")
        connect_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(connect_frame, text="Friend Username:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_username_entry = ttk.Entry(connect_frame, width=25, font=('Arial', 10))
        self.target_username_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(connect_frame, text="Access Code:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.access_code_entry = ttk.Entry(connect_frame, width=25, show="*")
        self.access_code_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        self.show_access_var = tk.BooleanVar()
        ttk.Checkbutton(connect_frame, text="Show", variable=self.show_access_var,
                       command=lambda: self.access_code_entry.config(show="" if self.show_access_var.get() else "*")).grid(row=1, column=2, padx=5)
        
        self.connect_btn = ttk.Button(connect_frame, text="🔗 Connect", command=self.connect_to_friend, state='disabled')
        self.connect_btn.grid(row=1, column=3, padx=10)
        
        self.connection_status = ttk.Label(connect_frame, text="● Not Connected", foreground="red", font=('Arial', 9, 'bold'))
        self.connection_status.grid(row=0, column=3, padx=10)
        
        # Chat Frame
        chat_frame = ttk.LabelFrame(main_frame, text="💬 Chat", padding="10")
        chat_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.chat_display = scrolledtext.ScrolledText(chat_frame, height=20, state='disabled', wrap=tk.WORD, font=('Consolas', 9))
        self.chat_display.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        input_frame = ttk.Frame(chat_frame)
        input_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.message_entry = ttk.Entry(input_frame, font=('Arial', 10))
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ttk.Button(input_frame, text="📤 Send", command=self.send_message, state='disabled')
        self.send_btn.grid(row=0, column=1, padx=5)
        
        self.clear_btn = ttk.Button(input_frame, text="🗑️ Clear", command=self.clear_chat)
        self.clear_btn.grid(row=0, column=2, padx=5)
        
        input_frame.columnconfigure(0, weight=1)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.auto_refresh_peers()
    
    def show_account_setup(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Account Setup")
        dialog.geometry("450x220")
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Create Your Username", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="This username will be visible on local network (1 Wi-Fi)", 
                 font=('Arial', 8), foreground="gray").grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky=tk.W, pady=10)
        username_entry = ttk.Entry(frame, width=25, font=('Arial', 10))
        username_entry.grid(row=2, column=1, pady=10, padx=10)
        username_entry.focus()
        
        ttk.Label(frame, text="(Will be used for local discovery)", 
                 font=('Arial', 8), foreground="gray").grid(row=3, column=1, sticky=tk.W, padx=10)
        
        def save_username():
            username = username_entry.get().strip().lower()
            if not username:
                messagebox.showerror("Error", "Please enter a username!")
                return
            
            if len(username) < 3:
                messagebox.showerror("Error", "Username must be at least 3 characters!")
                return
            
            if not username.replace('_', '').isalnum():
                messagebox.showerror("Error", "Username must be alphanumeric (underscore allowed)!")
                return
            
            self.username = username
            self.username_label.config(text=f"@{username}", foreground="blue")
            self.start_server_btn.config(state='normal')
            self.connect_btn.config(state='normal')
            
            dialog.destroy()
        
        ttk.Button(frame, text="✅ Create Account", command=save_username).grid(row=4, column=0, columnspan=2, pady=20)
        
        username_entry.bind('<Return>', lambda e: save_username())
    
    def go_online(self):
        if not self.username:
            messagebox.showerror("Error", "Please create an account first!")
            return
        
        access_code = self.create_code_entry.get().strip()
        if not access_code:
            messagebox.showerror("Error", "Please enter an access code!")
            return
        
        if len(access_code) < 6:
            messagebox.showerror("Error", "Access code must be at least 6 characters!")
            return
        
        try:
            self.server_port = int(self.port_entry.get())
            
            self.chat_server = ChatServer(self.server_port, self.receive_message_callback)
            self.chat_server.set_access_code(access_code)
            
            self.server_thread = threading.Thread(target=self.chat_server.start, daemon=True)
            self.server_thread.start()
            time.sleep(0.5)
            
            self.discovery = LocalDiscovery(self.username, self.server_port, lambda msg: None)
            self.discovery.start()
            
            self.server_status_label.config(text="● Server: Online", foreground="green")
            self.status_label.config(text="● Online", foreground="green")
            self.start_server_btn.config(state='disabled')
            self.create_code_entry.config(state='disabled')
            self.port_entry.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to go online:\n{str(e)}")
    
    def refresh_peers(self):
        if not self.discovery:
            return
        
        self.peers_listbox.delete(0, tk.END)
        
        if not self.discovery.peers:
            self.peers_listbox.insert(tk.END, "  No peers found yet... (waiting for broadcasts)")
            return
        
        for username, info in self.discovery.peers.items():
            peer_text = f"  👤 @{username} - {info['ip']}:{info['port']}"
            self.peers_listbox.insert(tk.END, peer_text)
    
    def auto_refresh_peers(self):
        if self.running:
            self.refresh_peers()
            self.root.after(3000, self.auto_refresh_peers)
    
    def connect_to_friend(self):
        if not self.username:
            messagebox.showerror("Error", "Please create an account first!")
            return
        
        if not self.discovery:
            messagebox.showerror("Error", "Please go online first!")
            return
        
        friend_username = self.target_username_entry.get().strip().lower()
        access_code = self.access_code_entry.get().strip()
        
        if not friend_username or not access_code:
            messagebox.showerror("Error", "Please enter username and access code!")
            return
        
        if friend_username == self.username:
            messagebox.showerror("Error", "You cannot connect to yourself!")
            return
        
        peer = self.discovery.find_peer(friend_username)
        
        if not peer:
            messagebox.showerror("Error", f"User '@{friend_username}' not found!\n\nMake sure:\n1. They are online\n2. Same Wi-Fi network\n3. Their app is running")
            return
        
        target_ip = peer['ip']
        target_port = peer['port']
        
        try:
            test_response = requests.get(f"http://{target_ip}:{target_port}/ping", timeout=5)
            
            if test_response.status_code != 200:
                messagebox.showerror("Error", "Peer is not responding!")
                return
            
            verify_response = requests.post(f"http://{target_ip}:{target_port}/verify_access",
                                           json={'code': access_code}, timeout=5)
            
            if verify_response.status_code == 200:
                result = verify_response.json()
                if result.get('verified'):
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=b'encrypted_chat_salt',
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(access_code.encode()))
                    self.cipher = Fernet(key)
                    
                    self.connected_username = friend_username
                    self.connected_ip = target_ip
                    self.connected_port = target_port
                    self.access_verified = True
                    
                    self.connection_status.config(text=f"● Connected: @{friend_username}", foreground="green")
                    self.connect_btn.config(state='disabled')
                    self.target_username_entry.config(state='disabled')
                    self.access_code_entry.config(state='disabled')
                    self.send_btn.config(state='normal')
                    self.message_entry.focus()
                else:
                    messagebox.showerror("Error", "Invalid access code!")
            else:
                messagebox.showerror("Error", "Access verification failed!")
                
        except requests.exceptions.Timeout:
            messagebox.showerror("Error", f"Connection timeout!\n\nPeer may be:\n- Behind firewall\n- Port blocked\n- Not responding")
        except requests.exceptions.ConnectionError:
            messagebox.showerror("Error", f"Cannot connect to peer!\n\nCheck:\n1. Peer is online\n2. Firewall settings\n3. Port {target_port} is open")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed:\n{str(e)}")
    
    def send_message(self):
        if not self.access_verified:
            messagebox.showerror("Error", "Not connected!")
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                encrypted = self.cipher.encrypt(message.encode()).decode()
                url = f"http://{self.connected_ip}:{self.connected_port}/send_message"
                
                response = requests.post(url, json={
                    'message': encrypted,
                    'sender': self.username
                }, timeout=5)
                
                if response.status_code == 200:
                    timestamp = time.strftime("%H:%M:%S")
                    self.add_message(f"[{timestamp}] @{self.username}: {message}")
                    self.message_entry.delete(0, tk.END)
                    return 
                else:
                    return
                    
            except requests.exceptions.Timeout:
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(1)
                else:
                    messagebox.showerror("Error", 
                        "Connection timeout!\n\n" +
                        "Possible causes:\n" +
                        "1. Firewall blocking connection\n" +
                        "2. Peer's server not responding\n" +
                        "3. Network issue\n\n" +
                        f"Try: Open Windows Firewall and allow port {self.connected_port}")
                    return
                    
            except requests.exceptions.ConnectionError:
                messagebox.showerror("Error", 
                    f"Cannot connect to {self.connected_ip}:{self.connected_port}\n\n" +
                    "SOLUTION:\n" +
                    "1. Turn off Windows Firewall temporarily, OR\n" +
                    "2. Run this command in PowerShell (as Admin):\n\n" +
                    f"netsh advfirewall firewall add rule name=\"P2P Chat\" dir=in action=allow protocol=TCP localport={self.connected_port}")
                return
                
            except Exception as e:
                messagebox.showerror("Error", f"Send failed:\n{str(e)}")
                return
    
    def receive_message_callback(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.add_message(f"[{timestamp}] {message}")
    
    def add_message(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')
    
    def clear_chat(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state='disabled')
    
    def on_closing(self):
        self.running = False
        if self.discovery:
            self.discovery.stop()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()
