import scapy.all as scapy
import threading
import time
import datetime
import os
import subprocess
import logging
import sqlite3
import platform

class IntrusionDetectionSystem:
    def __init__(self):
        self.running = False
        self.sniff_thread = None
        self.blocked_ips = set()
        self.port_scan_data = {}    # { ip: [(timestamp, dest_port), ...] }
        self.fingerprint_data = {}  # { ip: [(timestamp, flag_combo), ...] }
        self.syn_flood_data = {}    # { ip: [timestamp, ...] }
        self.live_traffic = []      # List to store captured packet summaries for live view
        self.lock = threading.Lock()

        # Get the local IP for filtering incoming traffic
        self.local_ip = scapy.get_if_addr(scapy.conf.iface)

        # Configure logging to file (ids.log) with the required format
        logging.basicConfig(
            filename="ids.log",
            level=logging.INFO,
            format="%(asctime)s — %(message)s",
            datefmt="%d-%m-%y %H:%M:%S"
        )

        # Initialize SQLite DB for bonus logging feature
        self.init_database()

    def init_database(self):
        self.conn = sqlite3.connect("ids.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS intrusions (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                date TEXT,
                                time TEXT,
                                intrusion_type TEXT,
                                attacker_ip TEXT,
                                details TEXT,
                                time_span TEXT)''')
        self.conn.commit()

    def log_to_db(self, intrusion_type, attacker_ip, details, time_span):
        now = datetime.datetime.now()
        date_str = now.strftime("%d-%m-%y")
        time_str = now.strftime("%H:%M:%S")
        self.cursor.execute(
            "INSERT INTO intrusions (date, time, intrusion_type, attacker_ip, details, time_span) VALUES (?, ?, ?, ?, ?, ?)",
            (date_str, time_str, intrusion_type, attacker_ip, details, time_span)
        )
        self.conn.commit()

    def send_alert(self, intrusion_type, attacker_ip, details):
        # Build the alert message
        alert_message = f"Intrusion Alert: {intrusion_type} detected\nAttacker IP: {attacker_ip}\nDetails: {details}\nTime: {datetime.datetime.now()}"
        print("Sending alert:")
        print(alert_message)
        # For Linux, we simply print the alert.
        # Alternatively, you could use a desktop notification system like notify-send.
        # Example (uncomment to use):
        # try:
        #     subprocess.run(['notify-send', 'Intrusion Alert', alert_message])
        # except Exception as e:
        #     print("Failed to send desktop notification:", e)

    def block_ip(self, ip):
        # Block an IP using iptables if not already blocked
        if ip in self.blocked_ips:
            return
        try:
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            print(f"Executing command: {cmd}")  # Debug print
            result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("Command output:", result.stdout.decode())
            self.blocked_ips.add(ip)
            print(f"Blocked IP: {ip}")
        except Exception as e:
            print(f"Failed to block IP {ip}: {e}")

    def unblock_ip(self, ip):
        # Unblock a previously blocked IP using iptables command
        if ip not in self.blocked_ips:
            print(f"IP {ip} is not in the block list.")
            return
        try:
            cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
            print(f"Executing command: {cmd}")  # Debug print
            result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("Command output:", result.stdout.decode())
            self.blocked_ips.remove(ip)
            print(f"Unblocked IP: {ip}")
        except Exception as e:
            print(f"Failed to unblock IP {ip}: {e}")

    def clear_block_list(self):
        # Unblock all blocked IPs
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)
        print("Cleared block list.")

    def process_packet(self, packet):
        # Process each captured packet and perform detection checks.
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            ip_layer = packet.getlayer(scapy.IP)
            tcp_layer = packet.getlayer(scapy.TCP)
            
            # Only process packets destined to the local IP (incoming traffic)
            if ip_layer.dst != self.local_ip:
                return
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            dst_port = tcp_layer.dport
            flags = tcp_layer.flags

            timestamp = time.time()
            summary = f"{datetime.datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')} - {src_ip} -> {dst_ip}:{dst_port} [Flags: {flags}]"
            with self.lock:
                self.live_traffic.append(summary)
                if len(self.live_traffic) > 50:
                    self.live_traffic.pop(0)

            # -------- Port Scanning Detection --------
            with self.lock:
                if src_ip not in self.port_scan_data:
                    self.port_scan_data[src_ip] = []
                self.port_scan_data[src_ip].append((timestamp, dst_port))
                self.port_scan_data[src_ip] = [(t, p) for (t, p) in self.port_scan_data[src_ip] if timestamp - t <= 15]
                ports = set(p for (t, p) in self.port_scan_data[src_ip])
                if len(ports) > 6:
                    intrusion_type = "Port Scanning"
                    details = f"Ports scanned: {ports}"
                    time_span = "15 seconds"
                    logging.info(f"{intrusion_type} — {src_ip} — {details} — {time_span}")
                    self.log_to_db(intrusion_type, src_ip, details, time_span)
                    self.send_alert(intrusion_type, src_ip, details)
                    self.block_ip(src_ip)
                    self.port_scan_data[src_ip] = []

            # -------- OS Fingerprinting Detection --------
            with self.lock:
                if src_ip not in self.fingerprint_data:
                    self.fingerprint_data[src_ip] = []
                flag_combo = tuple(sorted(set(str(flags))))
                self.fingerprint_data[src_ip].append((timestamp, flag_combo))
                self.fingerprint_data[src_ip] = [(t, f) for (t, f) in self.fingerprint_data[src_ip] if timestamp - t <= 20]
                distinct_flags = set(f for (t, f) in self.fingerprint_data[src_ip])
                if len(distinct_flags) >= 5:
                    intrusion_type = "OS Fingerprinting"
                    details = f"Flag combinations: {distinct_flags}"
                    time_span = "20 seconds"
                    logging.info(f"{intrusion_type} — {src_ip} — {details} — {time_span}")
                    self.log_to_db(intrusion_type, src_ip, details, time_span)
                    self.send_alert(intrusion_type, src_ip, details)
                    self.block_ip(src_ip)
                    self.fingerprint_data[src_ip] = []

            # -------- SYN Flood Detection --------
            if "S" in str(flags) and "A" not in str(flags):
                with self.lock:
                    if src_ip not in self.syn_flood_data:
                        self.syn_flood_data[src_ip] = []
                    self.syn_flood_data[src_ip].append(timestamp)
                    self.syn_flood_data[src_ip] = [t for t in self.syn_flood_data[src_ip] if timestamp - t <= 10]
                    if len(self.syn_flood_data[src_ip]) > 20:
                        intrusion_type = "SYN Flood"
                        details = f"{len(self.syn_flood_data[src_ip])} SYN packets in 10 seconds"
                        time_span = "10 seconds"
                        logging.info(f"{intrusion_type} — {src_ip} — {details} — {time_span}")
                        self.log_to_db(intrusion_type, src_ip, details, time_span)
                        self.send_alert(intrusion_type, src_ip, details)
                        self.block_ip(src_ip)
                        self.syn_flood_data[src_ip] = []

    def start(self):
        if self.running:
            print("IDS is already running.")
            return
        self.running = True
        print("Starting IDS...")
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop(self):
        if not self.running:
            print("IDS is not running.")
            return
        self.running = False
        print("Stopping IDS...")
        if self.sniff_thread is not None:
            self.sniff_thread.join(timeout=1)
            print("IDS stopped.")

    def sniff_packets(self):
        while self.running:
            try:
                scapy.sniff(filter="tcp", prn=self.process_packet, timeout=1)
            except Exception as e:
                print("Error during packet sniffing:", e)

    def view_live_traffic(self):
        with self.lock:
            for entry in self.live_traffic:
                print(entry)

    def view_logs(self):
        if os.path.exists("ids.log"):
            with open("ids.log", "r") as f:
                print(f.read())
        else:
            print("No logs found.")

    def view_blocked_ips(self):
        # For Linux, we print the internal blocked IPs list.
        if self.blocked_ips:
            print("Blocked IPs (internal list):")
            for ip in self.blocked_ips:
                print(ip)
        else:
            print("No IPs are currently blocked.")

def main():
    ids = IntrusionDetectionSystem()
    while True:
        print("\n==== Intrusion Detection System Menu ====")
        print("1. Start IDS")
        print("2. Stop IDS")
        print("3. View Live Traffic")
        print("4. View Intrusion Logs")
        print("5. Display Blocked IPs")
        print("6. Clear Block List")
        print("7. Unblock an IP")
        print("8. Exit")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            ids.start()
        elif choice == "2":
            ids.stop()
        elif choice == "3":
            ids.view_live_traffic()
        elif choice == "4":
            ids.view_logs()
        elif choice == "5":
            ids.view_blocked_ips()
        elif choice == "6":
            ids.clear_block_list()
        elif choice == "7":
            ip = input("Enter the IP to unblock: ").strip()
            ids.unblock_ip(ip)
        elif choice == "8":
            ids.stop()
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
