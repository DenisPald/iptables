import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import subprocess

class TrafficInspector:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Traffic Inspector")

        self.traffic_data = {}
        self.flagged_ips = set()
        self.denied_ips = set()
        self.port_scan_data = {}

        self._setup_ui()
        self._start_sniffing()

    def _setup_ui(self):
        frame_overview = tk.Frame(self.master)
        frame_overview.grid(row=0, column=0, padx=10, pady=10)

        frame_flags = tk.Frame(self.master)
        frame_flags.grid(row=0, column=1, padx=10, pady=10)

        frame_blocks = tk.Frame(self.master)
        frame_blocks.grid(row=0, column=2, padx=10, pady=10)

        tk.Label(frame_overview, text="Traffic Overview").pack(anchor="n")
        self.table_overview = ttk.Treeview(frame_overview, columns=("Address", "Port", "Bytes"), show="headings", height=10)
        self.table_overview.heading("Address", text="IP")
        self.table_overview.heading("Port", text="Port")
        self.table_overview.heading("Bytes", text="Data Size")
        self.table_overview.pack(fill="both", expand=True)

        tk.Label(frame_flags, text="Flagged IPs").pack(anchor="n")
        self.table_flags = ttk.Treeview(frame_flags, columns=("Address", "Reason"), show="headings", height=10)
        self.table_flags.heading("Address", text="IP")
        self.table_flags.heading("Reason", text="Flag Reason")
        self.table_flags.pack(fill="both", expand=True)

        self.btn_flag_block = tk.Button(frame_flags, text="Block Selected", command=self.block_flagged_ip)
        self.btn_flag_block.pack(fill="x", pady=5)

        tk.Label(frame_blocks, text="Blocked IPs").pack(anchor="n")
        self.table_blocks = ttk.Treeview(frame_blocks, columns=("Address",), show="headings", height=10)
        self.table_blocks.heading("Address", text="Blocked IP")
        self.table_blocks.pack(fill="both", expand=True)

        self.btn_unblock = tk.Button(frame_blocks, text="Unblock Selected", command=self.unblock_ip)
        self.btn_unblock.pack(fill="x", pady=5)

    def process_packet(self, packet):
        if packet.haslayer(scapy.IP):
            source_ip = packet[scapy.IP].src
            packet_length = len(packet)
            port = packet[scapy.IP].sport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else -1

            self.traffic_data[source_ip] = self.traffic_data.get(source_ip, 0) + packet_length

            if source_ip not in self.port_scan_data:
                self.port_scan_data[source_ip] = {}

            self.port_scan_data[source_ip][port] = self.port_scan_data[source_ip].get(port, 0) + 1

            if self.traffic_data[source_ip] > 1500 and source_ip not in self.flagged_ips:
                if source_ip not in self.flagged_ips:
                    self.flagged_ips.add(source_ip)
                    self.table_flags.insert("", "end", values=(source_ip, "High Data Volume"))

            if port == -1 or port > 60_000:
                if source_ip not in self.flagged_ips:
                    self.flagged_ips.add(source_ip)
                    self.table_flags.insert("", "end", values=(source_ip, "Strange port"))


            if len(self.port_scan_data[source_ip]) > 10:
                if source_ip not in self.flagged_ips:
                    self.flagged_ips.add(source_ip)
                    self.table_flags.insert("", "end", values=(source_ip, "Port Scanning"))

            if source_ip not in self.denied_ips:
                self.table_overview.insert("", "end", values=(source_ip, port, packet_length))

    def _start_sniffing(self):
        monitor_thread = threading.Thread(target=self._sniff_traffic, daemon=True)
        monitor_thread.start()

    def _sniff_traffic(self):
        scapy.sniff(prn=self.process_packet, store=False)

    def block_flagged_ip(self):
        selected = self.table_flags.selection()
        if selected:
            ip_to_block = self.table_flags.item(selected[0])['values'][0]
            if ip_to_block not in self.denied_ips:
                self.denied_ips.add(ip_to_block)
                self.table_blocks.insert("", "end", values=(ip_to_block,))
                self._apply_block_rule(ip_to_block)
                self.table_flags.delete(selected[0])

    def unblock_ip(self):
        selected = self.table_blocks.selection()
        if selected:
            ip_to_unblock = self.table_blocks.item(selected[0])['values'][0]
            if ip_to_unblock in self.denied_ips:
                self.denied_ips.remove(ip_to_unblock)
                self._remove_block_rule(ip_to_unblock)
                self.table_blocks.delete(selected[0])

    def _apply_block_rule(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"Blocked IP: {ip}")
        except subprocess.CalledProcessError as err:
            print(f"Error applying block rule for {ip}: {err}")

    def _remove_block_rule(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"Unblocked IP: {ip}")
        except subprocess.CalledProcessError as err:
            print(f"Error removing block rule for {ip}: {err}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TrafficInspector(root)
    root.mainloop()
