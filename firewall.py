from scapy.all import sniff, IP, TCP, UDP
import json
import csv
import datetime
import subprocess
import os

RULES_FILE = "rules.json"
LOG_FILE = "firewall_log.csv"


class Rule:
    def __init__(self, rule):
        self.name = rule.get("name")
        self.action = rule.get("action")
        self.protocol = rule.get("protocol", "ANY")
        self.dst_port = rule.get("dst_port", None)

    def matches(self, packet):
        if IP not in packet:
            return False

        if self.protocol != "ANY":
            if self.protocol == "TCP" and TCP not in packet:
                return False
            if self.protocol == "UDP" and UDP not in packet:
                return False

        if self.dst_port:
            if TCP in packet and packet[TCP].dport != self.dst_port:
                return False

        return True


def load_rules():
    with open(RULES_FILE) as f:
        return [Rule(r) for r in json.load(f)]


def log_packet(packet, action, rule_name):
    exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Action", "Rule"])
        writer.writerow([
            datetime.datetime.now(),
            packet[IP].src,
            packet[IP].dst,
            "TCP" if TCP in packet else "UDP",
            action,
            rule_name
        ])


def block_ip(ip):
    subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])


def process_packet(packet):
    rules = load_rules()
    for rule in rules:
        if rule.matches(packet):
            log_packet(packet, rule.action, rule.name)
            if rule.action == "BLOCK":
                block_ip(packet[IP].src)
                print(f"[BLOCKED] {packet[IP].src}")
            else:
                print(f"[ALLOWED] {packet[IP].src}")
            return


print("[+] Firewall started...")
sniff(filter="ip", prn=process_packet, store=False)
