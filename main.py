from scapy_local.all import *

print("✅ Scapy imported successfully!")

# Example: List all available interfaces
print("Available interfaces:")
print(Conf.ifaces)

# Example: Capture 3 packets (Ctrl+C to stop if it hangs)
print("\nSniffing 3 packets...")
packets = sniff(count=3)
for pkt in packets:
    print(pkt.summary())
