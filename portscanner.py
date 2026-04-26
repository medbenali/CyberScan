import socket

def port_scan(target_host, target_ports):
    for port in target_ports:
        try:
            # Create a TCP socket
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(1)  # Set timeout for this socket

            # Try to connect to the target host and port
            client.connect((target_host, port))
            print(f"✅ Port {port} is open")

        except (socket.timeout, socket.error):
            print(f"❌ Port {port} is closed or unreachable")

        finally:
            client.close()

# Example usage
target_host = "example.com"  # Replace with IP or domain
target_ports = [22, 80, 443, 8000]  # Common ports

port_scan(target_host, target_ports)