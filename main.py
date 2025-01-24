import argparse
from sniffing import start_sniffing
from filters import get_filtered_interfaces

def main():
    parser = argparse.ArgumentParser(description="Basic Packet Sniffer")
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (default: Choose from available interfaces)",
        default=None
    )
    parser.add_argument(
        "-f", "--filter",
        help="BPF filter for packet capture (default: None)",
        default=None
    )
    parser.add_argument(
        "-o", "--output",
        help="Output .pcap file (default: captured_packets.pcap)",
        default="captured_packets.pcap"
    )
    args = parser.parse_args()

    interfaces = get_filtered_interfaces()

    if not interfaces:
        print("No valid network interfaces found.")
        return

    print("Available network interfaces:")
    print("  0. All interfaces")
    for i, iface in enumerate(interfaces, start=1):
        print(f"  {i}. {iface}")

    if args.interface is None:
        choice = input("Select an interface number (or 0 for all interfaces): ").strip()
        try:
            choice = int(choice)
            if choice == 0:
                args.interface = None
            elif 1 <= choice <= len(interfaces):
                args.interface = interfaces[choice - 1]
            else:
                print("Invalid choice. Exiting.")
                return
        except ValueError:
            print("Invalid input. Exiting.")
            return

    if args.interface is None:
        print("Listening on all interfaces...")
    else:
        print(f"Listening on interface: {args.interface}")
    start_sniffing(interface=args.interface, packet_filter=args.filter, output_file=args.output)

if __name__ == "__main__":
    main()
