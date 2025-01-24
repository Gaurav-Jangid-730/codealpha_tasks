from scapy.all import sniff, wrpcap , Conf
from utils import analyze_packet, save_log
Conf.manufdb = r"C:\Users\Gaurav.Googlly\Desktop\Projects\python Projects\Basic Packter Sniffer\manuf.txt"

def start_sniffing(interface=None, packet_filter=None, output_file="captured_packets.pcap", packet_count=0):
    """
    Starts sniffing packets on a specified interface or all interfaces.
    Packets are stored in a PCAP file and optionally analyzed or logged.

    :param interface: Network interface to sniff on (default: None, which means all interfaces)
    :param packet_filter: BPF filter to apply (default: None)
    :param output_file: File to save captured packets (default: "captured_packets.pcap")
    :param packet_count: Number of packets to capture (default: 0 for infinite)
    """
    captured_packets = []

    def process_packet(packet):
        """
        Processes a single captured packet. Analyzes, logs, and writes it to the PCAP file.
        """
        print(packet.summury())
        # Analyze and log the packet (if needed)
        analyze_packet(packet)
        save_log(packet)

        # Add packet to the captured list
        captured_packets.append(packet)

        # Write packets to the output file incrementally
        try:
            wrpcap(output_file, captured_packets, append=True)
            captured_packets.clear()  # Clear the list after writing
        except Exception as e:
            print(f"Error writing packet to file: {e}")

    try:
        # Display starting message
        if interface:
            print(f"Starting packet sniffing on interface: {interface}... Press Ctrl+C to stop.")
        else:
            print("Starting packet sniffing on all interfaces... Press Ctrl+C to stop.")
        
        # Start sniffing
        packet = sniff(iface=interface, filter=packet_filter, count=packet_count, prn=process_packet)
        print(packet.summary())

    except KeyboardInterrupt:
        print("\nSniffing stopped by user.")
    except Exception as e:
        print(f"Error during sniffing: {e}")
    finally:
        print(f"Packets saved to {output_file}. You can open it in Wireshark.")

