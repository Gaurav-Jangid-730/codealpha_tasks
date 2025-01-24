from scapy.all import get_if_list
def apply_filters(filter_string=None):
    if filter_string:
        print(f"Applying filter: {filter_string}")
        return filter_string
    else:
        print("No filter applied. Capturing all traffic.")
        return None
    
def get_filtered_interfaces():
    """
    Get a filtered list of network interfaces, excluding loopback and virtual interfaces.
    """
    all_interfaces = get_if_list()
    filtered_interfaces = [
        iface for iface in all_interfaces
        if "Loopback" not in iface and "virtual" not in iface.lower() and "vmware" not in iface.lower()
    ]
    return filtered_interfaces