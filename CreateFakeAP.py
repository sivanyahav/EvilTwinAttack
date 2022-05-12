import os


def create_dnsmasq_file(interface_name):
    os.system("service dnsmasq stop >/dev/null 2>&1")

    # Flush iptables to avoid conflicts
    os.system("iptables -F")  #
    os.system("iptables -t nat -F")  #

    # define dnsmasq.conf
    interface_str = "interface=" + str(interface_name)  # Set the wireless interface
    IP_range_str = "\ndhcp-range=10.0.0.2,10.0.0.30,255.255.255.0,12h"  # Set the IP range for clients
    geteway_str = "\ndhcp-option=3,10.0.0.1"  # Set the gateway IP address
    DNS_str = "\ndhcp-option=6,10.0.0.1"  # Set DNS server address
    DNS_res = "\naddress=/#/10.0.0.1\naddress=/www.google.com/216.58.209.2\n"

    conf_str = interface_str + IP_range_str + geteway_str + DNS_str + DNS_res
    f = open("dnsmasq.conf", "w+")
    f.write(conf_str)
    f.close()
    os.chmod("dnsmasq.conf", 0o777)  # 0o777- give permission to read / write to everyone

    # route http traffic to captive portal page
    os.system('sudo iptables -t nat -A PREROUTING -p tcp -m tcp -s 10.0.0.0/24 --dport 80 -j DNAT --to-destination 10.0.0.1')
    os.system('sudo iptables -t nat -A PREROUTING -p tcp -m tcp -s 10.0.0.0/24 --dport 443 -j DNAT --to-destination 10.0.0.1')
    os.system('sudo iptables -t nat -A OUTPUT -p tcp -m tcp -s 10.0.0.0/24 --dport 443 -j DNAT --to-destination 10.0.0.1')

    os.system('sudo sysctl net.ipv4.ip_forward=1 >/dev/null 2>&1')     # Enable IP FORWARDING so the PC will
                                                                       # get the traffic from one wireless interface and to pass
                                                                       # it to another wireless interface


    os.system("sudo systemctl stop systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl disable systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl mask systemd-resolved >/dev/null 2>&1")
    # Initialize dnsmasq
    os.system('dnsmasq -C dnsmasq.conf')


def create_hostapd_file(interface_name, ssid="Ariel university", channel=1):

    os.system('sudo ip link set ' + str(interface_name) + ' down')
    os.system('sudo ifconfig ' + str(interface_name) + ' up 10.0.0.1 netmask 255.255.255.0')
    os.system('sudo route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1')
    os.system('sudo ip link set ' + str(interface_name) + ' up')

    # define hostapd.conf
    os.system("service hostapd stop >/dev/null 2>&1")
    interface_str = "interface=" + str(interface_name)  # Set wireless interface
    ssid_str = "\nssid=" + str(ssid)  # Set network name
    channel_str = "\nchannel=" + str(channel)  # Set channel
    driver_str = "\ndriver=nl80211"  # Set driver
    conf_str = interface_str + ssid_str + channel_str + driver_str
    f = open("hostapd.conf", "w+")
    f.write(conf_str)
    f.close()
    os.chmod("hostapd.conf", 0o777)
    os.system("hostapd hostapd.conf -B >/dev/null 2>&1")
