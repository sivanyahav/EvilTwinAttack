import signal
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, RadioTap

"""
 Let us note that the attacker levels of the attack are:
    1. choose who to attack (AP and user)
    2. send a lot of  Deauthentication packets
    3. create fake AP with the same SSID of the AP
    
Therefore, the defence levels protection will be:
    1. take from the user the name of interface he is using.
    2. we would like to check if exist two AP' with the same SSID and different mac (evil twin),
       because we might be under attack
    3. if level 2 happens, we would like to check if the evil twin AP 
       sends us a lot of Deauthentication packets.
    4. if level 3 happens, we would like to disconnect the attacker from the user. 
    5. we will send a lot of Deauthentication packets to the attacker and
       thus protecting the user.
 """

ap_list = []
ssid_list = []
interface = ""
ssid = ""
ap_mac = ""
attacked_mac=""
evil = ""
attacked = False
count = 0
first = True

def change_to_monitor_mode(interface):
    """
    In this func we change the network card mode to Monitor Mode
    by writing some of commands to the OS system
    """
    os.system('sudo airmon-ng check kill >/dev/null 2>&1')
    os.system('sudo ifconfig ' + str(interface) + ' down')
    os.system('sudo iwconfig ' + str(interface) + ' mode monitor')
    os.system('sudo ifconfig ' + str(interface) + ' up')


def network_scanning():
    """
    this function check if there is ap who send a lot
    of Deauthentication packets in 60 seconds , if so, it means we are under attack.
    """
    sniff(iface=interface, stop_filter=packet_handler, timeout=60)


def packet_handler(packet):
    global ap_list, ssid_list, ap_mac, evil
    # if the packet type 802.11
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        if packet.addr2 is not None:
            if packet.addr2 not in ap_list:
                ap_list.append(packet.addr2)  # addr2 - source mac address of sender
                ssid_list.append(packet.info.decode("utf-8"))
            else:
                for i in range(len(ssid_list)):
                    if packet.info.decode("utf-8") == ssid_list[i]:
                        evil = ssid_list[i]
                        ap_mac = ap_list[i]
                        break
                if ap_mac == packet.addr2:
                    print("\nExist Evil Twin AP, might be under attack !! ")
                    evil = ssid_list[i]
                    time.sleep(1)
                    return True


def deauth(interface):
    timeout = time.time() + 60  # a minute  from now
    while True:
        sniff(iface=interface, prn=deauth_handler, timeout=30)
        if time.time() > timeout or attacked:
            break


def deauth_handler(packet):
    """
    this function check if there is AP who dends us
    Deauthentication packets.
    if so, it saves the mac of that AP and stop.
    addr3- AP MAC
    addr2- Source mac
    """
    global ap_mac, attacked, attacked_mac, count, first
    # if the packet type 802.11 frame deauth
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
        if packet.addr2 is not None and packet.addr3 is not None:
            if str(packet.addr3) == ap_mac:  # first time we saw this AP mac
                count += 1  # Updating the number of time we've seen this AP mac
                if count > 40 and first:  # if we saw more than 60 packets we might be under attack.
                    attacked = True
                    first = False
                    print("\nYou under attack!!")
                    time.sleep(1)
                    attacked_mac = str(packet.addr1)
                    return True


def attack_attacker(attacker_mac, attacked_mac, interface):
    print("\nStart send Deauthentication packets.")
    sent_packets(attacker_mac, attacked_mac, interface)
    sent_packets(attacked_mac, attacker_mac, interface)


def sent_packets(sender, receiver, interface):
    dot11 = Dot11(type=0, subtype=12, addr1=receiver, addr2=sender, addr3=sender)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)  # create attack frame
    sendp(packet, inter=0.1, count=100, iface=interface, verbose=0)

def exit_handler(signum, frame):
    print("\nGoodye !! ")
    sys.exit()

def reset():
    global evil, attacked, attacked_mac, ap_mac, count, first, ssid_list, ap_list
    count = 0
    first = True
    attacked = False
    attacked_mac = []
    attacked = ''
    evil = ''
    ap_mac = ''
    ap_list = []
    ssid_list = []

def defence_main(interface):
    global  evil, attacked, attacked_mac, ap_mac

    while True:
        print("\nstarting scan if you want to stop press ctrl+c")
        time.sleep(1)

        # ----------- STEP 2 - Check for Evil Twin AP -----------
        print("\ncheck if exist evil twin in the network .. it will take minutes")
        time.sleep(1)
        network_scanning()

        if evil != '':  # There is Evil Twin AP

            # ----------- STEP 3 - Check for Deauthentication packets -----------
            print("\nStart scanning for deuth attack .. it will take a minute")
            time.sleep(1)
            deauth(interface)

            # ----------- STEP 4 - Disconnect the attacker -----------
            if attacked:
                atack_thread = threading.Thread(target=attack_attacker, args=(ap_mac, attacked_mac, interface),
                                                daemon=True)
                atack_thread.start()

                print("\nThe attacker was attacked, you are safe")
                time.sleep(1)
                reset()

            else:
                print("\nThere isn't deuth attack")
                time.sleep(1)

        else:
            print("\nThere is no attack, you are sefe")
            time.sleep(1)



if __name__ == "__main__":
    # ----------- STEP 1 - Get the user interface name and change to monitor mode -----------
    interface = input("enter the name of the interface you want to work with: ")
    change_to_monitor_mode(interface)
    time.sleep(2)

    while True:
        signal.signal(signal.SIGINT, exit_handler)
        defence_main(interface)
        time.sleep(5)

