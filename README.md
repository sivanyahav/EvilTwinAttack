
# EvilTwinAttack

### Submitses Group No. 14:
	Sivan Yahav
	Koral Elbaz
	Yoel Chemla
	Levana Sciari

Definitin of Evil Twin Attack

![image](https://user-images.githubusercontent.com/57485490/168141806-d56440ee-3a07-4ebe-a727-510ab7c7d192.png)

An evil twin attack takes place when an attacker sets up a fake Wi-Fi access point 
his goal is that users will connect to it 
When users connect to this access point, all the data they share with the network passes through a server controlled by the attacker
In a first part we want to do Simple implementation in Python for the evil twin attack , Then in a second part the defense on the user.

### Part One:Attack
The attack is split into two parts:
In the first part the attacker defines an access point and a user that he will want to attack, and then he disconnects the user from the network
In the second part the attacker establishes a fake access point with the same name of the network he is attacking, and lets the disconnected user connect to it.

#### Steps :
•  Scan WLAN in the environment and view the various networks discovered.

•  Select the network on which to attack.

•  Scanning for clients in the network 

•  Selecting a victim and performing a Evil-Twin attack.

• Disconnect the victim from the existing network  good using SCAPY.

•  After the victim connects to the fake network the Evil Twin network is activated and Portal Captive is activated.

Requierement
Linux operating system with two network interfaces, so that both can enter monitor mode.
Python 2.7 and above, apachy2, php, hostapd, dnsmasq

### Part Two:Defense
the defence levels protection will be:

1.  take from the user the name of interface he is using.

2.  we would like to check if exist two AP' with the same SSID and different mac (evil twin), because we might be under attack

3.  if level 2 happens, we would like to check if the evil twin AP sends us a lot of Deauthentication packets.

4.  if level 3 happens, we would like to disconnect the attacker from the user.

5.  we will send a lot of Deauthentication packets to the attacker andthus protecting the user.
