import os


def Change_to_Monitor_Mode(interfaceID):
    """
    In this func we change the network card mode to Monitor Mode
    by writing some of commands to the OS system
    """
    os.system('sudo airmon-ng check kill >/dev/null 2>&1')
    os.system('sudo ifconfig ' + str(interfaceID) + ' down')
    os.system('sudo iwconfig ' + str(interfaceID) + ' mode monitor')
    os.system('sudo ifconfig ' + str(interfaceID) + ' up')
    os.system("clear")


def Stop_Monitor_Mode(interfaceID):
    """
    In this func we cancel the Monitor Mode
    by writing some of commands to the OS system
    """
    os.system("sudo airmon-ng stop " + interfaceID)
    os.system("sudo systemctl start NetworkManager")
    os.system("clear")
