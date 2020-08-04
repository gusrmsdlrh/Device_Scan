import requests
import re
import sys
import socket
import struct
from timeit import default_timer as timer
import binascii

def primary_1():
        print("===========PRIMARY SCAN===========")
        MCAST_GRP = '239.255.255.250'
        MCAST_PORT = 1900

        # socket Multicast Request
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(time)
        sock.sendto(primary_pkt, (MCAST_GRP, MCAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        try:
                while 1:
                        data, address = sock.recvfrom(1024)
                        if target in address:
                                # LOCATION : XXX
                                location_data = re.search(b'(?m)(http://.*)', data, re.I).group()
                                location_url = location_data.split(b'\r')[0]
                                resp = request.get(location_url)

                                # XML Tags extract
                                model_description = scrape(resp.text, '<modelDescription>', '</modelDescription>')
                                device_type = scrape(resp.text, '<deviceType>', '</deviceType>')
                                friendly_name = scrape(resp.text, '<friendlyName>', '</friendlyName>')
                                tags_data = str(device_type) + " " + str(model_description) + " " + str(friendly_name)

                                # keyword match
                                keyword_match(tags_data)
        except socket.timeout as timeerror:
                print ("Primary Scan 1 : " + str(timeerror))
                primary_str = primary_2()

def primary_2():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(time)

        try:
                sock.connect((target, 1900))
                sock.send(primary_pkt)
                data = sock.recv(1024)

                # LOCATION : XXX
                location_data = re.search(b'(?m)(http://.*)', data, re.I).group()
                location_url = location_data.split(b'\r')[0]
                resp = request.get(location_url)

                # XML Tags extract
                model_description = scrape(resp.text, '<modelDescription>', '</modelDescription>')
                device_type = scrape(resp.text, '<deviceType>', '</deviceType>')
                friendly_name = scrape(resp.text, '<friendlyName>', '</friendlyName>')
                tags_data = str(device_type) + " " + str(model_description) + " " + str(friendly_name)

                # keyword match
                keyword_match(tags_data)
        except socket.timeout as timeerror:
                print ("Primary Scan 2 : " + str(timeerror))
        except socket.error as err:
                print ("Primary Scan 2 : " + str(err))

#Data extraction
def scrape(text, start_trig, end_trig):
        if text.find(start_trig) != -1:
                return text.split(start_trig, 1)[-1].split(end_trig, 1)[0]
        else:
                return False


def Auxiliary_1():
    print("===========Auxiliary SCAN===========")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(time)
    try:
        sock.connect((target, 137))
        sock.send(auxiliary_pkt)
        return (sock.recv(1024).decode('utf-8','replace'))
    except socket.timeout as timeerror:
        print("Auxiliary Scan 1 " + str(timeerror))
        return "Null"
    except socket.error as err:
        print("Auxiliary Scan 1 " + str(err))
        return "Null"

def Auxiliary_2():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(time)
        try:
                sock.connect((target, 5353))
                sock.send(Auxiliary_2_pkt)
                return (sock.recv(1024).decode('utf-8','replace'))
        except socket.timeout as timeerror:
                print("Auxiliary Scan 2 " + str(timeerror))
                Auxiliary_3_str = Auxiliary_3()
                return Auxiliary_3_str
        except socket.error as err:
                print("Auxiliary Scan 2 " + str(err))
                Auxiliary_3_str = Auxiliary_3()
                return Auxiliary_3_str

def Auxiliary_3():
    MCAST_GRP = '224.0.0.251'
    MCAST_PORT = 5353

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MCAST_PORT))
    host = socket.gethostbyname(socket.gethostname())
    sock.settimeout(time)
    sock.sendto(Auxiliary_2_pkt, (MCAST_GRP, MCAST_PORT))
    sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MCAST_GRP) + socket.inet_aton(host))

    try:
        while 1:
            data, addr = sock.recvfrom(1024)
            if target in addr:
                return(data.decode('utf-8','replace'))
    except socket.timeout as timeerror:
        print ("Auxiliary Scan 3 "+str(timeerror))
        return "Null"

def Auxiliary_reverse_ip(ip_addr):
        lens = []
        reverse = (ip_addr.split('.'))
        for i in reverse:
                lens.append(len(i))
        var_3 = binascii.unhexlify('0' + str(lens[3]))
        var_2 = binascii.unhexlify('0' + str(lens[2]))
        var_1 = binascii.unhexlify('0' + str(lens[1]))
        var_0 = binascii.unhexlify('0' + str(lens[0]))

        Auxiliary_2_pkt = b'\x00\x00\x01\x00\x00\x0e\x00\x00\x00\x00\x00\x00' \
                      b'\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x05_rtsp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x04_smb\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x0c_device-info\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x05_svnp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x06_adisk\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x0b_afpovertcp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x0c_workstation\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x04_CGI\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x05_psia\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x06_dhnap\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      b'\x06_audio\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
                      + var_3 + reverse[3].encode() + var_2 + reverse[2].encode() + var_1 + reverse[
                          1].encode() + var_0 + reverse[0].encode() + \
                      b'\x07in-addr\x04arpa\x00\x00\x0c\x00\x01'
        return Auxiliary_2_pkt

def keyword_match(data):
        # Types of IoT Devices
        '''
        o	Yang, K., Li, Q., & Sun, L. (2019). Towards automatic fingerprinting of IoT devices in the cyberspace. Computer Networks, 148, 318-327.
        o	Meidan, Y., Bohadana, M., Shabtai, A., Guarnizo, J. D., Ochoa, M., Tippenhauer, N. O., & Elovici, Y. (2017, April). ProfilIoT: a machine learning approach for IoT device identification based on network traffic analysis. In Proceedings of the symposium on applied computing (pp. 506-509).
        o	Sivanathan, A., Sherratt, D., Gharakheili, H. H., Radford, A., Wijenayake, C., Vishwanath, A., & Sivaraman, V. (2017, May). Characterizing and classifying IoT traffic in smart cities and campuses. In 2017 IEEE Conference on Computer Communications Workshops (INFOCOM WKSHPS) (pp. 559-564). IEEE.
        o	Kawai, H., Ata, S., Nakamura, N., & Oka, I. (2017, November). Identification of communication devices from analysis of traffic patterns. In 2017 13th International Conference on Network and Service Management (CNSM) (pp. 1-5). IEEE.
        o	Meidan, Y., Bohadana, M., Shabtai, A., Ochoa, M., Tippenhauer, N. O., Guarnizo, J. D., & Elovici, Y. (2017). Detection of unauthorized iot devices using machine learning techniques. arXiv preprint arXiv:1709.04647.

        •	IoT device categories (Total 20)
                o	Router / Switch / Hub / Gateway / Modem / (Wireless) access point
                o	(IP) television / TV
                o	Programmable / (Logic) controller
                o	Sensor / Thermostat
                o	PC / Laptop
                o	(IP / Network) camera
                o	NAS
                o	(Digital) video
                o	Trigger
                o	Recorder
                o	Printer
                o	Socket
                o	Firewall
                o	Refrigerator
                o	Monitor
                o	(Smart) watch
                o	Smartphone
                o	Healthcare (device)
                o	Digital media receiver
                o	Consumer game
        '''
        # Null data
        if data == "NullNull":
            sys.exit()

        device_list=[['router','switch','hub','gateway','modem', 'access point', 'accesspoint'],
                ['television', 'tv'],['programmable', 'controller'],['sensor', 'thermostat'],
                ['pc', 'laptop'],['camera'],['nas'],['video'],['trigger'],
                ['recorder'],['printer'],['socket'],['firewall'],['refrigerator'],
                ['monitor'],['watch'],['smartphone'],['healthcare'],['digital media receiver', 'media', 'digital'],
                ['consumer game', 'game']]
        type=['router', 'tv','controller',
                'sensor','laptop','camera',
                'nas','video','trigger','recorder',
                'printer','socket','firewall','refrigerator',
                'monitor','watch','smartphone','healthcare',
                'digital','game']

        # Type Var Declaration
        for i in type:
                globals()['{}_count'.format(i)]=0

        # UnboundLocalError Exception
        global router_count, tv_count, controller_count, sensor_count, laptop_count, camera_count, nas_count, video_count, \
                   trigger_count, recorder_count, printer_count, socket_count, firewall_count, refrigerator_count, monitor_count, \
                   watch_count, smartphone_count, healthcare_count, digital_count, game_count

        # Device Type Count List
        list_ls = [router_count, tv_count, controller_count, sensor_count, laptop_count, camera_count, nas_count, video_count, \
                   trigger_count, recorder_count, printer_count, socket_count, firewall_count, refrigerator_count, monitor_count, \
                   watch_count, smartphone_count, healthcare_count, digital_count, game_count]

        # Device Type Count
        for j in range(20):
                for i in device_list[j]:
                        if i in data.lower():
                                list_ls[j]=list_ls[j]+1
        # List Sort
        maxValue = list_ls[0]
        max_idx = 0
        second_idx = 0
        for i in range(1, len(list_ls)):
                if maxValue < list_ls[i]:
                        maxValue = list_ls[i]
                        max_idx = i
                elif maxValue != 0 and maxValue == list_ls[i]:
                        second_idx = i

        # Device Type Result
        if maxValue == 0:
                print ("Data : " + data)
                print ("Device Type : " + "Unknown")
                DT_unknown = timer()
                print("Time Stamp ---> " + str(DT_unknown - start)+"\r\n")
        else:
                print ("Data : " + data)
                print ("Device Type : " + type[max_idx])
                if second_idx > 0:
                        print ("Device Type : " + type[second_idx])
                sys.exit()

if __name__=="__main__":
        # Time Stamp
        start = timer()

        primary_pkt = b"M-SEARCH * HTTP/1.1\r\n" \
                   b"HOST: 239.255.255.250:1900\r\n" \
                   b"MAN: \"ssdp:discover\"\r\n" \
                   b"MX: 1\r\n" \
                   b"ST: upnp:rootdevice\r\n\r\n"

        auxiliary_pkt = b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                    b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
                    b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"

        time=0.2
        request = requests.Session()
        target=sys.argv[1]
        Auxiliary_2_pkt=Auxiliary_reverse_ip(target)

        primary_1()
        auxiliary_1_string=Auxiliary_1()
        auxiliary_2_string=Auxiliary_2()
        keyword_match(auxiliary_1_string+auxiliary_2_string)

        end = timer()
        print("Time Stamp ---> " + str(end - start)+"\r\n")
