from scapy.all import *
import requests
from timeit import default_timer as timer
import re
import binascii

#https://cnpnote.tistory.com/entry/PYTHON-%EC%96%B4%EB%96%BB%EA%B2%8C-%ED%8C%8C%EC%9D%B4%EC%8D%AC%EC%97%90%EC%84%9C-UDP-%EB%A9%80%ED%8B%B0-%EC%BA%90%EC%8A%A4%ED%8A%B8%ED%95%A9%EB%8B%88%EA%B9%8C
#https://wiki.python.org/moin/UdpCommunication
 
 
#start timer
start = timer()

#Multicast SSDP
def ssdp():    
    global start
    ssdp_pkt= "M-SEARCH * HTTP/1.1\r\n" \
    "HOST: 239.255.255.250:1900\r\n" \
    "MAN: \"ssdp:discover\"\r\n" \
    "MX: 1\r\n"\
    "ST: upnp:rootdevice\r\n\r\n"
 
 
    MCAST_GRP = '239.255.255.250'
    MCAST_PORT = 1900
 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #make the socket multicast-aware and set TTL
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.settimeout(time)
    #send data
    sock.sendto(ssdp_pkt, (MCAST_GRP, MCAST_PORT))

    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    try:
        while 1:
            data, address = sock.recvfrom(1024)
            if target in address:
                ssdp_url = re.search('(?m)(http://.*.xml)', data, re.I).group()
                resp=request.get(ssdp_url)

                # Keyword extract
                model_description = scrape(resp.text, '<modelDescription>', '</modelDescription>')
                device_type = scrape(resp.text, '<deviceType>', '</deviceType>')
                friendly_name = scrape(resp.text, '<friendlyName>', '</friendlyName>')
                ssdp_extract_name= str(device_type)+" "+str(model_description)+" "+str(friendly_name)
                extract_match(ssdp_extract_name)
                return "True"

    except socket.timeout as timeerror:
        print "SSDP Multicast "+str(timeerror)
        ssdp_str=ssdp2()
        return ssdp_str
        #start=start+time
 
#Unicast SSDP
def ssdp2():    
    global start
    ssdp_pkt= "M-SEARCH * HTTP/1.1\r\n" \
    "HOST: 239.255.255.250:1900\r\n" \
    "MAN: \"ssdp:discover\"\r\n" \
    "MX: 1\r\n"\
    "ST: upnp:rootdevice\r\n\r\n"
 
 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    s.settimeout(time)
    try:
        s.connect((target, 1900))
        s.send(ssdp_pkt)
        data=s.recv(1024)
        ssdp_url = re.search('\w{4}://\w+.\w+.\w+.\w+:\w+/\w+.\w+', data, re.I).group()
        resp=request.get(ssdp_url)

        # A = Keyword extract
        model_description = scrape(resp.text, '<modelDescription>', '</modelDescription>')
        device_type = scrape(resp.text, '<deviceType>', '</deviceType>')
        friendly_name = scrape(resp.text, '<friendlyName>', '</friendlyName>')
        ssdp_extract_name= str(device_type)+" "+str(model_description)+" "+str(friendly_name)
        extract_match(ssdp_extract_name)
    except socket.timeout as timeerror:
        print "SSDP Unicast "+str(timeerror)
        return "None"
        #start=start+time
    except socket.error as err:
        print str(err)+"\n"
        return "None"
 
#http://www.dns-sd.org/ServiceTypes.html
#Unicast MDNS
def mdns(reverse):    
    lens=[]
    for i in reverse:
        lens.append(len(i))
    var_3=binascii.unhexlify('0'+str(lens[3]))
    var_2=binascii.unhexlify('0'+str(lens[2]))
    var_1=binascii.unhexlify('0'+str(lens[1]))
    var_0=binascii.unhexlify('0'+str(lens[0]))

    global start
    mdns_pkt='\x00\x00\x01\x00\x00\x0e\x00\x00\x00\x00\x00\x00' \
    '\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x05_rtsp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x04_smb\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x0c_device-info\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01' \
    '\x05_svnp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x06_adisk\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x0b_afpovertcp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x0c_workstation\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x04_CGI\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x05_psia\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x06_dhnap\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    '\x06_audio\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
    +var_3+reverse[3]+var_2+reverse[2]+var_1+reverse[1]+var_0+reverse[0]+'\x07in-addr\x04arpa\x00\x00\x0c\x00\x01'
 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(time)


    try:
        s.connect((target, 5353))
        s.send(mdns_pkt)
        return s.recv(1024)
    except socket.timeout as timeerror:
        print "MDNS Unicast "+str(timeerror)
        #start=start+time
        return mdns2(reverse)
    except socket.error as err:
        print "MDNS Unicast "+str(err)
        return mdns2(reverse)

def mdns2(reverse):   
	lens=[]
	for i in reverse:
		lens.append(len(i))
	var_3=binascii.unhexlify('0'+str(lens[3]))
	var_2=binascii.unhexlify('0'+str(lens[2]))
	var_1=binascii.unhexlify('0'+str(lens[1]))
	var_0=binascii.unhexlify('0'+str(lens[0]))

	mdns_pkt='\x00\x00\x01\x00\x00\x0e\x00\x00\x00\x00\x00\x00' \
	'\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x05_rtsp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x04_smb\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x0c_device-info\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01' \
	'\x05_svnp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x06_adisk\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x0b_afpovertcp\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x0c_workstation\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x04_CGI\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x05_psia\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x06_dhnap\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	'\x06_audio\x04_tcp\x05local\x00\x00\x0c\x00\x01' \
	+var_3+reverse[3]+var_2+reverse[2]+var_1+reverse[1]+var_0+reverse[0]+'\x07in-addr\x04arpa\x00\x00\x0c\x00\x01'

	MCAST_GRP = '224.0.0.251' 
	MCAST_PORT = 5353
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	try:
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	except AttributeError:
		pass
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32) 
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

	sock.bind((MCAST_GRP, MCAST_PORT))
	host = socket.gethostbyname(socket.gethostname())
	sock.settimeout(time)
	#send data
	sock.sendto(mdns_pkt, (MCAST_GRP, MCAST_PORT))
	sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
	sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, 
		           socket.inet_aton(MCAST_GRP) + socket.inet_aton(host))
	try:
		while 1:
			data, addr = sock.recvfrom(1024)
			if target in addr:
				return data
	except socket.timeout as timeerror:
		print "MDNS Multicast "+str(timeerror)
		#start=start+time

#Unicast NBNS
def nbns():    
    print "========= Auxiliary_Scan(NBNS,MDNS) ==========="
    global start
    nbns_pkt="\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
    "\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
    "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(time)
    try:
        s.connect((target, 137))
        s.send(nbns_pkt)
        return s.recv(1024)
    except socket.timeout as timeerror:
        print "NBNS "+str(timeerror)
        #start=start+time
    except socket.error as err:
        print "NBNS "+str(err)
 
#SSDP URL-Data extraction
def scrape(text, start_trig, end_trig):
    if text.find(start_trig) != -1:
        return text.split(start_trig, 1)[-1].split(end_trig, 1)[0]
    else:
        return False
 
def extract_match(string1):
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

	for j in range(20):
		if type[j] == "router":
			router_num=0 
		elif type[j] == "tv":
			tv_num=0
		elif type[j] == "controller":
			controller_num=0
		elif type[j] == "sensor":
			sensor_num=0
		elif type[j] == "laptop":
			laptop_num=0
		elif type[j] == "camera":
			camera_num=0
		elif type[j] == "nas":
			nas_num=0
		elif type[j] == "video":
			video_num=0
		elif type[j] == "trigger":
			trigger_num=0
		elif type[j] == "recorder":
			recorder_num=0
		elif type[j] == "printer":
			printer_num=0
		elif type[j] == "socket":
			socket_num=0
		elif type[j] == "firewall":
			firewall_num=0
		elif type[j] == "refrigerator":
			refrigerator_num=0
		elif type[j] == "monitor":
			monitor_num=0
		elif type[j] == "watch":
			watch_num=0
		elif type[j] == "smartphone":
			smartphone_num=0
		elif type[j] == "healthcare":
			healthcare_num=0
		elif type[j] == "digital":
			digital_num=0
		elif type[j] == "game":
			game_num=0

		for i in device_list[j]:
			#print i
			#print j
			if i in string1.lower():
				#print i
				#print string1.lower()
				if type[j] == "router":
					router_num=router_num+1 
				elif type[j] == "tv":
					tv_num=tv_num+1
				elif type[j] == "controller":
					controller_num=controller_num+1
				elif type[j] == "sensor":
					sensor_num=sensor_num+1
				elif type[j] == "laptop":
					laptop_num=laptop_num+1
				elif type[j] == "camera":
					camera_num=camera_num+1
				elif type[j] == "nas":
					nas_num=nas_num+1
				elif type[j] == "video":
					video_num=video_num+1
				elif type[j] == "trigger":
					trigger_num=trigger_num+1
				elif type[j] == "recorder":
					recorder_num=recorder_num+1
				elif type[j] == "printer":
					printer_num=printer_num+1
				elif type[j] == "socket":
					socket_num=socket_num+1
				elif type[j] == "firewall":
					firewall_num=firewall_num+1
				elif type[j] == "refrigerator":
					refrigerator_num=refrigerator_num+1
				elif type[j] == "monitor":
					monitor_num=monitor_num+1
				elif type[j] == "watch":
					watch_num=watch_num+1
				elif type[j] == "smartphone":
					smartphone_num=smartphone_num+1
				elif type[j] == "healthcare":
					healthcare_num=healthcare_num+1
				elif type[j] == "digital":
					digital_num=digital_num+1
				elif type[j] == "game":
					game_num=game_num+1

	list_ls=[router_num, tv_num, controller_num, sensor_num,laptop_num,camera_num,nas_num,video_num,\
		trigger_num,recorder_num,printer_num,socket_num,firewall_num,refrigerator_num,monitor_num,\
		watch_num,smartphone_num,healthcare_num,digital_num,game_num]


	maxValue = list_ls[0]
	max_idx=0
	second=0
	for i in range(1, len(list_ls)):
		if maxValue < list_ls[i]:

			maxValue = list_ls[i]
			max_idx=i
		elif maxValue != 0 and maxValue == list_ls[i]:
			second=i			
			
	if maxValue == 0:
		print "Response Data : "+string1
		print "Device Type : "+"Unknown"
		print
		end1=timer()
		print "Time Stamp ---> "+str(end1-start)
		print
		nbns_string=nbns()
		mdns_string=mdns(reverse)
		if str(nbns_string) == 'None' and str(mdns_string) == 'None':
			print "NBNS, MDNS No Packet Response\n"
		elif str(nbns_string) == 'None':
			print "MDNS Packet Response\n"
			extract_match(str(nbns_string)+str(mdns_string))
		elif str(mdns_string) == 'None':
			print "NBNS Packet Response"
			extract_match(str(nbns_string)+str(mdns_string))
		elif str(mdns_string) != 'None' and str(nbns_string) != 'None':
			print "NBNS Packet Response"
			print "MDNS Packet Response\n"
			extract_match(str(nbns_string)+str(mdns_string))
	else:
		print "Response Data : "+string1
		print "Device Type : "+type[max_idx]
		if second > 0:
			print "Device Type : "+type[second]
		print

if __name__=="__main__":
        nbns_string=''
        mdns_string=''
        #set value
        time=0.2
        request=requests.Session()
        target=sys.argv[1]
        reverse=(target.split('.'))
        print "========= Primary_Scan(SSDP) ==========="
        ssdp_string=ssdp()
        if str(ssdp_string) == 'None':
		print "SSDP No Packet Response\n"
		quick_time=timer()
		print ("Time Stamp ---> "+str(quick_time-start))
		nbns_string=nbns()
		mdns_string=mdns(reverse)
		if str(nbns_string) == 'None' and str(mdns_string) == 'None':
			print "NBNS, MDNS No Packet Response\n"
		elif str(nbns_string) == 'None':
			print "MDNS Packet Response\n"
			extract_match(str(nbns_string)+str(mdns_string))
		elif str(mdns_string) == 'None':
			print "NBNS Packet Response"
			extract_match(str(nbns_string)+str(mdns_string))
		elif str(mdns_string) != 'None' and str(nbns_string) != 'None':
			print "NBNS Packet Response"
			print "MDNS Packet Response\n"
			extract_match(str(nbns_string)+str(mdns_string))

        end=timer()
        print "Time Stamp ---> "+str(end-start)
