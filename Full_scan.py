from scapy.all import *
import requests
from timeit import default_timer as timer
import re


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
    print("========= Multicast SSDP Packet REQUEST =========")
    try:
        while 1:
            data, address = sock.recvfrom(1024)
            if target in address:
                ssdp_url = re.search('\w{4}://\w+.\w+.\w+.\w+:\w+/\w+.\w+', data, re.I).group()
                resp=request.get(ssdp_url)

                # Keyword extract
                extract_match(resp.text)
                break
    except socket.timeout:
        print "No Response Packet\n"
        ssdp2()
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
    print("========= Unicast SSDP Packet REQUEST =========")
    try:
        s.connect((target, 1900))
        s.send(ssdp_pkt)
        data=s.recv(1024)
        ssdp_url = re.search('\w{4}://\w+.\w+.\w+.\w+:\w+/\w+.\w+', data, re.I).group()
        resp=request.get(ssdp_url)

        # A = Keyword extract
        extract_match(resp.text)
        print
    except socket.timeout:
        print "No Response Packet\n"
        #start=start+time
    except socket.error as err:
        print str(err)+"\n"

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
	for idx,val in enumerate(range(1, len(list_ls))):
		if maxValue < list_ls[val]:

			maxValue = list_ls[val]
			max_idx=idx
		elif maxValue != 0 and maxValue == list_ls[val]:
			print maxValue, list_ls[val]
	if maxValue == 0:
		print "Response Data : "+string1
		print "Device Type : Unknown"
	else:
		print "Response Data : "+string1
		print "Device Type : "+type[max_idx]


if __name__=="__main__":
        #set value
        time=0.2
        request=requests.Session()
	 
        target=sys.argv[1]
	 
        ssdp()
	 
        #end timer
        end=timer()
        print
        print ("Time Stamp ---> "+str(end-start))
