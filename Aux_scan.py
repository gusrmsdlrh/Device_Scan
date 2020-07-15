from scapy.all import *
from timeit import default_timer as timer

#https://cnpnote.tistory.com/entry/PYTHON-%EC%96%B4%EB%96%BB%EA%B2%8C-%ED%8C%8C%EC%9D%B4%EC%8D%AC%EC%97%90%EC%84%9C-UDP-%EB%A9%80%ED%8B%B0-%EC%BA%90%EC%8A%A4%ED%8A%B8%ED%95%A9%EB%8B%88%EA%B9%8C
#https://wiki.python.org/moin/UdpCommunication
 
 
#start timer
start = timer()


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
        print "MDNS "+str(timeerror)
        #start=start+time
    except socket.error as err:
        print "MDNS "+str(err)

#Unicast NBNS
def nbns():    
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
		print
		print "========= NBNS+MDNS Data ==========="
		print "Response Data : "+string1
		print "Device Type : Unknown"
	else:
		print
		print "========= NBNS+MDNS Data ==========="
		print "Response Data : "+string1
		print "Device Type : "+type[max_idx]

if __name__=="__main__":
        nbns_string=''
        mdns_string=''
        #set value
        time=0.2
	 
        target=sys.argv[1]
        reverse=(target.split('.'))
	 
        nbns_string=nbns()
        mdns_string=mdns(reverse)

        if str(nbns_string) == 'None' and str(mdns_string) == 'None':
		print "No Packet Response"
        elif str(nbns_string) != 'None':
		print "NBNS Packet Response"
        elif str(mdns_string) != 'None':
		print "MDNS Packet Response"
        else:
		print "NBNS Packet Response"
		print "MDNS Packet Response"
		sys.exit()
        extract_match(str(nbns_string)+str(mdns_string))

        #end timer
        end=timer()
        print
        print ("Time Stamp ---> "+str(end-start))
