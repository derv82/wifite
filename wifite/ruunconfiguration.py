class RunConfiguration:
    """
        Configuration for this rounds of attacks
    """
    def __init__(self):
        self.REVISION = 86;
        self.PRINTED_SCANNING       = False

        self.TX_POWER = 0 # Transmit power for wireless interface, 0 uses default power

        # WPA variables
        self.WPA_DISABLE          = False # Flag to skip WPA handshake capture
        self.WPA_STRIP_HANDSHAKE  = True  # Use pyrit or tshark (if applicable) to strip handshake
        self.WPA_DEAUTH_COUNT     = 5     # Count to send deauthentication packets
        self.WPA_DEAUTH_TIMEOUT   = 10    # Time to wait between deauthentication bursts (in seconds)
        self.WPA_ATTACK_TIMEOUT   = 500   # Total time to allow for a handshake attack (in seconds)
        self.WPA_HANDSHAKE_DIR    = 'hs'  # Directory in which handshakes .cap files are stored
        # Strip file path separator if needed
        if self.WPA_HANDSHAKE_DIR != '' and self.WPA_HANDSHAKE_DIR[-1] == os.sep:
            self.WPA_HANDSHAKE_DIR = self.WPA_HANDSHAKE_DIR[:-1]

        self.WPA_FINDINGS         = []    # List of strings containing info on successful WPA attacks
        self.WPA_DONT_CRACK       = False # Flag to skip cracking of handshakes
        self.WPA_DICTIONARY       = '/pentest/web/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
        if not os.path.exists(self.WPA_DICTIONARY): self.WPA_DICTIONARY = ''

        # Various programs to use when checking for a four-way handshake.
        # True means the program must find a valid handshake in order for wifite to recognize a handshake.
        # Not finding handshake short circuits result (ALL 'True' programs must find handshake)
        self.WPA_HANDSHAKE_TSHARK   = True  # Checks for sequential 1,2,3 EAPOL msg packets (ignores 4th)
        self.WPA_HANDSHAKE_PYRIT    = False # Sometimes crashes on incomplete dumps, but accurate.
        self.WPA_HANDSHAKE_AIRCRACK = True  # Not 100% accurate, but fast.
        self.WPA_HANDSHAKE_COWPATTY = False # Uses more lenient "nonstrict mode" (-2)

        # WEP variables
        self.WEP_DISABLE         = False # Flag for ignoring WEP networks
        self.WEP_PPS             = 600   # packets per second (Tx rate)
        self.WEP_TIMEOUT         = 600   # Amount of time to give each attack
        self.WEP_ARP_REPLAY      = True  # Various WEP-based attacks via aireplay-ng
        self.WEP_CHOPCHOP        = True  #
        self.WEP_FRAGMENT        = True  #
        self.WEP_CAFFELATTE      = True  #
        self.WEP_P0841           = True
        self.WEP_HIRTE           = True
        self.WEP_CRACK_AT_IVS    = 10000 # Number of IVS at which we start cracking
        self.WEP_IGNORE_FAKEAUTH = True  # When True, continues attack despite fake authentication failure
        self.WEP_FINDINGS        = []    # List of strings containing info on successful WEP attacks.
        self.WEP_SAVE            = False # Save packets.

        # WPS variables
        self.WPS_DISABLE         = False # Flag to skip WPS scan and attacks
        self.WPS_FINDINGS        = []    # List of (successful) results of WPS attacks
        self.WPS_TIMEOUT         = 660   # Time to wait (in seconds) for successful PIN attempt
        self.WPS_RATIO_THRESHOLD = 0.01  # Lowest percentage of tries/attempts allowed (where tries > 0)
        self.WPS_MAX_RETRIES     = 0     # Number of times to re-try the same pin before giving up completely.


        # Program variables
        self.SHOW_ALREADY_CRACKED = False   # Says whether to show already cracked APs as options to crack
        self.WIRELESS_IFACE     = ''    # User-defined interface
        self.TARGET_CHANNEL     = 0     # User-defined channel to scan on
        self.TARGET_ESSID       = ''    # User-defined ESSID of specific target to attack
        self.TARGET_BSSID       = ''    # User-defined BSSID of specific target to attack
        self.IFACE_TO_TAKE_DOWN = ''    # Interface that wifite puts into monitor mode
                                # It's our job to put it out of monitor mode after the attacks
        self.ORIGINAL_IFACE_MAC = ('', '') # Original interface name[0] and MAC address[1] (before spoofing)
        self.DO_NOT_CHANGE_MAC  = True  # Flag for disabling MAC anonymizer
        self.TARGETS_REMAINING  = 0     # Number of access points remaining to attack
        self.WPA_CAPS_TO_CRACK  = []    # list of .cap files to crack (full of CapFile objects)
        self.THIS_MAC           = ''    # The interfaces current MAC address.
        self.SHOW_MAC_IN_SCAN   = False # Display MACs of the SSIDs in the list of targets
        self.CRACKED_TARGETS    = []    # List of targets we have already cracked
        self.ATTACK_ALL_TARGETS = False # Flag for when we want to attack *everyone*
        self.ATTACK_MIN_POWER   = 0     # Minimum power (dB) for access point to be considered a target
        self.VERBOSE_APS        = True  # Print access points as they appear
        self.CRACKED_TARGETS = self.load_cracked()
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

    def ConfirmRunningAsRoot(self):
        if os.getuid() != 0:
            print R+' [!]'+O+' ERROR:'+G+' wifite'+O+' must be run as '+R+'root'+W
            print R+' [!]'+O+' login as root ('+W+'su root'+O+') or try '+W+'sudo ./wifite.py'+W
            exit(1)

    def ConfirmCorrectPlatform(self):
        if not os.uname()[0].startswith("Linux") and not 'Darwin' in os.uname()[0]: # OSX support, 'cause why not?
            print O+' [!]'+R+' WARNING:'+G+' wifite'+W+' must be run on '+O+'linux'+W
            exit(1)

    def CreateTempFolder(self):
        from tempfile import mkdtemp
        self.temp = mkdtemp(prefix='wifite')
        if not self.temp.endswith(os.sep):
            self.temp += os.sep

    def save_cracked(self, target):
        """
            Saves cracked access point key and info to a file.
        """
        self.CRACKED_TARGETS.append(target)
        with open('cracked.csv', 'wb') as csvfile:
            targetwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for target in self.CRACKED_TARGETS:
                targetwriter.writerow([target.bssid, target.encryption, target.ssid, target.key, target.wps])

    def load_cracked(self):
        """
            Loads info about cracked access points into list, returns list.
        """
        result = []
        if not os.path.exists('cracked.csv'): return result
        with open('cracked.csv', 'rb') as csvfile:
            targetreader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in targetreader:
                t = Target(row[0], 0, 0, 0, row[1], row[2])
                t.key = row[3]
                t.wps = row[4]
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

    def exit_gracefully(self, code=0):
        """
            We may exit the program at any time.
            We want to remove the temp folder and any files contained within it.
            Removes the temp files/folder and exists with error code "code".
        """
        # Remove temp files and folder
        if os.path.exists(self.temp):
            for f in os.listdir(self.temp):
                os.remove(self.temp + f)
            os.rmdir(self.temp)
        # Disable monitor mode if enabled by us
        self.RUN_ENGINE.disable_monitor_mode()
        # Change MAC address back if spoofed
        mac_change_back()
        print GR+" [+]"+W+" quitting" # wifite will now exit"
        print ''
        # GTFO
        exit(code)

    def handle_args(self):
        """
            Handles command-line arguments, sets global variables.
        """
        set_encrypt = False
        set_hscheck = False
        set_wep     = False
        capfile     = ''  # Filename of .cap file to analyze for handshakes

        opt_parser = self.build_opt_parser()
        options = opt_parser.parse_args()

        try:
            if not set_encrypt and (options.wpa or options.wep or options.wps):
                self.WPS_DISABLE = True
                self.WPA_DISABLE = True
                self.WEP_DISABLE = True
                set_encrypt = True
            if options.recrack:
                self.SHOW_ALREADY_CRACKED = True
                print GR+' [+]'+W+' including already cracked networks in targets.'
            if options.wpa:
                if options.wps:
                    print GR+' [+]'+W+' targeting '+G+'WPA'+W+' encrypted networks.'
                else:
                    print GR+' [+]'+W+' targeting '+G+'WPA'+W+' encrypted networks (use '+G+'-wps'+W+' for WPS scan)'
                self.WPA_DISABLE = False
            if options.wep:
                print GR+' [+]'+W+' targeting '+G+'WEP'+W+' encrypted networks'
                self.WEP_DISABLE = False
            if options.wps:
                print GR+' [+]'+W+' targeting '+G+'WPS-enabled'+W+' networks.'
                self.WPS_DISABLE = False
            if options.channel:
                try: self.TARGET_CHANNEL = int(options.channel)
                except ValueError: print O+' [!]'+R+' invalid channel: '+O+options.channel+W
                except IndexError: print O+' [!]'+R+' no channel given!'+W
                else: print GR+' [+]'+W+' channel set to %s' % (G+str(self.TARGET_CHANNEL)+W)
            if options.mac_anon:
                print GR+' [+]'+W+' mac address anonymizing '+G+'enabled'+W
                print O+'      not: only works if device is not already in monitor mode!'+W
                self.DO_NOT_CHANGE_MAC = False
            if options.interface:
                self.WIRELESS_IFACE = options.interface
                print GR+' [+]'+W+' set interface :%s' % (G+self.WIRELESS_IFACE+W)
            if options.essid:
                try: self.TARGET_ESSID = options.essid
                except ValueError: print R+' [!]'+O+' no ESSID given!'+W
                else: print GR+' [+]'+W+' targeting ESSID "%s"' % (G+self.TARGET_ESSID+W)
            if options.bssid:
                try: self.TARGET_BSSID = options.bssid
                except ValueError: print R+' [!]'+O+' no BSSID given!'+W
                else: print GR+' [+]'+W+' targeting BSSID "%s"' % (G+self.TARGET_BSSID+W)
            if options.showb:
                self.SHOW_MAC_IN_SCAN = True
                print GR+' [+]'+W+' target MAC address viewing '+G+'enabled'+W
            if options.all:
                self.ATTACK_ALL_TARGETS = True
                print GR+' [+]'+W+' targeting '+G+'all access points'+W
            if options.power:
                try: self.ATTACK_MIN_POWER = int(options.power)
                except ValueError: print R+' [!]'+O+' invalid power level: %s' % (R+options.power+W)
                except IndexError: print R+' [!]'+O+' no power level given!'+W
                else: print GR+' [+]'+W+' minimum target power set to %s' % (G+str(self.ATTACK_MIN_POWER)+W)
            if options.tx:
                try: self.TX_POWER = int(options.tx)
                except ValueError: print R+' [!]'+O+' invalid TX power leve: %s' % ( R+options.tx+W)
                except IndexError: print R+' [!]'+O+' no TX power level given!'+W
                else: print GR+' [+]'+W+' TX power level set to %s' % (G+str(self.TX_POWER)+W)
            if options.quiet:
                self.VERBOSE_APS = False
                print GR+' [+]'+W+' list of APs during scan '+O+'disabled'+W
            if options.check:
                try: capfile = options.check
                except IndexError:
                    print R+' [!]'+O+' unable to analyze capture file'+W
                    print R+' [!]'+O+' no cap file given!\n'+W
                    self.exit_gracefully(1)
                else:
                    if not os.path.exists(capfile):
                        print R+' [!]'+O+' unable to analyze capture file!'+W
                        print R+' [!]'+O+' file not found: '+R+capfile+'\n'+W
                        self.exit_gracefully(1)
            if options.update:
                self.upgrade()
                exit(0)
            if options.cracked:
                if len(self.CRACKED_TARGETS) == 0:
                    print R+' [!]'+O+' There are no cracked access points saved to '+R+'cracked.db\n'+W
                    self.exit_gracefully(1)
                print GR+' [+]'+W+' '+W+'previously cracked access points'+W+':'
                for victim in self.CRACKED_TARGETS:
                    if victim.wps != False:
                        print '     %s (%s) : "%s" - Pin: %s' % (C+victim.ssid+W, C+victim.bssid+W, G+victim.key+W, G+victim.wps+W)
                    else:
                        print '     %s (%s) : "%s"' % (C+victim.ssid+W, C+victim.bssid+W, G+victim.key+W)
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
                print GR+' [+]'+W+' handshake stripping '+G+'enabled'+W
            if options.wpadt:
                try: self.WPA_DEAUTH_TIMEOUT = int(options.wpadt)
                except ValueError: print R+' [!]'+O+' invalid deauth timeout: %s' % (R+options.wpadt+W)
                except IndexError: print R+' [!]'+O+' no deauth timeout given!'+W
                else: print GR+' [+]'+W+' WPA deauth timeout set to %s' % (G+str(self.WPA_DEAUTH_TIMEOUT)+W)
            if options.wpat:
                try: self.WPA_ATTACK_TIMEOUT = int(options.wpat)
                except ValueError: print R+' [!]'+O+' invalid attack timeout: %s' % (R+options.wpat+W)
                except IndexError: print R+' [!]'+O+' no attack timeout given!'+W
                else: print GR+' [+]'+W+' WPA attack timeout set to %s' % (G+str(self.WPA_ATTACK_TIMEOUT)+W)
            if options.crack:
                self.WPA_DONT_CRACK = False
                print GR+' [+]'+W+' WPA cracking '+G+'enabled'+W
                if options.dic:
                    try: self.WPA_DICTIONARY = options.dic
                    except IndexError: print R+' [!]'+O+' no WPA dictionary given!'
                    else:
                        if os.path.exists(options.dic):
                            print GR+' [+]'+W+' WPA dictionary set to %s' % (G + self.WPA_DICTIONARY + W)
                        else:
                            print R+' [!]'+O+' WPA dictionary file not found: %s' % (options.dic)
                else:
                    print R+' [!]'+O+' WPA dictionary file not given!'
                    self.exit_gracefully(1)
            if options.tshark:
                self.WPA_HANDSHAKE_TSHARK = True
                print GR+' [+]'+W+' tshark handshake verification '+G+'enabled'+W
            if options.pyrit:
                self.WPA_HANDSHAKE_PYRIT = True
                print GR+' [+]'+W+' pyrit handshake verification '+G+'enabled'+W
            if options.aircrack:
                self.WPA_HANDSHAKE_AIRCRACK = True
                print GR+' [+]'+W+' aircrack handshake verification '+G+'enabled'+W
            if options.cowpatty:
                self.WPA_HANDSHAKE_COWPATTY = True
                print GR+' [+]'+W+' cowpatty handshake verification '+G+'enabled'+W

            # WEP
            if not set_wep and options.chopchop or options.fragment or options.caffeelatte or options.arpreplay \
                                                or options.p0841 or options.hirte:
                self.WEP_CHOPCHOP   = False
                self.WEP_ARPREPLAY  = False
                self.WEP_CAFFELATTE = False
                self.WEP_FRAGMENT   = False
                self.WEP_P0841      = False
                self.WEP_HIRTE      = False
            if options.chopchop:
                print GR+' [+]'+W+' WEP chop-chop attack '+G+'enabled'+W
                self.WEP_CHOPCHOP = True
            if options.fragment:
                print GR+' [+]'+W+' WEP fragmentation attack '+G+'enabled'+W
                self.WEP_FRAGMENT = True
            if options.caffeelatte:
                print GR+' [+]'+W+' WEP caffe-latte attack '+G+'enabled'+W
                self.WEP_CAFFELATTE = True
            if options.arpreplay:
                print GR+' [+]'+W+' WEP arp-replay attack '+G+'enabled'+W
                self.WEP_ARPREPLAY = True
            if options.p0841:
                print GR+' [+]'+W+' WEP p0841 attack '+G+'enabled'+W
                self.WEP_P0841 = True
            if options.hirte:
                print GR+' [+]'+W+' WEP hirte attack '+G+'enabled'+W
                self.WEP_HIRTE = True
            if options.fakeauth:
                print GR+' [+]'+W+' ignoring failed fake-authentication '+R+'disabled'+W
                self.WEP_IGNORE_FAKEAUTH = False
            if options.wepca:
                try: self.WEP_CRACK_AT_IVS = int(options.wepca)
                except ValueError: print R+' [!]'+O+' invalid number: %s' % ( R+options.wepca+W )
                except IndexError: print R+' [!]'+O+' no IV number specified!'+W
                else: print GR+' [+]'+W+' Starting WEP cracking when IV\'s surpass %s' % (G+str(self.WEP_CRACK_AT_IVS)+W)
            if options.wept:
                try: self.WEP_TIMEOUT = int(options.wept)
                except ValueError: print R+' [!]'+O+' invalid timeout: %s' % (R+options.wept+W)
                except IndexError: print R+' [!]'+O+' no timeout given!'+W
                else: print GR+' [+]'+W+' WEP attack timeout set to %s' % (G+str(self.WEP_TIMEOUT) + " seconds"+W)
            if options.pps:
                try: self.WEP_PPS = int(options.pps)
                except ValueError: print R+' [!]'+O+' invalid value: %s' % (R+options.pps+W)
                except IndexError: print R+' [!]'+O+' no value given!'+W
                else: print GR+' [+]'+W+' packets-per-second rate set to %s' % (G+str(options.pps) + " packets/sec"+W)
            if options.wepsave:
                self.WEP_SAVE = True
                print GR+' [+]'+W+' WEP .cap file saving '+G+'enabled'+W

            # WPS
            if options.wpst:
                try: self.WPS_TIMEOUT = int(options.wpst)
                except ValueError: print R+' [!]'+O+' invalid timeout: %s' % (R+options.wpst+W)
                except IndexError: print R+' [!]'+O+' no timeout given!'+W
                else: print GR+' [+]'+W+' WPS attack timeout set to %s' % (G+str(self.WPS_TIMEOUT)+ " seconds"+W)
            if options.wpsratio:
                try: self.WPS_RATIO_THRESHOLD = float(options.wpsratio)
                except ValueError: print R+' [!]'+O+' invalid percentage: %s' % (R+options.wpsratio+W)
                except IndexError: print R+' [!]'+O+' no ratio given!'+W
                else: print GR+' [+]'+W+' minimum WPS tries/attempts threshold set to %s' % (G+str(self.WPS_RATIO_THRESHOLD)+""+W)
            if options.wpsretry:
                try: self.WPS_MAX_RETRIES = int(options.wpsretry)
                except ValueError: print R+' [!]'+O+' invalid number: %s' % (R+options.wpsretry+W)
                except IndexError: print R+' [!]'+O+' no number given!'+W
                else: print GR+' [+]'+W+' WPS maximum retries set to %s' % (G+str(self.WPS_MAX_RETRIES) + " retries"+W)

        except IndexError:
            print '\nindexerror\n\n'

        if capfile != '':
            self.RUN_ENGINE.analyze_capfile(capfile)
        print ''

    def build_opt_parser(self):
        """ Options are doubled for backwards compatability; will be removed soon and
		    fully moved to GNU-style
        """
        option_parser = argparse.ArgumentParser()

        # set commands
        command_group = option_parser.add_argument_group('COMMAND')
        command_group.add_argument('--check', help='Check capfile [file] for handshakes.', action='store', dest='check')
        command_group.add_argument('-check', action='store', dest='check', help=argparse.SUPPRESS)
        command_group.add_argument('--cracked', help='Display previously cracked access points.', action='store_true', dest='cracked')
        command_group.add_argument('-cracked', help=argparse.SUPPRESS, action='store_true', dest='cracked')
        command_group.add_argument('--recrack', help='Include already cracked networks in targets.', action='store_true', dest='recrack')
        command_group.add_argument('-recrack', help=argparse.SUPPRESS, action='store_true', dest='recrack')

        # set global
        global_group = option_parser.add_argument_group('GLOBAL')
        global_group.add_argument('--all', help='Attack all targets.', default=False, action='store_true', dest='all')
        global_group.add_argument('-all', help=argparse.SUPPRESS, default=False, action='store_true', dest='all')
        global_group.add_argument('-i', help='Wireless interface for capturing.', action='store', dest='interface')
        global_group.add_argument('--mac', help='Anonymize MAC address.', action='store_true', default=False, dest='mac_anon')
        global_group.add_argument('-mac', help=argparse.SUPPRESS, action='store_true', default=False, dest='mac_anon')
        global_group.add_argument('-c', help='Channel to scan for targets.', action='store', dest='channel')
        global_group.add_argument('-e', help='Target a specific access point by ssid (name).', action='store', dest='essid')
        global_group.add_argument('-b', help='Target a specific access point by bssid (mac).', action='store', dest='bssid')
        global_group.add_argument('--showb', help='Display target BSSIDs after scan.', action='store_true', dest='showb')
        global_group.add_argument('-showb', help=argparse.SUPPRESS, action='store_true', dest='showb')
        global_group.add_argument('--power', help='Attacks any targets with signal strength > [pow].',action='store',dest='power')
        global_group.add_argument('-power', help=argparse.SUPPRESS,action='store',dest='power')
        global_group.add_argument('--tx', help='Set adapter TX power level.', action='store', dest='tx')
        global_group.add_argument('-tx', help=argparse.SUPPRESS, action='store', dest='tx')
        global_group.add_argument('--quiet', help='Do not print list of APs during scan.', action='store_true', dest='quiet')
        global_group.add_argument('-quiet', help=argparse.SUPPRESS, action='store_true', dest='quiet')
        global_group.add_argument('--update', help='Check and update Wifite.', default=False,action='store_true', dest='update')
        global_group.add_argument('-update', help=argparse.SUPPRESS, default=False,action='store_true', dest='update')
        # set wpa commands
        wpa_group = option_parser.add_argument_group( 'WPA')
        wpa_group.add_argument('--wpa', help='Only target WPA networks (works with --wps --wep).', default=False,action='store_true', dest='wpa')
        wpa_group.add_argument('-wpa', help=argparse.SUPPRESS, default=False,action='store_true', dest='wpa')
        wpa_group.add_argument('--wpat', help='Time to wait for WPA attack to complete (seconds).', action='store', dest='wpat')
        wpa_group.add_argument('-wpat', help=argparse.SUPPRESS, action='store', dest='wpat')
        wpa_group.add_argument('--wpadt', help='Time to wait between sending deauth packets (seconds).', action='store', dest='wpadt')
        wpa_group.add_argument('-wpadt', help=argparse.SUPPRESS, action='store', dest='wpadt')
        wpa_group.add_argument('--strip', help='Strip handshake using tshark or pyrit.', default=False, action='store_true', dest='strip')
        wpa_group.add_argument('-strip', help=argparse.SUPPRESS, default=False, action='store_true', dest='strip')
        wpa_group.add_argument('--crack', help='Crack WPA handshakes using [dic] wordlist file.', action='store_true', dest='crack')
        wpa_group.add_argument('-crack', help=argparse.SUPPRESS, action='store_true', dest='crack')
        wpa_group.add_argument('--dict', help='Specificy dictionary to use when cracking WPA.', action='store', dest='dic')
        wpa_group.add_argument('-dict', help=argparse.SUPPRESS, action='store', dest='dic')
        wpa_group.add_argument('--aircrack', help='Verify handshake using aircrack.', default=False, action='store_true', dest='aircrack')
        wpa_group.add_argument('-aircrack', help=argparse.SUPPRESS, default=False, action='store_true', dest='aircrack')
        wpa_group.add_argument('--pyrit', help='Verify handshake using pyrit.', default=False, action='store_true', dest='pyrit')
        wpa_group.add_argument('-pyrit', help=argparse.SUPPRESS,default=False, action='store_true', dest='pyrit')
        wpa_group.add_argument('--tshark', help='Verify handshake using tshark.', default=False, action='store_true', dest='tshark')
        wpa_group.add_argument('-tshark', help=argparse.SUPPRESS, default=False, action='store_true', dest='tshark')
        wpa_group.add_argument('--cowpatty', help='Verify handshake using cowpatty.', default=False, action='store_true', dest='cowpatty')
        wpa_group.add_argument('-cowpatty', help=argparse.SUPPRESS, default=False, action='store_true', dest='cowpatty')
        # set WEP commands
        wep_group = option_parser.add_argument_group('WEP')
        wep_group.add_argument('--wep', help='Only target WEP networks.', default=False, action='store_true', dest='wep')
        wep_group.add_argument('-wep', help=argparse.SUPPRESS, default=False, action='store_true', dest='wep')
        wep_group.add_argument('--pps', help='Set the number of packets per second to inject.', action='store', dest='pps')
        wep_group.add_argument('-pps', help=argparse.SUPPRESS, action='store', dest='pps')
        wep_group.add_argument('--wept', help='Sec to wait for each attack, 0 implies endless.', action='store', dest='wept')
        wep_group.add_argument('-wept', help=argparse.SUPPRESS, action='store', dest='wept')
        wep_group.add_argument('--chopchop', help='Use chopchop attack.', default=False, action='store_true', dest='chopchop')
        wep_group.add_argument('-chopchop', help=argparse.SUPPRESS, default=False, action='store_true', dest='chopchop')
        wep_group.add_argument('--arpreplay', help='Use arpreplay attack.', default=False, action='store_true', dest='arpreplay')
        wep_group.add_argument('-arpreplay', help=argparse.SUPPRESS, default=False, action='store_true', dest='arpreplay')
        wep_group.add_argument('--fragment', help='Use fragmentation attack.', default=False, action='store_true', dest='fragment')
        wep_group.add_argument('-fragment', help=argparse.SUPPRESS, default=False, action='store_true', dest='fragment')
        wep_group.add_argument('--caffelatte', help='Use caffe-latte attack.', default=False, action='store_true', dest='caffeelatte')
        wep_group.add_argument('-caffelatte', help=argparse.SUPPRESS, default=False, action='store_true', dest='caffeelatte')
        wep_group.add_argument('--p0841', help='Use P0842 attack.', default=False, action='store_true', dest='p0841')
        wep_group.add_argument('-p0841', help=argparse.SUPPRESS, default=False, action='store_true', dest='p0841')
        wep_group.add_argument('--hirte', help='Use hirte attack.', default=False, action='store_true', dest='hirte')
        wep_group.add_argument('-hirte', help=argparse.SUPPRESS, default=False, action='store_true', dest='hirte')
        wep_group.add_argument('--nofakeauth', help='Stop attack if fake authentication fails.', default=False, action='store_true', dest='fakeauth')
        wep_group.add_argument('-nofakeauth', help=argparse.SUPPRESS, default=False, action='store_true', dest='fakeauth')
        wep_group.add_argument('--wepca', help='Start cracking when number of IVs surpass [n].', action='store', dest='wepca')
        wep_group.add_argument('-wepca', help=argparse.SUPPRESS, action='store', dest='wepca')
        wep_group.add_argument('--wepsave', help='Save a copy of .cap files to this directory.', default=None,action='store', dest='wepsave')
        wep_group.add_argument('-wepsave', help=argparse.SUPPRESS, default=None,action='store', dest='wepsave')
        # set WPS commands
        wps_group = option_parser.add_argument_group('WPS')
        wps_group.add_argument('--wps', help='Only target WPS networks.', default=False, action='store_true', dest='wps')
        wps_group.add_argument('-wps', help=argparse.SUPPRESS, default=False, action='store_true', dest='wps')
        wps_group.add_argument('--wpst', help='Max wait for new retry before giving up (0: never).', action='store', dest='wpst')
        wps_group.add_argument('-wpst', help=argparse.SUPPRESS, action='store', dest='wpst')
        wps_group.add_argument('--wpsratio', help='Min ratio of successful PIN attempts/total retries.', action='store', dest='wpsratio')
        wps_group.add_argument('-wpsratio', help=argparse.SUPPRESS, action='store', dest='wpsratio')
        wps_group.add_argument('--wpsretry', help='Max number of retries for same PIN before giving up.', action='store', dest='wpsretry')
        wps_group.add_argument('-wpsretry', help=argparse.SUPPRESS, action='store', dest='wpsretry')

        return option_parser

    def upgrade(self):
        """
            Checks for new version, prompts to upgrade, then
            replaces this script with the latest from the repo
        """
        try:
            print GR+' [!]'+W+' upgrading requires an '+G+'internet connection'+W
            print GR+' [+]'+W+' checking for latest version...'
            revision = get_revision()
            if revision == -1:
                print R+' [!]'+O+' unable to access GitHub'+W
            elif revision > self.REVISION:
                print GR+' [!]'+W+' a new version is '+G+'available!'+W
                print GR+' [-]'+W+'   revision:    '+G+str(revision)+W
                response = raw_input(GR+' [+]'+W+' do you want to upgrade to the latest version? (y/n): ')
                if not response.lower().startswith('y'):
                    print GR+' [-]'+W+' upgrading '+O+'aborted'+W
                    self.exit_gracefully(0)
                    return
                # Download script, replace with this one
                print GR+' [+] '+G+'downloading'+W+' update...'
                try:
                    sock = urllib.urlopen('https://github.com/derv82/wifite/raw/master/wifite.py')
                    page = sock.read()
                except IOError:
                    page = ''
                if page == '':
                    print R+' [+] '+O+'unable to download latest version'+W
                    self.exit_gracefully(1)

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
                           rm -rf ''' + this_file + '''\n
                           mv wifite_new.py ''' + this_file + '''\n
                           rm -rf update_wifite.sh\n
                           chmod +x ''' + this_file + '''\n
                          ''')
                f.close()

                # Change permissions on the script
                returncode = call(['chmod','+x','update_wifite.sh'])
                if returncode != 0:
                    print R+' [!]'+O+' permission change returned unexpected code: '+str(returncode)+W
                    self.exit_gracefully(1)
                # Run the script
                returncode = call(['sh','update_wifite.sh'])
                if returncode != 0:
                    print R+' [!]'+O+' upgrade script returned unexpected code: '+str(returncode)+W
                    self.exit_gracefully(1)

                print GR+' [+] '+G+'updated!'+W+' type "./' + this_file + '" to run again'

            else:
                print GR+' [-]'+W+' your copy of wifite is '+G+'up to date'+W

        except KeyboardInterrupt:
            print R+'\n (^C)'+O+' wifite upgrade interrupted'+W
        self.exit_gracefully(0)