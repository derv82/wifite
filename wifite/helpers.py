
##################
# MAIN FUNCTIONS #
##################

##############################################################
### End Classes

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
    print G+"  .;'                     `;,    "
    print G+" .;'  ,;'             `;,  `;,   "+W+"WiFite v2 (r" + str(RUN_CONFIG.REVISION) + ")"
    print G+".;'  ,;'  ,;'     `;,  `;,  `;,  "
    print G+"::   ::   :   "+GR+"( )"+G+"   :   ::   ::  "+GR+"automated wireless auditor"
    print G+"':.  ':.  ':. "+GR+"/_\\"+G+" ,:'  ,:'  ,:'  "
    print G+" ':.  ':.    "+GR+"/___\\"+G+"    ,:'  ,:'   "+GR+"designed for Linux"
    print G+"  ':.       "+GR+"/_____\\"+G+"      ,:'     "
    print G+"           "+GR+"/       \\"+G+"             "
    print W


def get_revision():
    """
        Gets latest revision # from the GitHub repository
        Returns : revision#
    """
    irev  =-1

    try:
        sock = urllib.urlopen('https://github.com/derv82/wifite/raw/master/wifite.py')
        page = sock.read()
    except IOError:
        return (-1, '', '')

    # get the revision
    start= page.find('REVISION = ')
    stop = page.find(";", start)
    if start != -1 and stop != -1:
        start += 11
        rev=page[start:stop]
        try:
            irev=int(rev)
        except ValueError:
            rev=rev.split('\n')[0]
            print R+'[+] invalid revision number: "'+rev+'"'

    return irev

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
    print sw+'\t-recrack    \t'+des+'allow recracking of previously cracked access points'+W
    print ''

    print head+'   GLOBAL'+W
    print sw+'\t-all         \t'+des+'attack all targets.              '+de+'[off]'+W
    #print sw+'\t-pillage     \t'+des+'attack all targets in a looping fashion.'+de+'[off]'+W
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




######################
# SCANNING FUNCTIONS #
######################





def wps_check_targets(targets, cap_file, verbose=True):
    """
        Uses reaver's "walsh" (or wash) program to check access points in cap_file
        for WPS functionality. Sets "wps" field of targets that match to True.
    """
    global RUN_CONFIG

    if not program_exists('walsh') and not program_exists('wash'):
        RUN_CONFIG.WPS_DISABLE = True # Tell 'scan' we were unable to execute walsh
        return
    program_name = 'walsh' if program_exists('walsh') else 'wash'

    if len(targets) == 0 or not os.path.exists(cap_file): return
    if verbose:
        print GR+' [+]'+W+' checking for '+G+'WPS compatibility'+W+'...',
        stdout.flush()

    cmd = [program_name,
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
    if verbose:
        print 'done'
    removed = 0
    if not RUN_CONFIG.WPS_DISABLE and RUN_CONFIG.WPA_DISABLE:
        i = 0
        while i < len(targets):
            if not targets[i].wps and targets[i].encryption.find('WPA') != -1:
                removed += 1
                targets.pop(i)
            else: i += 1
        if removed > 0 and verbose: print GR+' [+]'+O+' removed %d non-WPS-enabled targets%s' % (removed, W)



def print_and_exec(cmd):
    """
        Prints and executes command "cmd". Also waits half a second
        Used by rtl8187_fix (for prettiness)
    """
    print '\r                                                        \r',
    stdout.flush()
    print O+' [!] '+W+'executing: '+O+' '.join(cmd) + W,
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
    global RUN_CONFIG
    if RUN_CONFIG.DO_NOT_CHANGE_MAC: return
    if not program_exists('ifconfig'): return

    # Store old (current) MAC address
    proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
    proc.wait()
    for word in proc.communicate()[0].split('\n')[0].split(' '):
        if word != '': old_mac = word
    RUN_CONFIG.ORIGINAL_IFACE_MAC = (iface, old_mac)

    new_mac = generate_random_mac(old_mac)

    call(['ifconfig', iface, 'down'])

    print GR+" [+]"+W+" changing %s's MAC from %s to %s..." % (G+iface+W, G+old_mac+W, O+new_mac+W),
    stdout.flush()

    proc = Popen(['ifconfig', iface, 'hw', 'ether', new_mac], stdout=PIPE, stderr=DN)
    proc.wait()
    call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
    print 'done'

def mac_change_back():
    """
        Changes MAC address back to what it was before attacks began.
    """
    global RUN_CONFIG
    iface = RUN_CONFIG.ORIGINAL_IFACE_MAC[0]
    old_mac = RUN_CONFIG.ORIGINAL_IFACE_MAC[1]
    if iface == '' or old_mac == '': return

    print GR+" [+]"+W+" changing %s's mac back to %s..." % (G+iface+W, G+old_mac+W),
    stdout.flush()

    call(['ifconfig', iface, 'down'], stdout=DN, stderr=DN)
    proc = Popen(['ifconfig', iface, 'hw', 'ether', old_mac], stdout=PIPE, stderr=DN)
    proc.wait()
    call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
    print "done"



def get_essid_from_cap(bssid, capfile):
    """
        Attempts to get ESSID from cap file using BSSID as reference.
        Returns '' if not found.
    """
    if not program_exists('tshark'): return ''

    cmd = ['tshark',
           '-r', capfile,
           '-R', 'wlan.fc.type_subtype == 0x05 && wlan.sa == %s' % bssid,
           '-n']
    proc = Popen(cmd, stdout=PIPE, stderr=DN)
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
    global RUN_CONFIG

    if not program_exists('tshark'): return ''

# Attempt to get BSSID based on ESSID
    if essid != '':
        cmd = ['tshark',
               '-r', capfile,
               '-R', 'wlan_mgt.ssid == "%s" && wlan.fc.type_subtype == 0x05' % (essid),
               '-n',            # Do not resolve MAC vendor names
               '-T', 'fields',  # Only display certain fields
               '-e', 'wlan.sa'] # souce MAC address
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
        print GR+"\n [+] %s%d%s target%s remain%s" % (G, RUN_CONFIG.TARGETS_REMAINING, W,
                                '' if RUN_CONFIG.TARGETS_REMAINING == 1 else 's',
                                's' if RUN_CONFIG.TARGETS_REMAINING == 1 else '')
        print GR+" [+]"+W+" what do you want to do?"
        options += G+'c'+W
        print G+"     [c]ontinue"+W+" attacking targets"

        if len(RUN_CONFIG.WPA_CAPS_TO_CRACK) > 0:
            options += W+', '+O+'s'+W
            print O+"     [s]kip"+W+" to cracking WPA cap files"
        options += W+', or '+R+'e'+W
        print R+"     [e]xit"+W+" completely"
        ri = ''
        while ri != 'c' and ri != 's' and ri != 'e':
            ri = raw_input(GR+' [+]'+W+' please make a selection (%s): ' % options)

        if ri == 's':
            RUN_CONFIG.TARGETS_REMAINING = -1 # Tells start() to ignore other targets, skip to cracking
        elif ri == 'e':
            should_we_exit = True
    return should_we_exit


