#!/usr/bin/python

# -*- coding: utf-8 -*-

"""
    wifite

    author: derv82 at gmail
    author: bwall @botnet_hunter (ballastsec@gmail.com)
    author: drone @dronesec (ballastsec@gmail.com)

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

#############
# LIBRARIES #
#############

import csv          # Exporting and importing cracked aps
import os         # File management
import time       # Measuring attack intervals
import random     # Generating a random MAC address.
import errno      # Error numbers

from sys import argv          # Command-line arguments
from sys import stdout          # Flushing

from shutil import copy  # Copying .cap files

# Executing, communicating with, killing processes
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM

import re # RegEx, Converting SSID to filename
import argparse # arg parsing
import urllib # Check for new versions from the repo
import abc  # abstract base class libraries for attack templates


################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray

# /dev/null, send output from programs so they don't print to screen.
DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')








if __name__ == '__main__':
    RUN_CONFIG = RunConfiguration()
    try:
        banner(RUN_CONFIG)
        engine = RunEngine(RUN_CONFIG)
        engine.Start()
        #main(RUN_CONFIG)
    except KeyboardInterrupt: print R+'\n (^C)'+O+' interrupted\n'+W
    except EOFError:          print R+'\n (^D)'+O+' interrupted\n'+W

    RUN_CONFIG.exit_gracefully(0)
