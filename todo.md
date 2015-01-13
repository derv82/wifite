# GENERAL #
* Restore same command-line switch names from v1
* If device already in monitor mode, check for and, if applicable, use macchanger
* Group network interface related functions into a class
* More comments on code

# WPS #
* Mention reaver automatically resumes sessions
* Warning about length of time required for WPS attack (*hours*)
* Show time since last successful attempt
* Percentage of tries/attempts ?
* Update code to work with reaver 1.4 ("x" sec/att)
* Save reaver.db?

# WEP # 
* Option to capture only IVS packets (uses --output-format ivs,csv)
   - not compatible on older aircrack-ng's.
      + Just run "airodump-ng --output-format ivs,csv", "No interface specified" = works
   - would cut down on size of saved .caps
* Include previously captured IVs in total_IVs

# reaver # 
* MONITOR ACTIVITY!
* Enter ESSID when executing (?)
* Ensure WPS key attempts have begun.
* If no attempts can be made, stop attack
   - During attack, if no attempts are made within X minutes, stop attack & Print
   - Reaver's output when unable to associate:
     [!] WARNING: Failed to associate with AA:BB:CC:DD:EE:FF (ESSID: ABCDEF)
   - If failed to associate for x minutes, stop attack (same as no attempts?)

# MIGHTDO # 
* WPA - crack (pyrit/cowpatty) (not really important)
* Test injection at startup? (skippable via command-line switch)
