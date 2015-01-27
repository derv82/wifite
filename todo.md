# GENERAL #
* Restore same command-line switch names from v1
* If device already in monitor mode, check for and, if applicable, use macchanger
* More comments on code
* Attack all targets simultaneously?

# WPS #
* Mention reaver automatically resumes sessions
* Show time since last successful attempt
* Percentage of tries/attempts ?
* Update code to work with reaver 1.4 ("x" sec/att)
* Save reaver.db?

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
* Test injection at startup? (skippable via command-line switch)
