# Version 2.0 Rev 96 #
- Support to aircrack-ng 1.2-rc2 improved.

# Version 2.0 Rev 95 #
## WEP ##
- One bug fixed (Thanks Andrea from BackBox Linux)

# Version 2.0 Rev 94 #
## WEP ##
- One typo fixed (Reported by Andrea from BackBox Linux)

# Version 2.0 Rev 93 #
## WEP ##
- Behavior changes: Captured IVs during WEP attack will be saved to 'wep' folder under current directory by default, use "--wepnosave" to disable saving cap/ivs, "--wepsave" switch removed.
- Automatically count previously saved IV file when attacking WEP network. (*not very accurate, maybe duplicated IV in captured file?)
- More progress information (e.g. estimated finish time, additional IVs required) is shown when attacking WEP network.
- New switch "--wepsaveiv" to capture only IV packets (smaller file size) when attacking WEP network.
- Continue capturing if IVs are not enough to solve the key.

## WPA ##
- WPA cracking using pyrit and cowpatty added, option to use hash file (*experimental*) added.

## Network Interface ##
- Network functions clean up. Now more object-orientated.
- Switch "--mon-iface" removed, now wifite will determine automatically if the interface is already in monitor mode. Please use "-i" instead. 

## Others ##
- Fixed an error when analyzing .cap file.

# Version 2.0 Rev 92 #
- Codes clean up, slighly more modular
- Update route improved
- Change default folder for WPA handshake from 'hs' to 'wpa', old folder will be renamed automatically

# Version 2.0 Rev 91 #
- Fixed a bug which cause program exit if selecting targets using numbers
- New switch "--wpssave" to save the progress of WPS PIN attack (useful if you are running live CD and don't want to backup the file manually)
- Codes clean up

# Version 2.0 Rev 90 #
- Fixed four typos
- Automatically find *phpbb.txt* as dictionary file instead of hard-coding the path

# Version 2.0 Rev 89 #
- Minor message tweak
- I accidentally covert the last two releases to evil CRLF line ending, now move back to LF line ending.
- Modified --timeout/--attack/--scan switch: now "bBSSID+" means AP contains BSSID with associated client, same meaning for "eSSID+".

# Version 2.0 Rev 88 #
- Tidy up message printing 
- Modified "--timeout" switch for better flexibility in scanning state (e.g. "--timeout bBSSID,n\>30,600" means to timeout if target contains BSSID is found or total targets exceed 30, or after 10 minutes.)
- Prompt to install missing programs.
- Add "--debug" switch to print debug message.

# Version 2.0 Rev 87 #
- Save/load decloaked hidden network.
- Save/load scanned network.
- Decloaking hidden networks without waiting.
- Add lots of filters (e.g. WPA+ for WPA network with clients, WPA1 for WPA network with one client, -p<20 to exclude network with power below 20dB etc).
- Timeout when scanning networks.
- List wireless AP in two columns 
- List number of clients for each wireless AP, instead of just the word "CLIENT(S)"
- Max rows to show when scanning networks
- Tidy up the help page (e.g. separate the interface setting into new INTERFACE section)
- Default to skip network if WPA handshake file is found (can be override by --recapture)
- Tidy up message printing (*incomplete*)
- Fix a bug that show all APs has no client

# Version 2.0 #

The biggest change from version 1 is support for ["reaver"](http://reaver-wps.googlecode.com/), a Wifi-Protected Setup (WPS) attack tool.  Reaver can compromise the PIN and PSK for many routers that have WPS enabled, usually within hours.

Other changes include a complete code re-write with bug fixes and added stability.  Due to problems with the Python Tkinter suite, the GUI has been left out of this latest version.

