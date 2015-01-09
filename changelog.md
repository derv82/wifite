# Version 2.0 Rev 91 #
- Fixed a bug which cause program exit if selecting targets using numbers
- New switch "--wpssave" to save the progress of WPS PIN attack (useful if you are running live CD and don't want to backup the file manually)
- Codes clean up

# Version 2.0 Rev 90 #
- Fixed four typos
- Automatically find *phpbb.txt* as dictionary file instead of hard-coding the path+

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

