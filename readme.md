wifite
======

An automated wireless attack tool.

About
-----

_Wifite is for Linux only._

Wifite was designed for use with pentesting distributions of Linux, such as [Kali Linux](http://www.kali.org/), [Pentoo](http://www.pentoo.ch/), [BackBox](http://www.backbox.org); any Linux distributions with wireless drivers patched for injection. The script appears to also operate with Ubuntu 11/10, Debian 6, and Fedora 16.

Wifite must be run as __root__. This is required by the suite of programs it uses. Running downloaded scripts as root is a bad idea. I recommend using the Kali Linux bootable Live CD, a bootable USB stick (for persistent), or a virtual machine. Note that Virtual Machines cannot directly access hardware so a wireless USB dongle would be required.

Wifite assumes that you have a wireless card and the appropriate drivers that are patched for injection and promiscuous/monitor mode.


Execution
---------

To download and execute wifite, run the commands below:

`wget https://github.com/derv82/wifite/raw/master/wifite.py` (devr82's version) or `wget https://github.com/brianpow/wifite/raw/master/wifite.py` (brianpow's version)  
`chmod +x wifite.py`  
`./wifite.py`  


### More Complex Examples (only work in brianpow's version)###

```
wifite.py --mac --showb --attack all,-eMYWIFI,-wpa0 --timeout 120,e,n\>50 --save ap.csv --two --wpssave --wepsave
```
Meaning: Anonymize my MAC address; show BSSID when scanning; attack all APs excepts APs with name containing MYWIFI, exclude WPA APs without client; Automatically attack APs after scanning for 120 seconds, or if hidden network is detected, or if total targets are more than 50; Save scanned APs into ap.csv; List APs in two columns; Save progress of WPS PIN attack in 'wps' folder under current folder; Save captured IVs file in 'wep' folder under current folder.


Required Programs
-----------------

Please see [the installation guide](https://github.com/derv82/wifite/wiki/Installation) on the wiki for help installing any of the tools below.

* [__Python 2.7.x__](http://python.org/getit/). Wifite is a Python script and requires Python to run.

* [__aircrack-ng suite__](http://aircrack-ng.org/).
  This is absolutely required.  The specific programs used in the suite are: 
    * airmon-ng, 
    * airodump-ng, 
    * aireplay-ng, 
    * packetforge-ng, and
    * aircrack-ng.

* Standard linux programs.
  * iwconfig, ifconfig, which, iw

Suggested Programs
------------------

_`*` indicates program is not included in [Backtrack 5 R1](http://www.backtrack-linux.org/)_

* `*`[__reaver__](http://code.google.com/p/reaver-wps/), a Wifi-Protected Setup (WPS) attack tool.  Reaver includes a scanner "walsh" (or "wash") for detecting WPS-enabled access points. Wifite uses Reaver to scan for and attack WPS-enabled routers.

* `*`[__pyrit__](http://code.google.com/p/pyrit/), a GPU cracker for WPA PSK keys. Wifite uses pyrit (if found) to detect handshakes. In the future, Wifite may include an option to crack WPA handshakes via pyrit.

* __tshark__. Comes bundled with [Wireshark](http://www.wireshark.org/), packet sniffing software.

* [__cowpatty__](http://www.willhackforsushi.com/Cowpatty.html), a WPA PSK key cracker. Wifite uses cowpatty (if found) to detect handshakes.

Licensing
---------

Wifite is licensed under the GNU General Public License version 2 (GNU GPL v2).

(C) 2010-2015 Derv Merkler
