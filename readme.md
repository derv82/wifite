wifite
======

An automated wireless attack tool.

Introduction
------------

wifite is a program automates attacking and cracking wireless access points protected by WEP, WPA with/without WPS. Traditionally it has to be done manually and involved numerous program with many parameters, which is very inconvenient for batch access points security auditing. This little python script saves your time by automatically attack chosen access points in batch.

Installation
------------

To download and execute wifite, run the commands below:

`wget https://github.com/derv82/wifite/raw/master/wifite.py` (devr82's orginal version) or `wget https://github.com/brianpow/wifite/raw/master/wifite.py` (my fork)  
`chmod +x wifite.py`  
`./wifite.py`  

Usage
-----


```
wifite.py --showb --attack all,-eMYWIFI,-wpa0,-wps2,wps1 --timeout 120,e,n\>50 --save ap --two 
```

Meaning: show BSSID when scanning; attack all APs excepts APs with name containing MYWIFI, exclude WPA APs without client, exclude both locked and WPS-enabled APs and include wps-enabled AP (i.e. remove WPS locked APs); Automatically attack APs after scanning for 120 seconds, or if hidden network is detected, or if total targets are more than 50; Save scanned APs into ap.csv and ap.cap; List APs in two columns.


Requirement
-----------

### Mandatory Requirement ###

#### Hardware ####

* Wireless card with supported driver for entering promiscuous/monitor mode and support packet injection (USB wireless dongle if you are running in virtual machine.)

#### Software ####

Pentesting distributions of Linux, such as [Kali Linux](http://www.kali.org/), [Pentoo](http://www.pentoo.ch/), [BackBox](http://www.backbox.org) (Ubuntu 11/10, Debian 6, and Fedora 16 may work but not confirmed).

Unless you are using very old distro of Linux, the following software should be pre-installed and available. Please see [the installation guide](https://github.com/derv82/wifite/wiki/Installation) on the wiki if you really need to install any of the tools below manually.

* [__Python 2.7.x__](http://python.org/getit/). wifite is a Python script and requires Python to run.

* [__aircrack-ng suite__](http://aircrack-ng.org/).
  This is absolutely required.  The specific programs used in the suite are: 
    * airmon-ng, 
    * airodump-ng, 
    * aireplay-ng, 
    * packetforge-ng, and
    * aircrack-ng.

* Standard linux programs.
  * iwconfig, ifconfig, which, iw

### Recommended Hardware/Software ###

#### Hardware ####

* Computer with NVIDIA or ATI display card (for accelerated cracking)

#### Software ####

_`*` indicates program is not included in [Backtrack 5 R1](http://www.backtrack-linux.org/)_

* `*`[__reaver__](https://github.com/t6x/reaver-wps-fork-t6x), a Wifi-Protected Setup (WPS) attack tool.  Reaver includes a scanner "walsh" (or "wash") for detecting WPS-enabled access points. wifite uses Reaver to scan for and attack WPS-enabled routers.

* `*`[__pyrit__](http://code.google.com/p/pyrit/), a GPU cracker for WPA PSK keys. Wifite uses pyrit (if found) to detect handshakes.

* __tshark__. Comes bundled with [Wireshark](http://www.wireshark.org/), packet sniffing software.

* [__cowpatty__](http://www.willhackforsushi.com/Cowpatty.html), a WPA PSK key cracker. Wifite uses cowpatty (if found) to detect handshakes.

#### Others ####

* Rainbow table (for accelerated cracking)

Licensing
---------

wifite is licensed under the GNU General Public License version 2 (GNU GPL v2).

(C) 2010-2015 Derv Merkler
