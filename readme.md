THIS PROJECT IS IN LIFE-SUPPORT MODE
------------------------------------

This repo tracks the old version of Wifite (*v1*) which does not receive frequent updates and has many bugs (check out the *Isuses* tab!).

There's a new version of Wifite (*Wifite2*) available at [https://github.com/derv82/wifite2](https://github.com/derv82/wifite2). *Wifite2* has more features, bug fixes, and reliability.

*Try the new Wifite2, especially if you're having problems with Wifite v1*


About
-----

_Wifite is for Linux only._

Wifite is an automated wireless attack tool.

Wifite was designed for use with pentesting distributions of Linux, such as [Kali Linux](http://www.kali.org/), [Pentoo](http://www.pentoo.ch/), [BackBox](http://www.backbox.org); any Linux distributions with wireless drivers patched for injection. The script appears to also operate with Ubuntu 11/10, Debian 6, and Fedora 16.

Wifite must be run as __root__. This is required by the suite of programs it uses. Running downloaded scripts as root is a bad idea. I recommend using the Kali Linux bootable Live CD, a bootable USB stick (for persistent), or a virtual machine. Note that Virtual Machines cannot directly access hardware so a wireless USB dongle would be required.

Wifite assumes that you have a wireless card and the appropriate drivers that are patched for injection and promiscuous/monitor mode.


Execution
---------

To download and execute wifite, run the commands below:

`wget https://raw.github.com/derv82/wifite/master/wifite.py`  
`chmod +x wifite.py`  
`./wifite.py`  


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

* `*`[__reaver__](https://github.com/t6x/reaver-wps-fork-t6x), a Wifi-Protected Setup (WPS) attack tool.  Reaver includes a scanner "walsh" (or "wash") for detecting WPS-enabled access points. Wifite uses Reaver to scan for and attack WPS-enabled routers.

* `*`[__pyrit__](https://github.com/JPaulMora/Pyrit), a GPU cracker for WPA PSK keys. Wifite uses pyrit (if found) to detect handshakes. In the future, Wifite may include an option to crack WPA handshakes via pyrit.

* __tshark__. Comes bundled with [Wireshark](http://www.wireshark.org/), packet sniffing software.

* [__cowpatty__](http://www.willhackforsushi.com/Cowpatty.html), a WPA PSK key cracker. Wifite uses cowpatty (if found) to detect handshakes.


Licensing
---------

Wifite is licensed under the GNU General Public License version 2 (GNU GPL v2).

(C) 2010-2012 Derv Merkler
