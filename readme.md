wifite
======

An automated wireless attack tool.


What's New?
-----------

The biggest change from version 1 is support for the tool [reaver](http://reaver-wps.googlecode.com/), a Wifi-Protected Setup (WPS) attack tool.  Reaver can compromise the PIN and PSK for many routers that have WPS enabled, usually within hours. The tool pixiewps is also included and the script is up-to-date supporting the Pixie dust attack.

Another big change is the support for [hashcat](https://hashcat.net). Now Wifite can perform WPA cracking with multiGPUs at the same time. 

Other changes include a complete code re-write with bug fixes and added stability.  Due to problems with the Python Tkinter suite, the GUI has been left out of this latest version.


About
-----

_Wifite is only for Linux._

Wifite was designed for use with pentesting distributions of Linux, such as [Kali Linux](http://www.kali.org/), [Pentoo](http://www.pentoo.ch/), [BackBox](http://www.backbox.org); any Linux distributions with wireless drivers patched for injection. The script appears to also operate with Ubuntu 14.04/15.04, Debian 8 and Fedora 16.

Wifite must be run as __root__. This is required by the suite of programs it uses. Running downloaded scripts as root is a bad idea. I recommend using the Kali Linux bootable Live CD, a bootable USB stick (for persistent), or a virtual machine. Note that Virtual Machines cannot directly access hardware so a wireless USB dongle would be required.

Wifite assumes that you have a wireless card and the appropriate drivers that are patched for injection and promiscuous/monitor mode.



Dependencies
------------

In order to install all the prerequisites execute the following script. This script is for debian-based Linux distributions.

```{r, engine='bash'}
bash deps.sh
bash deps.sh [CUDA or AMD]
```
Execution
---------

To download and execute wifite, run the commands below:

```sh
git clone https://github.com/enovella/wifite.git
chmod +x wifite.py
sudo python wifite.py
```


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

* [__reaver__](http://code.google.com/p/reaver-wps/), a Wifi-Protected Setup (WPS) attack tool.  Reaver includes a scanner "walsh" (or "wash") for detecting WPS-enabled access points. Wifite uses Reaver to scan for and attack WPS-enabled routers.

* [__hashcat__](https://hashcat.net), the best and fastest WPA PSK key MultiGPU cracker. Worlds fastest password cracker. It can be run as follows: 
```
python wifite.py --aircrack --hashcat-gpu --dic /wordlists/rockyou.txt
```

* [__pyrit__](http://code.google.com/p/pyrit/), a GPU cracker for WPA PSK keys. Wifite uses pyrit (if found) to detect handshakes. In the future, Wifite may include an option to crack WPA handshakes via pyrit.

* __tshark__. Comes bundled with [Wireshark](http://www.wireshark.org/), packet sniffing software.

* [__cowpatty__](http://www.willhackforsushi.com/Cowpatty.html), a WPA PSK key cracker. Wifite uses cowpatty (if found) to detect handshakes.


Licensing
---------

Wifite is licensed under the GNU General Public License version 2 (GNU GPL v2).

```
(C) 2010-2012 Derv Merkler
```

```
(C) 2015-2016 Eduardo Novella   (@enovella_)
```