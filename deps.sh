#!/bin/bash

# @author : Eduardo Novella
# 2015-11-13


APTCMD="apt-get"
APT_CANDIDATES="wget tshark gzip bzip2 tar p7zip p7zip-full"
DEPS_PYRIT="python2.7-dev python2.7-libpcap subversion libpcap-dev nvidia-cuda-toolkit linux-headers-$(uname -r)"
DEPS_AIRCRACK="build-essential libssl-dev pkg-config subversion libsqlite3-dev libpcap-dev sqlite3 libsqlite3-dev make gcc"
DEPS_REAVER_PIXIE="git libssl-dev"

VIOLET="\e[01;35m"
BLUE="\e[01;34m"
YELLOW="\e[01;33m"
RED="\e[01;31m"
GREEN="\e[01;32m"
END="\e[00m"


# Check for root privileges
if [ $UID -eq 0 ]
then
    SUDO=""
else
    SUDO="sudo"
fi


# Check if number of arguments introduced is one
if [ "$#" -ne 1 ]
then 
	echo -e "\nUsage: bash $0 AMD"
	echo -e "       bash $0 CUDA\n"
	echo -e "AMD is your hashcat choice for AMD GPUs"
	echo -e "CUDA is your hashcat choice for CUDA GPUs\n"
	exit
fi

# Functions to install programs
function install_hashcat()
{

	cd ~
	if [ "AMD" == "$1" ]; then
		prefix="ocl"
	elif [ "CUDA" == "$1" ]; then
		prefix="cuda"
	else 
		exit
	fi

	wget https://hashcat.net/files/${prefix}Hashcat-1.37.7z
	7z x ${prefix}Hashcat-1.37.7z
	echo -e "\n[+] Your $RED HASHCAT_PATH $END to add in wifite.py is $GREEN $PWD/${prefix}Hashcat-1.37 $END\n"
	rm ${prefix}Hashcat-1.37.7z 2>/dev/null

}


function install_cowpatty
{
	cd /tmp
	wget http://www.willhackforsushi.com/code/cowpatty/4.6/cowpatty-4.6.tgz
	tar zxfv /tmp/cowpatty-4.6.tgz
	cd /tmp/cowpatty-4.6 
	$SUDO make clean 2>/dev/null
	make -j
	$SUDO make install
	rm -rf /tmp/cowpatty*
}



# function install_pyrit
# {

# 	$SUDO $APTCMD update
# 	$SUDO $APTCMD install $APT_CANDIDATES -y 
# 	$SUDO $APTCMD install $DEPS_PYRIT -y

# 	if [ "AMD" == "$1" ]; then
# 		prefix="opencl"
# 	elif [ "CUDA" == "$1" ]; then
# 		prefix="cuda"
# 	else 
# 		exit
# 	fi

# 	cd /tmp
# 	wget https://pyrit.googlecode.com/files/cpyrit-${prefix}-0.4.0.tar.gz
# 	tar xvzf cpyrit-${prefix}-0.4.0.tar.gz 
# 	cd cpyrit-${prefix}-0.4.0/
# 	$SUDO python setup.py install

# 	$SUDO rm -rf cpyrit*
# }

function install_pyrit
{
	$SUDO $APTCMD install pyrit -y 
}

function install_aircrack-ng-svn
{
 	$SUDO $APTCMD install $DEPS_AIRCRACK -y 

 	cd /tmp
 	svn co http://svn.aircrack-ng.org/trunk/ aircrack-ng
	cd aircrack-ng
	make pcre=true sqlite=true -j2
	$SUDO make pcre=true sqlite=true install

    rm -rf /tmp/aircrack*
}


function install_reaver-pixie
{
	$SUDO $APTCMD $DEPS_REAVER_PIXIE -y

	cd /tmp
	git clone https://github.com/wiire/pixiewps.git
	cd pixiewps/src
	make -j
	$SUDO make install

	cd /tmp
	git clone https://github.com/t6x/reaver-wps-fork-t6x
	cd reaver-wps-fork-t6x/src
	./configure
	make -j2
	$SUDO make install

	rm -rf /tmp/pixiewps /tmp/reaver-wps-fork-t6x
}




# MAIN
$SUDO $APTCMD update
install_cowpatty
install_pyrit
install_aircrack-ng-svn
install_reaver-pixie
install_hashcat $1