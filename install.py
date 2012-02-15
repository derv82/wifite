#!/usr/bin/python

"""
	Installs recommended/required packages used by Wifite
"""

from subprocess import Popen, PIPE, call
from sys import stdout
from shutil import copy
import os

MANAGER=''

DN=open(os.devnull, 'a')

def main():
	global MANAGER
	if program_exists('apt-get'): MANAGER = 'apt-get'
	elif program_exists('yum'):   MANAGER = 'yum'
	else: MANAGER = ''
	
	if MANAGER != '': print 'using package manager: "%s"' % MANAGER
	else: print 'no package manager found!'
	
	result = install_aircrack()
	print 'result = %s' % str(result)


def program_exists(program):
	proc = Popen(['which', program], stdout=PIPE)
	return proc.communicate()[0].strip() != ''


def install_package(package):
	if MANAGER == '': return False
	proc = Popen([MANAGER, 'install', package], stdout=PIPE, stderr=PIPE)
	comm = proc.communicate()
	txt = comm[1].split('\n')
	if comm[0].find('already the newest version') != -1:
		print '%s is already installed' % package
		return True
	
	if len(txt) == 0 or txt[0] == '':
		print '%s installed successfully' % package
		return True
	
	print 'error while installing %s' % package
	return False


def install_aircrack():
	if program_exists('aircrack-ng'): 
		print 'aircrack-ng already installed'
		return True
	
	if install_package('aircrack-ng'): return True

	script = """
wget http://download.aircrack-ng.org/aircrack-ng-1.1.tar.gz
tar -zxvf aircrack-ng-1.1.tar.gz
cd aircrack-ng-1.1
make
sudo make install
cd ..
rm -rf aircrack-ng-1.1
"""
	shell = Popen(['sh'], stdin=PIPE, stdout=PIPE)
	shell.stdin.write(script + '\n')
	lines = shell.stdout.split('\n')
	for line in lines: print '"%s"' % line
	
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt: pass
