#!/usr/bin/env python
__author__ = "Moxie Marlinspike"
__email__  = "moxie@thoughtcrime.org"
__license__= """
Copyright (c) 2009 Moxie Marlinspike <moxie@thoughtcrime.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

import time, os, sys
import argparse
import subprocess

from struct import *
from knockknock.Profile import Profile

def usage():
    print "Usage: knockknock.py -p <portToOpen> <host>"
    sys.exit(2)

def valid_host_path(string):
    host_dir = ""
    path = os.path.abspath(string)
    #Check if relative path, absolute path, or neither.
    if os.path.exists(path):
        host_dir = path
    elif os.path.exists(os.path.join("/", string)):
        host_dir = os.path.join("/", string)
    else:        
        msg = "The path {0} is not a valid knockknock path.".format(string)
        raise argparse.ArgumentTypeError(msg)
    if not os.path.isdir(host_dir):
        msg = "The path {0} must be a directory.".format(string)
        raise argparse.ArgumentTypeError(msg)
    for cfg in ["counter". "cipher.key", "mac.key", "config"]:
        if not os.isfile(os.path.join(host_dir, cfg)):
            msg = "The path {0} is not a valid knockknock host directory.".format(string)
            raise argparse.ArgumentTypeError(msg)
    return host_dir

def parseArguments(argv):

    port       = 0
    host       = ""
    directory  = None
    arg_p = argparse.ArgumentParser("Open a port on a specified KnockKnock server.")
    arg_p.add_argument("-p", "--port", type=int, choices=range(1, 65535), help="What port to open on the KnockKnock server.")
    arg_p.add_argument("-h", "--host", help="The host to connect to.")
    arg_p.add_argument("-d", "--directory", help="The folder where the config, keys, and counter are stored.", type=valid_host_path)
    args = arg_parser.parse_args()
    
    return (args.port, args.host, args.directory)

def getProfile(host, directory=None):
    #process a directory is passed
    if directory:
        if os.path.isdir(directory):
            return Profile(directory, hostname=host)
        else:
            print "Error: the directory at {0} does not exist.".format(directory)
            sys.exit(2)
    #Process default directory
    homedir = os.path.expanduser('~')
    
    if not os.path.isdir(homedir + '/.knockknock/'):
        print "Error: you need to setup your profiles in " + homedir + '/.knockknock/'
        sys.exit(2)

    if not os.path.isdir(homedir + '/.knockknock/' + host):
        print 'Error: profile for host ' + host + ' not found at ' + homedir + '/.knockknock/' + host
        sys.exit(2)

    return Profile(homedir + '/.knockknock/' + host)

def verifyPermissions():
    if os.getuid() != 0:
        print 'Sorry, you must be root to run this.'
        sys.exit(2)    

def existsInPath(command):
    def isExe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    for path in os.environ["PATH"].split(os.pathsep):
        exeFile = os.path.join(path, command)
        if isExe(exeFile):
            return exeFile

    return None

def main(argv):
    (port, host, directory) = parseArguments(argv)
    verifyPermissions()
    
    profile      = getProfile(host, directory)
    port         = pack('!H', int(port))
    packetData   = profile.encrypt(port)
    knockPort    = profile.getKnockPort()
    
    (idField, seqField, ackField, winField) = unpack('!HIIH', packetData)

    hping = existsInPath("hping3")

    if hping is None:
        print "Error, you must install hping3 first."
        sys.exit(2)

    command = [hping, "-S", "-c", "1",
               "-p", str(knockPort),
               "-N", str(idField),
               "-w", str(winField),
               "-M", str(seqField),
               "-L", str(ackField),
               host]
    
    try:
        subprocess.call(command, shell=False, stdout=open('/dev/null', 'w'), stderr=subprocess.STDOUT)
        print 'Knock sent.'

    except OSError:
        print "Error: Do you have hping3 installed?"
        sys.exit(3)

if __name__ == '__main__':
    main(sys.argv[1:])
