#!/usr/bin/env python
##
## cryptvolume-conf.py for CryptVolume-Conf in /home/rohja/Projects/epitech-crypto-pamela
## 
## Made by Paul "Rohja" Lesellier
## Login   <rohja@rohja.com>
## 
## Started on  Thu Jan 10 12:52:34 2013
##

import sys
import json
import subprocess
from os import path

# Fcts

def cvc_list(argv):
    config = cvc_load_config()
    print "Crypted Volumes List:"
    if len(config) == 0:
        print "~ No volumes in configuration"
    i = 1
    for entry in config:
        print "[%d] %s -> %s" % (i, entry.get('from'), entry.get('to'))
        i += 1
    return True

def cvc_add(argv):
    if len(argv) != 4:
        print "ERROR: You need to specify a volume and a mount point."
        return False
    mount_from = argv[2]
    mount_to = argv[3]
    config = cvc_load_config()
    for entry in config:
        if entry.get("from") == mount_from:
            print "ERROR: Volume %s already used in configuration file." % mount_from
            return False
        if entry.get("to") == mount_to:
            print "ERROR: Mount point %s already used in configuration file." % mount_to
            return False
    config.append({"from": mount_from, "to": mount_to})
    if cvc_write_config(config):
        print "Configuration file updated successfuly!"
        return True
    return False

def cvc_remove(argv):
    if len(argv) != 3:
        print "ERROR: You need to specify which volume you want to remove from configuration."
        return False
    to_delete = argv[2]
    config = cvc_load_config()
    new_config = []
    found = False
    for entry in config:
        if entry.get("from") != to_delete and entry.get("to") != to_delete:
            new_config.append(entry)
        else:
            found = True
    if not found:
        print "ERROR: Can't find selected mount point or volume"
        return False
    if cvc_write_config(new_config):
        print "Configuration file updated successfuly!"
        return True
    return False

def cvc_check(argv):
    config = cvc_load_config()
    i = 1
    for entry in config:
        if "from" not in entry or "to" not in entry:
            print "ERROR: Entry #%d have missing fields." % i
            return False
        ret = subprocess.call("cryptsetup isLuks %s" % entry["from"], shell=True,
                              stderr=subprocess.PIPE,
                              stdout=subprocess.PIPE)
        if ret != 0:
            print "WARNING: %s seems to be an invalid Luks volume." % entry['from']
        i += 1
    return True
# Tools

def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv

def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
           key = key.encode('utf-8')
        if isinstance(value, unicode):
           value = value.encode('utf-8')
        elif isinstance(value, list):
           value = _decode_list(value)
        elif isinstance(value, dict):
           value = _decode_dict(value)
        rv[key] = value
    return rv

def cvc_usage(name):
    print """- CryptVolume Configurator -
USAGE: %s <params>

PARAMS:
  %s list -> Display all volumes and mount point currently
    set in the configuration file.
  %s add <volume> <mountpoint> -> Add a volume in the configuration
    file.
  %s remove [<volume>/<mountpoint>] -> Delete a volume/mountpoint from
    the configuration.
  %s check -> Check the configuration file validity.
""" % (name, name, name, name, name)
    return 0

def cvc_load_config():
    home = path.expanduser("~")
    try:
        config = open(path.join(home, ".pam_cryptvolume"))
    except IOError:
        print "WARNING: Can't load configuration, using an empyt one."
        return []
    config_content = config.read()
    try:
        config_dict = json.loads(config_content, object_hook=_decode_dict)
    except ValueError:
        print "WARNING: Can't load you config file (maybe there's bad data in it.) Using an empyt one."
        return []
    else:
        return config_dict

def cvc_write_config(config):
    home = path.expanduser("~")
    try:
        config_file = open(path.join(home, ".pam_cryptvolume"), 'w+')
    except IOError:
        print "ERROR: Can't open config file with write access."
        return False
    config_string = json.dumps(config)
    config_file.write(config_string)
    return True

# Main
CRYPTVOLUME_CMDS = {
    "list": cvc_list,
    "add": cvc_add,
    "remove": cvc_remove,
    "check": cvc_check
    }

def cryptvolumeconf(argv):
    if len(argv) == 1 or argv[1] not in CRYPTVOLUME_CMDS:
        cvc_usage(argv[0])
    else:
        return CRYPTVOLUME_CMDS[argv[1]](argv)
    return 0

if __name__ == "__main__":
    cryptvolumeconf(sys.argv)
