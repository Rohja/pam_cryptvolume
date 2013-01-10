#!/usr/bin/env python
##
## pam_cryptvolume.py for PAM_CRYPTVOLUME in /home/rohja/epitech-crypto-pamela
##
## Made by Paul "Rohja" Lesellier
## Login   <rohja@rohja.com>
##
## Started on  Wed Dec 19 14:32:37 2012
##

import syslog
import os
import json
import subprocess
import hashlib

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

def getmd5(string):
    m = hashlib.md5()
    m.update(string)
    return m.hexdigest()

# Containers support

class CryptSetupManager():
    ERR_ALREADYOPEN = 239
    ERR_ALREADYMOUNT = 32
    SUCCESS = 0

    def __init__(self, from_, to_):
        self.from_ = from_
        self.to_ = to_

    def activate(self, passwd):
        cmd = "echo '%s' | cryptsetup luksOpen %s %s" % (passwd, self.from_, getmd5(self.from_))
        ret = subprocess.call(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        return ret

    def mount(self):
        cmd = "mount /dev/mapper/%s %s" % (getmd5(self.from_), self.to_)
        ret = subprocess.call(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        return ret

    def deactivate(self):
        syslog.syslog("[~] Trying to deactivate luks.")
        cmd = "cryptsetup luksClose %s" % getmd5(self.from_)
        ret = subprocess.call(cmd, shell=True)
        syslog.syslog("[~] Subprocess return value = %d" % ret)
        return ret

# Functions

def send_error_msg(pamh, msg):
    return send_msg(pamh, pamh.PAM_ERROR_MSG, "[luks] " + msg)

def send_info_msg(pamh, msg):
    return send_msg(pamh, pamh.PAM_TEXT_INFO, "[luks] " + msg)

def send_msg(pamh, msg_style, msg):
    pammsg = pamh.Message(msg_style, msg)
    rsp = pamh.conversation(pammsg)
    return rsp

def ask_for_password(pamh):
    passmsg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Luks volume key: ")
    rsp = pamh.conversation(passmsg)
    return rsp.resp

def check_initial_passwd(pamh):
    pamh.authtok
    if pamh.authtok == None:
        syslog.syslog("[-] No existing password, asking for one.")
        pamh.authtok = ask_for_password(pamh)
        if pamh.authtok == None:
            send_error_msg(pamh, "[luks] Unknow error while trying to get password.")
            syslog.syslog("[x] NO PASSWORD - Unknow error.")
            return False
    return True

def check_config_dict(config_dict):
    if type(config_dict) is not list:
        syslog.syslog("[x] Configuration file does not contains a list.")
        return False
    for entry in config_dict:
        if 'from' not in entry or 'to' not in entry:
            syslog.syslog("[x] Missing field in configuration structure. (%s)"
                          % str(entry))
            return False
        if type(entry['from']) is not str or type(entry['to']) is not str:
            syslog.syslog("[x] Bad data type in configuration structure. (%s)"
                          % str(entry))
            return False
    return True

def read_config_file(pamh):
    config_path = os.path.join("/home/", pamh.user, ".pam_cryptvolume")
    syslog.syslog("[+] Reading configuration file: %s." % config_path)
    if not os.path.isfile(config_path):
        syslog.syslog("[x] Configuration file %s is not a file or don't exist." % config_path)
        send_error_msg(pamh, "Error with configuration file.")
        return False
    try:
        config_file = open(config_path)
    except IOError, e:
        syslog.syslog("[x] Configuration file error: %s" % e.strerror)
        send_error_msg(pamh, "Error with configuration file.")
        return False
    config_content = config_file.read()
    try:
        config_dict = json.loads(config_content, object_hook=_decode_dict)
    except ValueError:
        syslog.syslog("[x] Bad configuration file format.")
        send_error_msg(pamh, "Error with configuration file.")
        return False
    if not check_config_dict(config_dict):
        syslog.syslog("[x] Bad fields in configuration file.")
        return False
    return config_dict

def try_mount(pamh, entry):
    send_info_msg(pamh, "Trying to open and mount %s" % entry['from'])
    syslog.syslog("[+] Activating and mounting entry: %s" % str(entry))
    luks = CryptSetupManager(entry["from"], entry["to"])

    try_count = 0
    activated = False
    password = pamh.authtok
    while try_count < 3:
        ret = luks.activate(password)
        if ret == CryptSetupManager.ERR_ALREADYOPEN:
            # Maybe SUCESS - Bad deconnection or already in use by someone else.
            send_info_msg(pamh, "Luks volume %s already opened!" % entry['from'])
            activated = True
            break
        elif ret == CryptSetupManager.SUCCESS:
            # SUCESS - Activation seem ok.
            send_info_msg(pamh, "Luks volume %s opened whit success!" % entry['from'])
            activated = True
            break
        password = ask_for_password(pamh)
        try_count += 1

    if activated:
        ret = luks.mount()
        if ret == CryptSetupManager.ERR_ALREADYMOUNT:
            send_error_msg(pamh, "Luks volume already mounted!")
        elif ret == CryptSetupManager.SUCCESS:
            send_info_msg(pamh, "Luks volume mounted to %s." % entry['to'])
        else:
            luks.deactivate()
    else:
        send_error_msg(pamh, "Unable to activate volume %s!" % entry['from'])

def try_umount_and_deactivate(pamh, entry):
    send_info_msg(pamh, "Trying to umount and deactivate %s" % entry['to'])
    syslog.syslog("[+] Deactivating and umounting entry: %s" % str(entry))
    luks = CryptSetupManager(entry["from"], entry["to"])

    ret1 = subprocess.call("/bin/umount /dev/mapper/%s" % getmd5(entry['from']),
                           shell=True,
                           stderr=subprocess.PIPE,
                           stdout=subprocess.PIPE)
    if ret1 != CryptSetupManager.SUCCESS:
        send_info_msg(pamh, "Can't umount %s." % entry['to'])
    ret2 = subprocess.call("cryptsetup luksClose %s" % getmd5(entry['from']),
                           shell=True,
                           stderr=subprocess.PIPE,
                           stdout=subprocess.PIPE)
    if ret2 != CryptSetupManager.SUCCESS:
        send_info_msg(pamh, "Can't close volume %s" % entry['from'])
    if CryptSetupManager.SUCCESS in [ret1, ret2]:
        send_info_msg(pamh, "Success!")

# Pam

def pam_sm_authenticate(pamh, flags, argv):
    syslog.syslog("[+] Starting pam_cryptvolume")
    if check_initial_passwd(pamh) is False:
        return pamh.PAM_AUTH_ERR
    syslog.syslog("[+] Password in memory.")
    config = read_config_file(pamh)
    if config is False:
        return pamh.PAM_AUTH_ERR

    for entry in config:
        try_mount(pamh, entry)

    return pamh.PAM_SUCCESS

def pam_sm_end(pamh):
    syslog.syslog("[+] Cleaning pam_cryptvolume for user %s" % pamh.user)
    config = read_config_file(pamh)
    if config is False:
        return pamh.PAM_AUTH_ERR

    for entry in config:
        try_umount_and_deactivate(pamh, entry)

    return pamh.PAM_SUCCESS

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
