#!/usr/bin/env python
##
## pam_luks.py for PAM_LUKS in /home/rohja/epitech-crypto-pamela
##
## Made by Paul "Rohja" Lesellier
## Login   <rohja@rohja.com>
##
## Started on  Wed Dec 19 14:32:37 2012 paul lesellier
## Last update Wed Dec 19 14:32:37 2012 paul lesellier
##

import syslog
import os


def send_error_msg(pamh, msg):
    return send_msg(pamh, pamh.PAM_ERROR_MSG, "[luks] " + msg)

def send_info_msg(pamh, msg):
    return send_msg(pamh, pamh.PAM_TEXT_INFO, "[luks]" + msg)

def send_msg(pamh, msg_style, msg):
    pammsg = pamh.Message(msg_style, msg)
    rsp = pamh.conversation(pammsg)
    return rsp

def ask_for_password(pamh):
    passmsg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Luks volume key: ")
    rsp = pamh.conversation(passmsg)
    syslog.syslog("[~] Got password: " + rsp.resp)
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
    return False

def read_config_file(pamh):
    config_path = os.path.join("/home/", pamh.user, ".pam_luks")
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
        config_dict = json.loads(config_content)
    except ValueError:
        syslog.syslog("[x] Bad configuration file format.")
        send_error_msg(pamh, "Error with configuration file.")
        return False
    if not check_config_dict(config_dict):
        return False
    return config_dict

def pam_sm_authenticate(pamh, flags, argv):
    syslog.syslog("[+] Starting pam_luks")
    syslog.syslog("[|] Checking password existance.")
    if check_initial_passwd(pamh) is False:
        return pamh.PAM_AUTH_ERR
    syslog.syslog("[+] Password in memory.")
    config = read_config_file(pamh)
    if config is False:
        return pamh.PAM_AUTH_ERR

    syslog.syslog("[+] FIXME: check if already mounted")
    trycount = 0
    mounted = False

    send_info_msg(pamh, "[luks] Trying to mount /home/%s/secure_data" % pamh.user)
    while mounted == False and trycount < 3:
        syslog.syslog("[~] FIXME: try mount")
        # FIXME: Try mount
        if mounted == True:
            send_error_msg(pamh, "[luks] Successfuly mounted.")
            syslog.syslog("[+] Successfuly mounted.")
            return pamh.PAM_SUCCESS
        else:
            # FIXME: get explicit error message
            send_error_msg(pamh, "[luks] Error while mounting volume.")
            syslog.syslog("[-] Error while mounting volume")
            pamh.authtok = ask_for_password(pamh)
        trycount += 1

    send_error_msg(pamh, "[luks] Fatal error, can't mount volume.")
    syslog.syslog("[x] Authentification error.")
    return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
