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

def ask_for_password(pamh):
    passmsg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Luks volume key: ")
    rsp = pamh.conversation(passmsg)
    syslog.syslog("[+] Got password: " + rsp.resp)
    return rsp.resp


def pam_sm_authenticate(pamh, flags, argv):
    syslog.syslog("[+] Starting pam_luks")
    pamh.authtok
    if pamh.authtok == None:
        syslog.syslog("[-] No existing password, asking for one.")
        pamh.authtok = ask_for_password(pamh)
        if pamh.authtok == None:
            return pamh.PAM_AUTH_ERR
    syslog.syslog("[~] FIXME: check if already mounted")
    trycount = 0
    mounted = False
    while mounted == False and trycount < 3:
        syslog.syslog("[~] FIXME: try mount")
        if mounted == True:
            return pamh.PAM_SUCCESS
        else:
            pamh.authtok = ask_for_password(pamh)
        trycount += 1
    syslog.syslog("[x] Authentification error.")
    return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
