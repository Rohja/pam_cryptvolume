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


def pam_sm_authenticate(pamh, flags, argv):
    syslog.syslog("[+] Starting pam_luks")
    pamh.authtok
    if pamh.authtok == None:
        syslog.syslog("[-] No password found, asking one.")
        passmsg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Luks volume key: ")
        rsp = pamh.conversation(passmsg)
        syslog.syslog("[+](debug) Password is " + rsp.resp)
        pamh.authtok = rsp.resp
        # so we should at this point have the password either through the
        # prompt or from previous module
    syslog.syslog("[+] Got password: " + pamh.authtok)
    if pamh.authtok == "totolol":
        return pamh.PAM_SUCCESS
    else:
        return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
