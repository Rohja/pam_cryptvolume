#
# Duplicates pam_permit.create#
DEFAULT_USER    = "nobody"

import syslog

def pam_sm_authenticate(pamh, flags, argv):
  # INFO MESSAGE
  # try:
  #   pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "pam_sm_authenticate()"))
  # except pamh.exception:
  #   return pamh.PAM_SYSTEM_ERR
  syslog.syslog("pam_sm_authenticate() executed from pam_python.so")
  # ChECKING STUFF
  try:
    user = pamh.get_user(None)
  except pamh.exception, e:
    return e.pam_result
  if user == None:
    pam.user = DEFAULT_USER
  return pamh.PAM_SUCCESS

def pam_sm_setcred(pamh, flags, argv):
  print "pam_sm_setcred()"
  return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
  print "pam_sm_acct_mgmt()"
  return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
  print "pam_sm_open_session()"
  return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
  print "pam_sm_close_session()"
  return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
  print "pam_sm_chauthtok()"
  return pamh.PAM_SUCCESS

'''
= HOW TO USE =
Assuming it and pam_python.so are in the directory
  /lib/security adding these rules to
  /etc/pam.conf would run it:

login account   requisite   pam_python.so pam_accept.py
login auth      requisite   pam_python.so pam_accept.py
login password  requisite   pam_python.so pam_accept.py
login session   requisite   pam_python.so pam_accept.py
'''