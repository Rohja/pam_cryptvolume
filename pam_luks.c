/*
** pam_luks.c for Pam Luks in /home/rohja/epitech-crypto-pamela
** 
** Made by paul lesellier
** Login   <lesell_p@epitech.net>
** 
** Started on  Tue Dec 18 16:31:12 2012 paul lesellier
** Last update Tue Dec 18 16:31:12 2012 paul lesellier
*/

#include <security/pam_appl.h>

/* pam_start(...) - Return Values
   PAM_ABORT - General failure.
   PAM_BUF_ERR - Memory buffer error.
   PAM_SUCCESS - Transaction was successful created.
   PAM_SYSTEM_ERR - System error, for example a NULL
     pointer was submitted instead of a pointer to
     data. */
int	pam_start(const char *service_name,
		  const char *user,
		  const struct pam_conv *pam_conversation,
		  pam_handle_t **pamh)
{
  return (0);
}

/* pam_authenticate(...) -  Return Values
   PAM_ABORT - The application should exit immediately
     after calling pam_end(3) first.
   PAM_AUTH_ERR - The user was not authenticated.
   PAM_CRED_INSUFFICIENT - For some reason the
     application does not have sufficient credentials
     to authenticate the user.
   PAM_AUTHINFO_UNVAIL - The modules were not able to
     access the authentication information. This might
     be due to a network or hardware failure etc.
   PAM_MAXTRIES - One or more of the authentication
     modules has reached its limit of tries
     authenticating the user. Do not try again.
   PAM_SUCCESS - The user was successfully
     authenticated.
   PAM_USER_UNKNOWN - User unknown to authentication
     service. */
int	pam_authenticate(pam_handle_t *pamh,
			 int flags)
{
  return (0);
}

/* pam_end(...) - Return Values
   PAM_SUCCESS - Transaction was successful terminated.
   PAM_SYSTEM_ERR - System error, for example a NULL
     pointer was submitted as PAM handle or the
     function was called by a module. */
int	pam_end(pam_handle_t *pamh,
		int pam_status)
{
  return (0);
}
