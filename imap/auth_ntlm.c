#include <ntlm.h>

int imap_auth_ntlm(IMAP_DATA *idata, char *user, char *pass)
{
  char buf[LONG_STRING];
  char seq[16];
  char tmpstr[32];
  int len;
  tSmbNtlmAuthRequest   request;              
  tSmbNtlmAuthChallenge challenge;
  tSmbNtlmAuthResponse  response;

  mutt_message _("NTLM Authentication...");
  imap_make_sequence (seq, sizeof (seq));

  snprintf (buf, sizeof (buf), "%s AUTHENTICATE NTLM\r\n", seq);

  mutt_socket_write (idata->conn, buf);

  if (mutt_socket_read_line_d (buf, sizeof buf, idata->conn) < 0)
    return -1;

  if (buf[0] != '+')
    return -1;

  buildSmbNtlmAuthRequest(&request,user,NULL);

#ifdef DEBUG
  if (debuglevel > 0)
    dumpSmbNtlmAuthRequest(debugfile,&request);
#endif  

  memset(buf,0,sizeof buf);
  mutt_to_base64((unsigned char*)buf, (unsigned char*)&request, SmbLength(&request));
  strcat(buf,"\r\n");

  mutt_socket_write (idata->conn, buf);

  if (mutt_socket_read_line_d (buf, sizeof buf, idata->conn) < 0)
    return -1;

  if ((buf[0] != '+') || (buf[1] != ' '))
    return -1;

  len = mutt_from_base64((char*)&challenge, buf+2);

#ifdef DEBUG
  if (debuglevel > 0)
  dumpSmbNtlmAuthChallenge(debugfile,&challenge);
#endif
 
  buildSmbNtlmAuthResponse(&challenge, &response, user, pass);
 
#ifdef DEBUG
  if (debuglevel > 0)
    dumpSmbNtlmAuthResponse(debugfile,&response);
#endif
   
  memset(buf,0,sizeof buf);
  mutt_to_base64((unsigned char*)buf, (unsigned char*)&response, SmbLength(&response));
  strcat(buf,"\r\n");
 
  mutt_socket_write (idata->conn, buf);
   
  if (mutt_socket_read_line_d (buf, sizeof buf, idata->conn) < 0)
    return -1;
 
  snprintf (tmpstr, sizeof tmpstr, "%s OK", seq);
   
  if (strncmp(buf,tmpstr,strlen(tmpstr)))
  {
    mutt_error _("Login failed.");
    FREE (&ImapUser);
    FREE (&ImapPass);
    return -2;
  }

  return 0;
}
