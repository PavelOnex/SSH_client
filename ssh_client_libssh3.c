#include <stdio.h>
#include <libssh/libssh.h> 
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
size_t strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}
size_t strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}
//DEF_WEAK(strlcpy);


int verify_knownhost(ssh_session session) {

  int state, hlen;
  unsigned char *hash = NULL;
  char *hexa;
  char buf[10];

  state = ssh_is_server_known(session);
  hlen = ssh_get_pubkey_hash(session, &hash);

  if (hlen < 0)
    return -1;
  switch (state)

  {
    case SSH_SERVER_KNOWN_OK:
      break; //ok 
    case SSH_SERVER_KNOWN_CHANGED:
      fprintf(stderr, "Host key for server changed: it is now:\n");
      ssh_print_hexa("Public key hash", hash, hlen);
      fprintf(stderr, "For security reasons, connection will be stopped\n");
      free(hash);
      return -1;
    case SSH_SERVER_FOUND_OTHER:
      fprintf(stderr, "The host key for this server was not found but an other"
        "type of key exists.\n");
      fprintf(stderr, "An attacker might change the default server key to"
        "confuse your client into thinking the key does not exist\n");
      free(hash);
      return -1;
    case SSH_SERVER_FILE_NOT_FOUND:
      fprintf(stderr, "Could not find known host file.\n");
      fprintf(stderr, "If you accept the host key here, the file will be"
       "automatically created.\n");
      // fallback to SSH_SERVER_NOT_KNOWN behavior 
    case SSH_SERVER_NOT_KNOWN:
      hexa = ssh_get_hexa(hash, hlen);
      fprintf(stderr,"The server is unknown. Do you trust the host key [yes/no]?\n");
      fprintf(stderr, "Public key hash: %s\n", hexa);
      free(hexa);
      if (fgets(buf, sizeof(buf), stdin) == NULL)
      {
        free(hash);
        return -1;
      }
      if (strncasecmp(buf, "yes", 3) != 0)
      {
        free(hash);
        return -1;
      }
      if (ssh_write_knownhost(session) < 0)
      {
        fprintf(stderr, "Error %s\n", strerror(errno));
        free(hash);
        return -1;
      }
      break;
    case SSH_SERVER_ERROR:
      fprintf(stderr, "Error %s", ssh_get_error(session));
      free(hash);
      return -1;
  }

  free(hash);
  return 0;
}
int write_console(int nbytes, ssh_channel channel, char *buffer)
{
nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (write(1, buffer, nbytes) != (unsigned int) nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }
    
  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
}

int show_list(ssh_channel channel, ssh_session session) {

  int rc;
  char buffer[256];
  int nbytes;

  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }

  rc = ssh_channel_request_exec(channel, " grep home /etc/passwd | cut -d: -f1\n");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }

int out=write_console(nbytes, channel, buffer);
/*
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (write(1, buffer, nbytes) != (unsigned int) nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }
    
  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  } */
//printf("\n\n");
//printf(buffer);

  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);

  return SSH_OK;
}
int change_pass_by_user(char *pass_enter, char *pass_action, ssh_channel channel, ssh_session session)
{
  int rc;
  char buffer[256];
  int nbytes;
char command[200];

  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }

strlcpy(command, " echo -e \"", sizeof(command));
strlcat(command, pass_enter, sizeof(command));
strlcat(command, "\n", sizeof(command));
strlcat(command, pass_action, sizeof(command));
strlcat(command, "\n", sizeof(command));
strlcat(command, pass_action, sizeof(command));
strlcat(command, "\n\" | passwd | tail -n +2\n", sizeof(command));
rc=ssh_channel_request_exec(channel, command);
//rc = ssh_channel_request_exec(channel, " echo -e \"Xsw23edc\nCde34rfv\nCde34rfv\n\" | passwd | tail -n +2\n");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }

 int out=write_console(nbytes, channel, buffer);

  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);

  return SSH_OK;
}

int change_pass_by_root(char *username_action, char *pass_action, char *pass_root, ssh_channel channel, ssh_session session)
{
  int rc;
  char buffer[256];
  int nbytes;
  char command[300];
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
  strlcpy(command, " sh -c \"sleep 1; echo ", sizeof(command));
  strlcat(command, pass_root, sizeof(command));
  strlcat(command, "\" | script -qc 'su -c \"sleep 1; echo -e \\\"", sizeof(command));
  strlcat(command, pass_action, sizeof(command));
  strlcat(command, "\\n", sizeof(command));
  strlcat(command, pass_action, sizeof(command));
  strlcat(command, "\\n\\\" | passwd ", sizeof(command));
  strlcat(command, username_action, sizeof(command));
  strlcat(command, "\"' | tail -n +2\n", sizeof(command));
  rc=ssh_channel_request_exec(channel, command);
//rc=ssh_channel_request_exec(channel, " sh -c \"sleep 1; echo Xsw23edc\" | script -qc 'su -c \"sleep 1; echo -e \\\"Cde34rfv\\nCde34rfv\\n\\\" | passwd chns\"' | tail -n +2\n");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  } 

int out=write_console(nbytes, channel, buffer);

//printf("\n\n");
//	printf(buffer);
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);

  return SSH_OK;
}

int check(char *username_action, char *pass_action, ssh_channel channel, ssh_session session)
{
 
  int rc;
  char buffer[256];
  int nbytes;
char command[200];
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
strlcpy(command, " sh -c \"sleep 1; echo ", sizeof(command));
strlcat(command, pass_action, sizeof(command));
strlcat(command, "\" | script -qc 'su -c \"whoami\" ", sizeof(command));
strlcat(command, username_action, sizeof(command));
strlcat(command, "' | tail -n +2\n", sizeof(command));
rc=ssh_channel_request_exec(channel, command);
//rc=ssh_channel_request_exec(channel, " sh -c \"sleep 1; echo Xsw23edc\" | script -qc 'su -c \"whoami\" chns' | tail -n +2\n");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  } 
int out=write_console(nbytes, channel, buffer);


//printf(buffer);
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);

  return SSH_OK;

}

int main(int argc, char **argv) {

     if (argc < 9) exit(-1);
    char host[100];
    strlcpy(host, argv[1], sizeof(host)-1);
    int port = atoi(argv[2]);
    int action = atoi(argv[3]);
    char username_enter[20];
    strlcpy(username_enter, argv[4], sizeof(username_enter));
    char pass_enter[30];
    strlcpy(pass_enter, argv[5], sizeof(pass_enter));
    char username_action[20];
    strlcpy(username_action, argv[6], sizeof(username_action));
    char pass_action[30];
    strlcpy(pass_action, argv[7], sizeof(pass_action));
    char pass_root[30];
    strlcpy(pass_root, argv[8], sizeof(pass_root));



// set verbosity if need
//    int verbosity = SSH_LOG_FUNCTIONS;
//    int verbosity = SSH_LOG_PROTOCOL;
    int connection;
     ssh_channel channel;
	int rc;
    ssh_session session;
    session = ssh_new();

    if (session == NULL) exit(-1);

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
//    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username_enter);

//    printf("Connecting to host %s and port %d\n", host, port);
    connection = ssh_connect(session);

    if (connection != SSH_OK) {
        printf("Error connecting to %s: %s\n", host, ssh_get_error(session));
        exit -1;
    } //else {
      //  printf("Connected.\n");
    //}    
channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;
/*
    if (verify_knownhost(session) < 0) {
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);   
    }
*/
    rc = ssh_userauth_password(session, username_enter, pass_enter);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

 if (action == 0)
{
    if (show_list(channel, session) != SSH_OK) {
        printf("Error executing request\n");
        ssh_get_error(session);
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    } //else { 
      //  printf("\nRequest completed successfully!\n");
    //}
} else if (action == 1){
rc=change_pass_by_user(pass_enter, pass_action, channel, session);
} else if (action == 2){
rc=change_pass_by_root(username_action, pass_action, pass_root, channel, session);
} else if (action == 3){
rc=check(username_action, pass_action, channel, session);
} else printf("Error!\n");
//printf(" sh -c \"sleep 0.5; echo Xsw23edc\" | script -qc 'su -c \"sleep 0.5; echo -e \\\"Cde34rfv\\nCde34rfv\\n\\\" | passwd chns\"'\n");

    ssh_disconnect(session);
   ssh_free(session);
}
     

