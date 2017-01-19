#include <stdio.h>
#include <string.h>
       #include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_BUFFER 1024

int main(int argc, char* argv[])
{
int sfd, cfd, len, i, ret;
struct sockaddr_in saddr, caddr;
struct sctp_initmsg initmsg;
char buff[INET_ADDRSTRLEN];
char buffer[MAX_BUFFER+1] = "Message ##\n";

           struct addrinfo hints;
           struct addrinfo *result, *rp;
           int s, j;
           ssize_t nread;

           if (argc < 3) {
               fprintf(stderr, "Usage: %s host port \n", argv[0]);
               exit(EXIT_FAILURE);
           }

           /* Obtain address(es) matching host/port */

           memset(&hints, 0, sizeof(struct addrinfo));
           hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
           hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
           hints.ai_flags = 0;
           hints.ai_protocol = IPPROTO_SCTP;          /* Any protocol */

           s = getaddrinfo(argv[1], argv[2], &hints, &result);
           if (s != 0) {
               fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
               exit(EXIT_FAILURE);
           }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or connect(2)) fails, we (close the socket
              and) try the next address. */

           for (rp = result; rp != NULL; rp = rp->ai_next) {
               sfd = socket(rp->ai_family, rp->ai_socktype,
                            rp->ai_protocol);
               if (sfd == -1)
                   continue;

               if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                   break;                  /* Success */


           }

           s = getaddrinfo(argv[3], argv[2], &hints, &result);
           if (s != 0) {
               fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
               exit(EXIT_FAILURE);
           }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or connect(2)) fails, we (close the socket
              and) try the next address. */

           for (rp = result; rp != NULL; rp = rp->ai_next) {

  ret = sctp_bindx( sfd, rp->ai_addr, 1, SCTP_BINDX_ADD_ADDR);
	}

/* Maximum of 3 streams will be available per socket */
memset( &initmsg, 0, sizeof(initmsg) );
initmsg.sinit_num_ostreams = 3;
initmsg.sinit_max_instreams = 3;
initmsg.sinit_max_attempts = 2;
setsockopt( sfd, IPPROTO_SCTP, SCTP_INITMSG,
&initmsg, sizeof(initmsg) );

listen( sfd, 5 );

for(;;) {
printf("Server Running\n");

len=sizeof(caddr);
cfd=accept(sfd, (struct sockaddr *)&caddr, &len);

printf("Connected to %s\n",
inet_ntop(AF_INET, &caddr.sin_addr, buff,
sizeof(buff)));


for(i=0; i< 3; i++) {
/* Changing 9th character the character after # in the message buffer */
buffer[9] = '1'+i;

sctp_sendmsg( cfd, (void *)buffer, (size_t)strlen(buffer),
NULL, 0, 0, 0, i /* stream */, 0, 0 );
printf("Sent: %s\n", buffer);
}

close( cfd );
}
return 0;
}
