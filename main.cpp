//
// Created by Erica Braunschweig, braune, on 4/25/16.
//
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define USERAGENT "HTMLGET 1.1"
#define BUFFERSIZE 1024
#define USERAGENT "HTMLGET 1.1"

int tmpres;
//=================================================================================================================
//Function to do http query

char *build_get_query(char *host, char *page)
{
    char *query;
    char *getpage = page;

    std::string input = "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";
    char *tpl = new char[input.length() + 1];
    strcpy(tpl, input.c_str());

    if(getpage[0] == '/'){
        getpage = getpage + 1;
        fprintf(stderr,"Removing leading \"/\", converting %s to %s\n", page, getpage);
    }

    query = (char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)-5);
    sprintf(query, tpl, getpage, host, USERAGENT);
    return query;
}

//=================================================================================================================

const char *openssl_strerror( ) {
	return ERR_error_string(ERR_get_error(), NULL);
}

//=================================================================================================================

SSL_CTX *create_ssl_context( ) {
	SSL_CTX *ret;

	/* create a new SSL context */
	ret = SSL_CTX_new(SSLv23_client_method( ));

	if (ret == NULL) {
		fprintf(stderr, "SSL_CTX_new failed!\n");
		return NULL;
	}

	SSL_CTX_set_options(
		ret,
		SSL_OP_NO_SSLv2 |
		SSL_OP_NO_SSLv3 |
		SSL_OP_NO_COMPRESSION
	);

	SSL_CTX_set_verify(
		ret,
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		NULL
	);
	SSL_CTX_set_verify_depth(ret, 4);


	if (SSL_CTX_load_verify_locations(ret, NULL, "/etc/ssl/certs") == 0) {
		fprintf(stderr, "Failed to load root certificates\n");
		SSL_CTX_free(ret);
		return NULL;
	}

	return ret;
}

//=================================================================================================================

BIO *open_ssl_connection(SSL_CTX *ctx, const char *server) {
	BIO *ret;

	/* use our settings to create a BIO */
	ret = BIO_new_ssl_connect(ctx);
	if (ret == NULL) {
		fprintf(
			stderr,
			"BIO_new_ssl_connect failed: %s\n",
			openssl_strerror( )
		);
		return NULL;
	}

	/* according to documentation, this cannot fail */
	BIO_set_conn_hostname(ret, server);

	/* try to connect */
	if (BIO_do_connect(ret) != 1) {
		fprintf(stderr,
			"BIO_do_connect failed: %s\n",
			openssl_strerror( )
		);

		BIO_free_all(ret);
		return NULL;
	}

	/* try to do TLS handshake */
	if (BIO_do_handshake(ret) != 1) {
		fprintf(
			stderr,
			"BIO_do_handshake failed: %s\n",
			openssl_strerror( )
		);

		BIO_free_all(ret);
		return NULL;
	}

	return ret;
}

//=================================================================================================================

int check_certificate(BIO *conn, const char *hostname) {
	SSL *ssl;
	X509 *cert;
	X509_NAME *subject_name;
	X509_NAME_ENTRY *cn;
	ASN1_STRING *asn1;
	unsigned char *cn_str;
	int pos;
	bool hostname_match;

	/* get this particular connection's TLS/SSL data */
	BIO_get_ssl(conn, &ssl);
	if (ssl == NULL) {
		fprintf(
			stderr, "BIO_get_ssl failed: %s\n",
			openssl_strerror( )
		);

		return -1;
	}

	/* get the connection's certificate */
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		/* no certificate was given - failure */
		return -1;
	}

	/* check that the certificate was verified */
	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		/* certificate was not successfully verified */
		return -1;
	}

	/* get the name of the certificate subject */
	subject_name = X509_get_subject_name(cert);

	/* and print it out */
	X509_NAME_print_ex_fp(stderr, subject_name, 0, 0);

	/* loop through "common names" (hostnames) in cert */
	pos = -1;
	hostname_match = false;
	for (;;) {
		/* move to next CN entry */
		pos = X509_NAME_get_index_by_NID(
			subject_name, NID_commonName, pos
		);

		if (pos == -1) {
			break;
		}

		cn = X509_NAME_get_entry(subject_name, pos);
		asn1 = X509_NAME_ENTRY_get_data(cn);
		if (ASN1_STRING_to_UTF8(&cn_str, asn1) < 0) {
			fprintf(
				stderr, "ASN1_STRING_to_UTF8 failed: %s",
				openssl_strerror( )
			);
			return -1;
		}

		/* finally we have a hostname string! */
		if (strcmp((char *) cn_str, hostname) == 0) {
			hostname_match = true;
		}
	}

	if (hostname_match) {
		return 0;
	} else {
		fprintf(stderr, "hostnames do not match!\n");
		return -1;
	}
}

//=================================================================================================================

int main(int argc, char *argv[]) {
    int sockfd, ret;
    struct addrinfo ai_hints;
    struct addrinfo *ai_results, *j;

    //=============================================================================================================
    /* Get url and parse it*/
    std::string URL = argv[1];

    std::string url_prefix;
    std::string host;
    std::string port;
    std::string path;

    //Get URL Prefix
    unsigned int i = 0;
    for (i = 0; i < URL.length(); ++i) {

        if ((URL[i] == '/') && (URL[i + 1] == '/')) {
            i = i + 2;
            break;
        }

        if(i == URL.length() - 1) {
            i = 0;
            break;
        }
        if (URL[i] != ':') {
           url_prefix += URL[i];
        }
    }

    std::cout << "\n\n\n" << URL << "\n";
    while(i < URL.length()) {

        //get path
        if (URL[i] == '/') {

            while(i < URL.length()) {
                path += URL[i];
                ++i;
            }
        }

        //get port
        else if (URL[i] == ':') {
            ++i;
            while(i < URL.length() && URL[i] != '/') {
                port += URL[i];
                ++i;
            }
            --i;
        }

        //host
        else {
            host += URL[i];
        }
        ++i;
    }

    if (port.length() == 0 && url_prefix == "http") {
        port = "80";
    }

    else if (port.length() == 0 && url_prefix == "https") {
        port = "443";
    }

    std::cout << "URL PREFIX: \t" << url_prefix << "\n";
    std::cout << "HOST: \t\t" << host << "\n";
    std::cout << "PORT: \t\t" << port << "\n";
    std::cout << "PATH: \t\t" << path << "\n\n\n";

    char *host_c = new char[host.length() + 1];
    strcpy(host_c, host.c_str());

    char *path_c = new char[path.length() + 1];
    strcpy(path_c, path.c_str());
    //=============================================================================================================
    //IF THIS IS AN HTTPS REQUEST...

    if (url_prefix == "https") {
      SSL_CTX *ctx;
      BIO *conn;
      int size;

      std::string hostname = host;
      std::string destination = hostname + ":" + port;

      char buf[BUFFERSIZE];
      char * req = build_get_query(host_c, path_c);

      SSL_library_init( );
      SSL_load_error_strings( );

      /* Create the OpenSSL context */
      ctx = create_ssl_context( );
      if (ctx == NULL) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
      }

      /* Try to open an SSL connection */
      conn = open_ssl_connection(ctx, destination.c_str( ));
      if (conn == NULL) {
        fprintf(stderr, "Failed to create SSL connection\n");
        SSL_CTX_free(ctx);
        return 1;
      }

      if (check_certificate(conn, hostname.c_str( )) != 0) {
        fprintf(stderr, "Certificate tests failed\n");
        BIO_free_all(conn);
        SSL_CTX_free(ctx);
        return 1;
      }

      /* send request */
      BIO_puts(conn, req);

      /* receive response */
      do {
        size = BIO_read(conn, buf, BUFFERSIZE);
        if (size > 0) {
          fwrite(buf, 1, size, stdout);
        }
      } while (size > 0 || BIO_should_retry(conn));

      BIO_free_all(conn);
      return 0;
    }

    //=============================================================================================================
    //IF THIS IS AN HTTP request

    if (url_prefix == "http") {
      memset(&ai_hints, 0, sizeof(ai_hints));
      ai_hints.ai_family = AF_UNSPEC;
      ai_hints.ai_socktype = SOCK_STREAM;
      ai_hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;

      ret = getaddrinfo(host.c_str(), port.c_str(), &ai_hints, &ai_results);

      if (ret != 0) {
          fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(ret));
          return 1;
      }

      for (j = ai_results; j != NULL; j = j->ai_next) {
          /* create TCP socket */
          sockfd = socket(j->ai_family, j->ai_socktype, 0);
          if (sockfd == -1) {
              continue;
          }

          if(connect(sockfd, j->ai_addr, j->ai_addrlen) != -1) {
              break;
          }

          close(sockfd);
      }

      char * get = build_get_query(host_c, path_c);

      //Send the query to the server
      unsigned int sent = 0;
      while(sent < strlen(get))
      {
          tmpres = send(sockfd, get+sent, strlen(get)-sent, 0);
          if(tmpres == -1){
              perror("Can't send query");
              exit(1);
          }
          sent += tmpres;
      }

      //now it is time to receive the page
      char buf[BUFFERSIZE];
      memset(buf, 0, sizeof(buf));
      int htmlstart = 0;
      char * htmlcontent;

      while((tmpres = recv(sockfd, buf, BUFFERSIZE, 0)) > 0){

          if(htmlstart == 0) {
              htmlcontent = strstr(buf, "\r\n\r\n");
              if(htmlcontent != NULL){
                  htmlstart = 1;
                  htmlcontent += 4;
              }
          }
          else{
              buf[BUFFERSIZE] = '\0';
              htmlcontent = buf;
          }
          if(htmlstart){
              write(0, htmlcontent, BUFFERSIZE);
          }
          memset(buf, 0, tmpres);
      }

      if(tmpres < 0) {
          perror("Error receiving data");
      }
    }
    exit(0);
}
//=================================================================================================================
