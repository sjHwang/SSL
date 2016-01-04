// Simple_SSL_Client.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Simple_SSL_Client.h"

#define PORT "12345"
#define LOCALHOST "127.0.0.1"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#pragma comment(lib, "libeay32MTd.lib")
#pragma comment(lib, "ssleay32MTd.lib")

// The one and only application object

CWinApp theApp;

using namespace std;

#define FAIL    -1

//Added the LoadCertificates how in the server-side makes.    
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

SOCKET OpenConnection(const char *hostname, int port)
{
	SOCKET sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if ((host = gethostbyname(hostname)) == NULL)
	{
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&addr,NULL, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		closesocket(sd);
		perror(hostname);
		abort();
	}
	return sd;
}

SSL_CTX* InitCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = (SSL_METHOD *)SSLv3_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	if (cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		printf("No certificates.\n");
}


int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(NULL);

	if (hModule != NULL)
	{
		// initialize MFC and print and error on failure
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			// TODO: change error code to suit your needs
			_tprintf(_T("Fatal Error: MFC initialization failed\n"));
			nRetCode = 1;
		}
		else
		{
			// TODO: code your application's behavior here.
			SSL_CTX *ctx;
			SOCKET server;
			SSL *ssl;
			char buf[1024];
			int bytes;
			char *hostname, *portnum;
			char CertFile[] = "/home/myCA/cacert.pem";
			char KeyFile[] = "/home/myCA/private/cakey.pem";

			SSL_library_init();
			hostname = LOCALHOST;
			portnum = PORT;

			ctx = InitCTX();
			LoadCertificates(ctx, CertFile, KeyFile);
			server = OpenConnection(hostname, atoi(portnum));
			ssl = SSL_new(ctx);      /* create new SSL connection state */
			SSL_set_fd(ssl, server);    /* attach the socket descriptor */
			if (SSL_connect(ssl) == FAIL)   /* perform the connection */
				ERR_print_errors_fp(stderr);
			else
			{
				char *msg = "Hello???";

				printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
				ShowCerts(ssl);        /* get any certs */
				SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
				bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
				buf[bytes] = 0;
				printf("Received: \"%s\"\n", buf);
				SSL_free(ssl);        /* release connection state */
			}
			closesocket(server);         /* close socket */
			SSL_CTX_free(ctx);        /* release context */
		}
	}
	else
	{
		// TODO: change error code to suit your needs
		_tprintf(_T("Fatal Error: GetModuleHandle failed\n"));
		nRetCode = 1;
	}

	return nRetCode;
}