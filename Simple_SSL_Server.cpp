// Simple_SSL_Server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Simple_SSL_Server.h"

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

int OpenListener(int port)
{
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&addr,NULL, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		perror("can't bind port");
		abort();
	}
	if (listen(sd, 10) != 0)
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* InitServerCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *)SSLv3_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	int val = 0;
	//val = SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM);
	if ((val = SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM)) <= 0)
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

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if (cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
	char buf[1024];
	char reply[1024];
	SOCKET sd;
	int bytes;
	const char* HTMLecho = "<html><body><pre>%s</pre></body></html>\n\n";

	SSL_CTX_set_verify(SSL_get_SSL_CTX(ssl), SSL_VERIFY_PEER, NULL);
	if (SSL_accept(ssl) == FAIL)     /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);        /* get any certificates */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
		if (bytes > 0)
		{
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
		//	sprintf(reply, HTMLecho, buf);   /* construct reply */
			SSL_write(ssl, reply, strlen(reply)); /* send reply */
		}
		else
			ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);       /* get socket connection */
	SSL_free(ssl);         /* release SSL state */
	closesocket(sd);          /* close connection */
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
			int server;
			char *portnum;
			
			char KeyFile[] = "mycert.pem";
			char CertFile[] = "mycert.pem";


			FILE * pFile;
			pFile = fopen("C:\\Users\\accou\\Documents\\Visual Studio 2013\\Projects\\Simple_SSL_Server\\x64\\Debug\\mycert.pem", "r");
			if (pFile != NULL)
			{
				int c; // note: int, not char, required to handle EOF
				while ((c = fgetc(pFile)) != EOF) { // standard C I/O file reading loop
					putchar(c);
				}

				if (std::ferror(pFile))
					puts("I/O error when reading");
				else if (std::feof(pFile))
					puts("End of file reached successfully");

				fclose(pFile);
			}


			SSL_library_init();

			portnum = PORT;
			ctx = InitServerCTX();        /* initialize SSL */
			LoadCertificates(ctx, CertFile, KeyFile); /* load certs */
			server = OpenListener(atoi(portnum));    /* create server socket */
			while (1)
			{
				struct sockaddr_in addr;
				socklen_t len = sizeof(addr);
				SSL *ssl;

				int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
				printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
				ssl = SSL_new(ctx);              /* get new SSL state with context */
				SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
				Servlet(ssl);         /* service connection */
			}
			closesocket(server);          /* close server socket */
			SSL_CTX_free(ctx);         /* release context */
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
