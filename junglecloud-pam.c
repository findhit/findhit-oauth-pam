/* ******************************************************************************

	PAM OAuth2

	Adapted from:
		* Google OAuth PAM module (https://code.google.com/p/oauth-pam)
		* Ben Servoz PAM ( http://ben.akrin.com/?p=1068 )

****************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t

WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		/* out of memory! */ 
		printf("not enough memory (realloc returned NULL)\n");
		exit(EXIT_FAILURE);
	}
 
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
 
	return realsize;
}
 

int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ); 
	if( retval==PAM_SUCCESS ) {
			retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr );
	}

	return retval;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;
	int i;

	
	/* these guys will be used by converse() */
	char *pass;
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;
	

	/* retrieving parameters */
	int got_base_email_domain  = 0;
	char *base_email_domain;
	for( i=0; i<argc; i++ ) {
			if( strncmp(argv[i], "base_email_domain=", 9)==0 ) {
					strncpy( base_email_domain, argv[i]+9, 256 );
					got_base_email_domain = 1;

			}
	}
	if( got_base_email_domain==0) {
		base_email_domain = "junglecloud.com";
	}


	/* getting the username that was used in the previous authentication */
	const char *username;
			if( (retval = pam_get_user(pamh,&username,"login: "))!=PAM_SUCCESS ) {
			return retval;
	}

	/* setting up conversation call prompting for one-time code */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = "pass: ";
	resp = NULL;
	if( (retval = converse(pamh, 1 , pmsg, &resp))!=PAM_SUCCESS ) {
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval;
	}

	/* retrieving user input */
	if( resp ) {
		if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
			free( resp );
			return PAM_AUTH_ERR;
		}

		pass = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL;                        
	} else {
			return PAM_CONV_ERR;
	}
	


	/* building URL */
	char url[ strlen("https://www.junglecloud.com/auth/o2") ];

	char data[ strlen("https://www.google.com/auth/o2") + strlen("?login=") + strlen( username ) + strlen("@") + strlen( base_email_domain ) + strlen( "&pass=" ) + strlen(pass) ];

	strcpy( data, "https://www.google.com/accounts/ClientLogin" );


	strcat( data, "?login=" );
	strcat( data, username );
	strcat( data, "@" );
	strcat( data, base_email_domain );
	strcat( data, "&pass=" );
	strcat( data, pass );		

	/* HTTP request to service that will dispatch the code */
	CURL *curl;
	CURLcode res;
	FILE *stream = NULL; 
	char *enc_data = NULL;

	struct MemoryStruct chunk;

	chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
	chunk.size = 0;    /* no data at this point */ 

	curl = curl_easy_init();
	
	if( curl ) {

		curl_easy_setopt( curl, CURLOPT_URL, data);
		curl_easy_setopt( curl, CURLOPT_HEADER, 1);
		curl_easy_setopt( curl, CURLOPT_VERBOSE, 0);
		curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1);
		curl_easy_setopt( curl, CURLOPT_USERAGENT, "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8");
		curl_easy_setopt( curl, CURLOPT_COOKIEJAR, "cookie.txt");
		curl_easy_setopt( curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
		curl_easy_setopt( curl, CURLOPT_SSLVERSION, 3);
		curl_easy_setopt( curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt( curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt( curl, CURLOPT_POST, 0);
		//curl_easy_setopt( curl, CURLOPT_POSTFIELDS, data);
		//curl_easy_setopt( curl, CURLOPT_POSTFIELDSIZE, strlen(data)); 
		curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt( curl, CURLOPT_WRITEDATA, (void *)&chunk);

		res = curl_easy_perform( curl );
	}

	
	if(chunk.size > 900){       
		return PAM_SUCCESS;
	} else {
		return PAM_AUTH_ERR;
	}

	curl_easy_cleanup( curl );
}
