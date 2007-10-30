/**
 * File: mod_authnz_ds.c
 * 
 * User authentication and authorization module using Apple's Directory Services for Apache 2.x.
 *
 * I had need of an authentication module that would allow one to utilize their Kerberos ticket for 
 * single-signon if they had it available, but be able to fall back to a Basic-type username and 
 * password prompt if they did not have a Kerberos ticket or their browser did not support the 
 * Negotiate protocol.  Both these methods needed to authenticate against a directory service 
 * such as Open Directory or Active Directory.  
 * 
 * I also needed a module that would do authorization against this same directory.  The 
 * mod_authnz_ldap module that is included in the Apache distribution served for a while but did 
 * not allow us to do single-signon via Kerberos and there was no way to gracefully integrate the 
 * two.  In addition, the version of Apache (specifically APR) that ships on Mac OS X was not built 
 * with LDAP support and thus was not useable for our purpose.
 *
 * This module is designed to fulfill all these needs.  It provides a two-pronged approach to 
 * authentication and a simple but powerful authorization scheme.  Both the Negotiate and Basic 
 * authentication methods are supported.  When Basic is used, it will authenticate the user against 
 * the built-in Directory Services; enabling anyone who is listed in Directory Services to be 
 * authenticated.  So, to add support for Active Directory integration, simply bind Open Directory 
 * to Active Directory using the Directory Utility and you have instant AD authentication.
 * 
 * Similarly, with authorization, it will accept any user or group that is represented in Directory 
 * Services.  Also, unlike the LDAP authorization module, this will support nested groups as well.
 *
 * Installation
 * ============
 * 
 * The module must be compiled using apxs, which comes with your Apache distribution.  The supplied 
 * Makefile will do this for you.  Simply run:
 * 
 *   %> ./configure
 *   %> make
 *   %> sudo make install
 *
 * It will compile the module and install it in Apache's modules directory and add the LoadModule 
 * statement to your httpd.conf.  It will be enabled by default so if you don't want to use it 
 * right away, simply comment it out.
 * 
 * 
 * Usage
 * =====
 * 
 * Authentication
 * --------------
 * To enable authentication for a directory, simply add the following lines to the Location section 
 * of your httpd.conf file:
 * 
 * Example:
 * (start example)
 * <Location /secured/>
 *   AuthName "My Secured Site"
 *   AuthType DirectoryServices
 * </Location>
 * (end example)
 *
 * There should also be an Order statement (e.g. Order allow,deny) and an Allow or Deny statement 
 * (e.g. Allow from all)
 *
 * Authorization
 * -------------
 * To enable authorization, simply provide a Require statement like the following:
 * 
 *   Require group admin
 *
 * Any group that is accessible by Directory Services can be named here and more than one group 
 * can be specified (e.g. Require group admin www).
 *
 * Additionally, one or more of the following directives may be specified to customize the behavior 
 * of the module.  See below for more information.
 *
 * So a complete Location with both Kerberos and Basic would look like the following:
 *
 * Example:
 * (start example)
 * <Location /secured/>
 *   AuthName "My Secured Site"
 *   AuthType DirectoryServices
 *   AuthnDSEnableKerberos On
 *   AuthnDSEnableBasic On
 *   Order allow,deny
 *   Allow from all
 *   Require group admin
 * </Location>
 * (end example)
 * 
 * 
 * Directives
 * ==========
 * 
 * AuthnDSAuthoritative
 *   'On' or 'Off'; specifies if lower modules should be given the opportunity to response to 
 *   requests if this returns DECLINED.
 *
 * AuthnDSEnableKerberos
 *   'On' or 'Off'; specifies if Kerberos authentication via the Negotiate protocol is enabled.  
 *   Default is 'Off'.
 *
 * AuthnDSEnableBasic
 *   'On' or 'Off'; specifies if username/password authentication via the Basic protocol is 
 *   enabled.  Default is 'On'.
 *
 * AuthnDSKeytab
 *   Specifies the location of the Kerberos keytab file.
 * 
 * AuthnDSRealms (also AuthnDSRealm)
 *   Specifies the Kerberos realm(s) that tickets should be accepted for.
 * 
 * AuthnDSServiceName
 *   Specifies the service name; typically "HTTP".
 * 
 * 
 * Credits:
 * 
 *   Written by Nathan Mellis (nmellis@maf.org).
 * 
 * Copyright / License:
 * 
 *   Copyright 2007 Mission Aviation Fellowship
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * Version:
 *   $Id$ 
 */

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_base64.h"
#include "apr_pools.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <Security/Security.h>
#include <membership.h>

#include <Kerberos/Kerberos.h>

// These methods aren't exported in the headers
// I found these in the Apple Calendar Server AppleAuth file so they must be okay to use.
int checkpw(const char* username, const char* password);
int mbr_reset_cache(void);
int mbr_user_name_to_uuid(const char* name, uuid_t uu);
int mbr_group_name_to_uuid(const char* name, uuid_t uu);

// Define some constants
#define MECH_NEGOTIATE "Negotiate"
#define SERVICE_NAME "HTTP"


#pragma mark -
#pragma mark Module Config definitions
// -------------------------------------------------------------------------------------------------
module AP_MODULE_DECLARE_DATA authnz_ds_module;
// -------------------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------------------
// authn_ds_config_t definition
// -------------------------------------------------------------------------------------------------
typedef struct {
    apr_pool_t *pool;                   // Pool that this config is allocated from
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;           // Lock for this config
#endif
    int auth_authoritative;             // Is this module authoritative (i.e. pass on after failure)
    int enable_kerberos;                // Enables Kerberos authentication
    int enable_basic;                   // Enables Basic (password-based) authentication
    char *kerberos_keytab;              // Location of the Kerberos keytab file
    char *kerberos_realms;              // The Kerberos realms to look in
    const char *kerberos_service_name;  // The service name for Kerberos, usually HTTP
} authn_ds_config_t;

// -------------------------------------------------------------------------------------------------
// authn_ds_state_t definition
// -------------------------------------------------------------------------------------------------
typedef struct {
    apr_pool_t *pool;               // Pool that this config is allocated from
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;       // Lock for this state
#endif
    apr_hash_t *cache;              // Authentication cache
} authn_ds_state_t;



#pragma mark -
// -------------------------------------------------------------------------------------------------
// Authentication Phase
// -------------------------------------------------------------------------------------------------
/**
 * Method: set_auth_headers
 *
 * Sets the headers of the incoming request if no authorization headers were sent or the 
 * authorization failed.  If Kerberos is enabled it will give priority to the Negotiate protocol.
 * 
 * Parameters:
 *   request_rec *r           - the current request object
 *   authn_ds_config_t *conf  - the per-directory configuration for this process
 *   int use_password         - `true` if we should allow Basic authentication to be an option for 
 *                              this request
 *   char *negotiate_response - the response from <authn_ds_kerberos>.  If NULL, Negotiate is 
 *                              disabled.  If a null string (e.g. '\0'), Negotiate is added as an 
 *                              authorization header.  Otherwise it is the response from a previous 
 *                              Negotiate response step and will be sent to the client.
 */
static void set_auth_headers(request_rec *r, authn_ds_config_t *conf, int use_password, 
                             char *negotiate_response)
{
    const char *auth_name = NULL;
    char *negotiate_params;
    const char *header_name = 
    (r->proxyreq == PROXYREQ_PROXY) ? "Proxy-Authenticate" : "WWW-Authenticate";
    
    // Get the auth name
    auth_name = ap_auth_name(r);
    
    // Add the headers for Negotiate method if enabled
    if (conf->enable_kerberos && negotiate_response != NULL) {
        negotiate_params = (*negotiate_response == '\0') ? 
            MECH_NEGOTIATE : apr_pstrcat(r->pool, MECH_NEGOTIATE " ", negotiate_response, NULL);
        apr_table_add(r->err_headers_out, header_name, negotiate_params);
    }
    
    // Add the headers for Basic if enabled
    if (conf->enable_basic && use_password) {
        apr_table_add(r->err_headers_out, header_name, 
                      apr_pstrcat(r->pool, "Basic realm=\"", auth_name, "\"", NULL));
    }
}

#pragma mark Kerberos Authentication
// -------------------------------------------------------------------------------------------------
// Taken from mod_auth_kerb
static const char *get_gss_error(apr_pool_t *p, OM_uint32 majorError, OM_uint32 minorError, 
                                 char *prefix)
{
    OM_uint32 majorStatus, minorStatus;
    OM_uint32 messageContext = 0;
    gss_buffer_desc statusString;
    char *errorMessage;
    
    errorMessage = apr_pstrdup(p, prefix);
    do {
        majorStatus = gss_display_status(&minorStatus, majorError, GSS_C_GSS_CODE, GSS_C_NO_OID, 
                                         &messageContext, &statusString);
        if (GSS_ERROR(majorStatus))
            break;
        
        errorMessage = apr_pstrcat(p, errorMessage, ": ", (char *)statusString.value, NULL);
        gss_release_buffer(&minorStatus, &statusString);
        
        majorStatus = gss_display_status(&minorStatus, minorError, GSS_C_MECH_CODE, GSS_C_NULL_OID, 
                                         &messageContext, &statusString);
        if (!GSS_ERROR(majorStatus)) {
            errorMessage = 
                apr_pstrcat(p, errorMessage, " (", (char *)statusString.value, ")", NULL);
            gss_release_buffer(&minorStatus, &statusString);
        }
    } while (!GSS_ERROR(majorStatus) && messageContext != 0);
    
    return errorMessage;
}

// -------------------------------------------------------------------------------------------------
// Taken from Apple Sample Code: Network Authenticate/GSSauthenticate.c
static int AcquireGSSCredentials(request_rec *r, const char *inServiceName, 
                                 gss_cred_id_t *outServiceCredentials)
{
    gss_name_t      stServerName    = GSS_C_NO_NAME;
    gss_buffer_desc stNameBuffer;
    OM_uint32       iMajorStatus;
    OM_uint32       iMinorStatus;
    
    // Check the inServiceName to see if it has a string
    if (inServiceName == NULL || *inServiceName == '\0') {
        return -1;
    }
    
    // Fill the stNameBuffer with the incoming service name
    stNameBuffer.value  = (char *)inServiceName;
    stNameBuffer.length = strlen(inServiceName) + 1;
    
    iMajorStatus = 
        gss_import_name(&iMinorStatus, &stNameBuffer, GSS_C_NT_HOSTBASED_SERVICE, &stServerName);
    
    if (iMajorStatus != GSS_S_COMPLETE) {
        // Log here if necessary with more detail using:
		//		gss_display_status( &tempStatus, iMajorStatus, GSS_C_GSS_CODE, ... )
		//		gss_display_status( &tempStatus, iMinorStatus, GSS_C_MECH_CODE, ... )
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "Kerberos: Failure in AcquireGSSCredentials in gss_import_name");
        return -1;
    }
    
    // Get credentials with the expectation that we are accepting credentials on behalf of this 
    // service.  This will go to the keytab to look for the key for this service and prepare to 
    // allow authentication to the service by clients
    iMajorStatus = gss_acquire_cred(&iMinorStatus, stServerName, GSS_C_INDEFINITE, 
                                    GSS_C_NULL_OID_SET, GSS_C_ACCEPT, outServiceCredentials, 
                                    NULL, NULL);
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: gss_acquire_cred major status: %d", 
                  iMajorStatus);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: gss_acquire_cred minor status: %d", 
                  iMinorStatus);
    
    if (iMajorStatus == GSS_S_NO_CRED)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: NO_CRED");
    else if (iMajorStatus == GSS_S_BAD_NAME)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: BAD_NAME");
    else if (iMajorStatus == GSS_S_BAD_MECH)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: BAD_MECH");
    else if (iMajorStatus == GSS_S_CREDENTIALS_EXPIRED)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: CREDENTIALS_EXPIRED");
    else if (iMajorStatus == GSS_S_BAD_NAMETYPE)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: BAD_NAMETYPE");

        
    
    // Need to release the allocated stServerName
    OM_uint32 iTempStatus;  // Create a temporary variable so we don't overwrite iMinorStatus
    gss_release_name(&iTempStatus, &stServerName);
    
    // Check our status and determine if we succeeded or not
    if (iMajorStatus != GSS_S_COMPLETE) {
        // Log here if necessary with more detail using:
		//		gss_display_status( &tempStatus, iMajorStatus, GSS_C_GSS_CODE, ... )
		//		gss_display_status( &tempStatus, iMinorStatus, GSS_C_MECH_CODE, ... )
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "Kerberos: Failure in AcquireGSSCredentials in gss_acquire_cred");
		return -1;        
    }
    
    return 0;
}

// -------------------------------------------------------------------------------------------------
// Taken from Apple Sample Code: Network Authenticate/GSSauthenticate.c
static OM_uint32 AuthenticateGSS(request_rec *r, char *inToken, int inTokenLength, 
                                 char **outToken, int *outTokenLength, 
                                 char **inOutServiceName, char **outUserPrincipal, 
                                 gss_ctx_id_t *inOutGSSContext, gss_cred_id_t *inOutGSSCreds)
{
    OM_uint32       minorStatus         = 0;
    OM_uint32       majorStatus         = GSS_S_DEFECTIVE_TOKEN;
    gss_buffer_desc sendToken           = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc recvToken           = { inTokenLength, inToken };
    gss_name_t      gssClientPrincipal  = GSS_C_NO_NAME;
    
    if (inToken == NULL) {
        // our default majorStatus is GSS_S_DEFECTIVE_TOKEN
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "Kerberos: Failure in AuthenticateGSS; inToken is NULL");
        goto finished;
    }
    
    // If we don't have credentials and a service name is supplied, attempt to get credentials
    // for that service principal
    if (*inOutGSSCreds == NULL && inOutServiceName && *inOutServiceName && 
        (*inOutServiceName)[0] != '\0')
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Fetching GSS Credentials");
        if (AcquireGSSCredentials(r, *inOutServiceName, inOutGSSCreds) != 0) {
            majorStatus = GSS_S_DEFECTIVE_CREDENTIAL;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                    "Kerberos: Failure in AuthenticateGSS; AcquireGSSCredentials result is not 0");
            goto finished;
        }
    }
    
    // Let's accept the security context.  If this is a new context, it will set a new one 
    // based on the incoming token
    majorStatus = gss_accept_sec_context(&minorStatus, inOutGSSContext, *inOutGSSCreds, &recvToken, 
                                         GSS_C_NO_CHANNEL_BINDINGS, &gssClientPrincipal, NULL, 
                                         &sendToken, NULL, NULL, NULL);
    
    if (majorStatus == GSS_S_COMPLETE) {
        // If a service name was not specified for this, let's return the one that was used
        if (inOutServiceName != NULL && *inOutServiceName == NULL) {
            // Export the credentials that were used to make the connection
            // (i.e. http/server@REALM, server@REALM, etc.)
            gss_name_t servicePrincipal = GSS_C_NO_NAME;
            
            // Get the information from the buffer
            majorStatus = gss_inquire_context(&minorStatus, *inOutGSSContext, NULL, 
                                              &servicePrincipal, NULL, NULL, NULL, NULL, NULL);
            if (majorStatus == GSS_S_COMPLETE) {
                gss_buffer_desc nameToken = GSS_C_EMPTY_BUFFER;
                
                // Now let's get a readable version of the service principal
                majorStatus = gss_display_name(&minorStatus, servicePrincipal, &nameToken, NULL);
                if (majorStatus == GSS_S_COMPLETE) {
                    *inOutServiceName = apr_pstrdup(r->pool, nameToken.value);
                    gss_release_buffer(&minorStatus, &nameToken);
                }
            }
        }
        
        // Reset to complete regardless because we don't want to return an error
        majorStatus = GSS_S_COMPLETE;
    }
    
    // If we have a return token, be sure to return it, whether it is a continue et al.
    if (sendToken.length && sendToken.value) {
        *outTokenLength = sendToken.length;
        *outToken = apr_pcalloc(r->pool, sendToken.length);
        
        bcopy(sendToken.value, *outToken, sendToken.length);
    }
    else {
        *outTokenLength = 0;
        *outToken = NULL;
    }
    
    // Release any buffer held by sendToken
    gss_release_buffer(&minorStatus, &sendToken);
    
finished:
    // If we weren't successful, let's cleanup the context
    if (majorStatus != GSS_S_CONTINUE_NEEDED && majorStatus != GSS_S_COMPLETE) {
        gss_delete_sec_context(&minorStatus, inOutGSSContext, GSS_C_NO_BUFFER);
        *inOutGSSContext = GSS_C_NO_CONTEXT;
    }
    
    // Let's return the gssClientPrincipal in case they want to note a failure, but only if it 
    // is not already set
    if (gssClientPrincipal != NULL && *outUserPrincipal == NULL) {
        gss_buffer_desc nameToken = GSS_C_EMPTY_BUFFER;
        
        OM_uint32 iStatus = gss_display_name(&minorStatus, gssClientPrincipal, &nameToken, NULL);
        if (iStatus == GSS_S_COMPLETE) {
            *outUserPrincipal = apr_pstrdup(r->pool, nameToken.value);
            gss_release_buffer(&minorStatus, &nameToken);
        }
    }
    
    return majorStatus;
}

// -------------------------------------------------------------------------------------------------
static int authn_ds_kerberos(request_rec *r, authn_ds_config_t *conf, const char *auth_line, 
                             char **negotiate_response)
{
    int             response            = HTTP_UNAUTHORIZED;
    
    char           *pRecvToken          = NULL;
    int             iRecvTokenLength    = 0;
    char           *pSendToken          = NULL;
    int             iSendTokenLength    = 0;
    char           *pUserPrincipal      = NULL;
    char           *pServiceName        = NULL;
    gss_ctx_id_t    gssContext          = GSS_C_NO_CONTEXT;
    gss_cred_id_t   gssCreds            = GSS_C_NO_CREDENTIAL;
    OM_uint32       iResult             = GSS_S_DEFECTIVE_CREDENTIAL;
    OM_uint32       iMinorStatus;
    OM_uint32       iMinorStatus2;
    
    const char *auth_param = NULL;
    
    *negotiate_response = "\0";
    
    if (conf->kerberos_keytab) {
        char *ktname;
        
        // Don't use the APR allocator because we don't want it to be free'd by apache
        ktname = malloc(strlen("KRB5_KTNAME=") + strlen(conf->kerberos_keytab) + 1);
        if (ktname == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "Kerberos: malloc() failed; not enough memory");
            response = HTTP_INTERNAL_SERVER_ERROR;
            goto end;
        }
        
        sprintf(ktname, "KRB5KTNAME=%s", conf->kerberos_keytab);
        putenv(ktname);
    }
    
    // Get/set the service principal
    char tempBuffer[1024];
    int have_server_principal = 
        conf->kerberos_service_name && strchr(conf->kerberos_service_name, '/') != NULL;
    if (have_server_principal) {
        strncpy(tempBuffer, conf->kerberos_service_name, sizeof(tempBuffer));
    }
    else {
        snprintf(tempBuffer, sizeof(tempBuffer), "%s@%s", 
                 (conf->kerberos_service_name) ? conf->kerberos_service_name : SERVICE_NAME, 
                 ap_get_server_name(r));
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "Kerberos: Service Name %s", tempBuffer);

    pServiceName = tempBuffer;
    
    // Get the authorization parameter
    auth_param = ap_getword_white(r->pool, &auth_line);
    if (auth_param == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "Kerberos: No authorization parameter in request from client");
        response = HTTP_UNAUTHORIZED;
        goto end;
    }
    
    iRecvTokenLength = apr_base64_decode_len(auth_param) + 1;
    pRecvToken = apr_pcalloc(r->connection->pool, iRecvTokenLength);
    if (pRecvToken == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ap_pcalloc() failed (not enough memory)");
        response = HTTP_INTERNAL_SERVER_ERROR;
        goto end;
    }
    iRecvTokenLength = apr_base64_decode(pRecvToken, auth_param);
    
    iResult = AuthenticateGSS(r, pRecvToken, iRecvTokenLength, &pSendToken, &iSendTokenLength, 
                              &pServiceName, &pUserPrincipal, &gssContext, &gssCreds);
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "Kerberos: Verification returned code %d", iResult);
    
    if (iSendTokenLength) {
        char *token = NULL;
        size_t length;
        
        length = apr_base64_encode_len(iSendTokenLength) + 1;
        token  = apr_pcalloc(r->connection->pool, length + 1);
        
        if (token == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ap_pcalloc() failed; not enough memory");
            response = HTTP_INTERNAL_SERVER_ERROR;
            goto end;
        }
        
        apr_base64_encode(token, pSendToken, iSendTokenLength);
        token[length] = '\0';
        *negotiate_response = token;
        
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "Kerberos: GSS-API token of length %d bytes will be sent back", 
                      iSendTokenLength);
        
        set_auth_headers(r, conf, 0, *negotiate_response);
    }
    
    if (GSS_ERROR(iResult)) {
        if (iRecvTokenLength > 7 && memcmp(pRecvToken, "NTLMSSP", 7) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                          "Kerberos: received token seems to be NTLM");
        }
        
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Kerberos: %s", 
                      get_gss_error(r->pool, iResult, iMinorStatus, 
                                    "gss_accept_sec_context failed"));
        
        // Don't offer the Negotiate method again if this fails
        *negotiate_response = NULL;
        response = HTTP_UNAUTHORIZED;
        goto end;
    }
    
    r->ap_auth_type = MECH_NEGOTIATE;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Kerberos: Setting user to %s", pSendToken);
    r->user = apr_pstrdup(r->pool, pSendToken);

    response = OK;
    
end:
    // Clean up any context
    if (gssContext != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&iMinorStatus, &gssContext, GSS_C_NO_BUFFER);
        gssContext = GSS_C_NO_CONTEXT;
    }
    
    // Clean up any credentials
    if (gssCreds != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&iMinorStatus, &gssCreds);
        gssCreds = GSS_C_NO_CREDENTIAL;
    }
    
    return response;
}

#pragma mark Password Authentication
// -------------------------------------------------------------------------------------------------
static int authn_ds_password(request_rec *r, authn_ds_config_t *conf, const char *auth_line)
{
    authn_ds_state_t *state = 
        (authn_ds_state_t *)ap_get_module_config(r->server->module_config, &authnz_ds_module);
    
    // Skip leading spaces
    while (apr_isspace(*auth_line)) {
        auth_line++;
    }
    
    const char *user;
    const char *password;
    char *decoded_line;
    char *cache_key;
    int length;
    
    decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
    length = apr_base64_decode(decoded_line, auth_line);
    // Null-terminate the string
    decoded_line[length] = '\0';
    
    cache_key = apr_pstrdup(state->pool, (const char *)decoded_line);
    
    user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');
    password = decoded_line;
    
//    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache hash key: %s", cache_key);
    
    // Set the environment variables
    r->user = (char *)user;
    r->ap_auth_type = "Basic";
    
    // Make sure we have a valid user and password to work with
    if (user == NULL || user == '\0' || password == NULL || password == '\0') {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] auth_ds authenticate: user/password not specified", 
                      getpid());
        return HTTP_UNAUTHORIZED;
    }
    else {
//        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
//                      "[%" APR_PID_T_FMT "] auth_ds authenticate: received user %s", 
//                      getpid(), user);
    }
    
    int response;
    
#if APR_HAS_THREADS
    apr_thread_mutex_lock(state->lock);
#endif
    
    apr_time_t temp_now = apr_time_now();
    apr_time_t *now = apr_palloc(state->pool, sizeof(apr_time_t));
    memcpy(now, &temp_now, sizeof(apr_time_t));

//    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
//                  "[%"APR_PID_T_FMT"] Cache Now:        %"APR_TIME_T_FMT, getpid(), *now);
    
    // Check to see if this auth_line is in the authentication hash
    apr_time_t *cached_value = apr_hash_get(state->cache, cache_key, APR_HASH_KEY_STRING);
    
    int is_valid = 0;
    if (cached_value != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] Cache: We have a cached value", getpid());
        // We have a cached value.  Check to see if it is expired
        // Check to see if the cached value is less than five minutes old
        is_valid = (*now - *cached_value) < apr_time_from_sec(300);
        
        if (is_valid) {
            // We have a valid and current cache entry, assume authentication will pass
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                          "[%" APR_PID_T_FMT "] Using cached authentication", getpid());
            response = OK;
            goto end;
        }
        else {
            // Remove the entry from the cache
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                          "[%" APR_PID_T_FMT "] Cached authentication expired", getpid());
            apr_hash_set(state->cache, cache_key, APR_HASH_KEY_STRING, NULL);
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] Cache: We don't have a cached value", getpid());
    }
    
    // We don't have a current cached entry, so proceed with the authentication
    // Check the password
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "[%" APR_PID_T_FMT "] No cache, checking password", getpid());
    int result = checkpw(user, password);

    if (result == 0) {
        // Cache the result so we don't have to look it up next time
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] Password check okay, caching result", getpid());
        apr_hash_set(state->cache, cache_key, APR_HASH_KEY_STRING, now);
        response = OK;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] Password check failed", getpid());
        response = HTTP_UNAUTHORIZED;
    }
    
end:

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(state->lock);
#endif
    
    return response;
}

#pragma mark Authentication Phase
// -------------------------------------------------------------------------------------------------
// Inspired by mod_auth_kerb
static int authn_already_succeeded(request_rec *r)
{
    //    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
    //                  "Is initial request: %s", ap_is_initial_req(r) ? "Yes" : "No");
    //    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
    //                  "Auth type: %s", r->ap_auth_type);
    
    if (ap_is_initial_req(r) || r->ap_auth_type == NULL)
        return 0;
    if (strcmp(r->ap_auth_type, MECH_NEGOTIATE) || strcmp(r->ap_auth_type, "Basic")) {
        return 1;
    }
    return 0;
}

// -------------------------------------------------------------------------------------------------
static int authn_ds_authenticate(request_rec *r)
{
    authn_ds_config_t *conf = 
        (authn_ds_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ds_module);
    
    // Make sure we have at least one authentication method available
    if (!conf->enable_kerberos && !conf->enable_basic) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "No authentication methods have been enabled");
        return HTTP_UNAUTHORIZED;
    }
    
    char *path = r->uri;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "[%" APR_PID_T_FMT "] Requesting URL: %s", getpid(), path);

    const char *auth_type    = NULL;
    const char *auth_line    = NULL;
    const char *type         = NULL;
    char *negotiate_response = NULL;
    
    int response;
    static int last_response = HTTP_UNAUTHORIZED;
    
    // Get the AuthType directive value specified in the config file
    type = ap_auth_type(r);
    
    // Get what the user sent in the HTTP header
    auth_line = apr_table_get(r->headers_in, (r->proxyreq == PROXYREQ_PROXY) ? 
                              "Proxy-Authorization" : "Authorization");
    
//    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
//                  "authn_ds_authenticate auth_line: %s", auth_line ? auth_line : "(None)");
    
    if (!auth_line) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "No auth_line, sending headers");
        set_auth_headers(r, conf, 1, "\0");
        return HTTP_UNAUTHORIZED;
    }
    
    auth_type = ap_getword_white(r->pool, &auth_line);
    
//    if (authn_already_succeeded(r)) {
//        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Already Succeeded");
//        return last_response;
//    }
    
    // Reset the response to a default of unauthorized
    response = HTTP_UNAUTHORIZED;
    
    // Do the proper authentication method
    if (strcasecmp(auth_type, MECH_NEGOTIATE) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] Do Kerberos Authentication", getpid());
        response = authn_ds_kerberos(r, conf, auth_line, &negotiate_response);
    }
    else if (strcasecmp(auth_type, "Basic") == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] Do Password Authentication", getpid());
        response = authn_ds_password(r, conf, auth_line);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Got neither Negotiate nor Basic, declining");
        response = DECLINED;
    }
    
    // If we are still unauthorized, send new headers and let them try again
    if (response == HTTP_UNAUTHORIZED) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Received UNAUTHORIZED, send headers");
        set_auth_headers(r, conf, 1, negotiate_response);
        return HTTP_UNAUTHORIZED;
    }

    last_response = response;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "User: %s", r->user);
    return response;
}

#pragma mark -
#pragma mark Authorization Phase
// -------------------------------------------------------------------------------------------------
// Authorization Phase
// -------------------------------------------------------------------------------------------------
static int check_membership(const char *user, const char *group)
{
    //(void)mbr_reset_cache();
    
    uuid_t uid;
    uuid_t gid;
    int result;
    int isMember = 0;
    
    // Get the uuid for the user
    result = mbr_user_name_to_uuid(user, uid);
    if (result != 0) {
        return -1;
    }
    
    result = mbr_group_name_to_uuid(group, gid);
    if (result != 0) {
        return -2;
    }
    
    result = mbr_check_membership(uid, gid, &isMember);
    if (isMember != 1) {
        return -3;
    }
    
    return 0;
}

// -------------------------------------------------------------------------------------------------
// Inspired by mod_authnz_ldap
static int authz_ds_authorize(request_rec *r)
{
    authn_ds_config_t *conf =
        (authn_ds_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ds_module);
    
    const apr_array_header_t *requires_array = ap_requires(r);
    require_line *requires = requires_array ? (require_line *)requires_array->elts : NULL;
    
    // Make sure we have a requirement list
    if (!requires_array) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                      "[%" APR_PID_T_FMT "] authnz_ds authorize: no requirements array", getpid());
        return conf->auth_authoritative ? HTTP_UNAUTHORIZED : DECLINED;
    }
    
    const char *user = r->user;
//    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
//                  "[%" APR_PID_T_FMT "] authnz_ds authorize: got user %s", getpid(), user);
    
    // Loop through the requirements array until there are no elements left or one is satisfied
    int method_restricted = 0;
    register int i;
    const char *t;
    char *w;
    int result;
    
    for (i = 0; i < requires_array->nelts; i++) {
        if (!(requires[i].method_mask & (AP_METHOD_BIT << r->method_number)))
            continue;
        
        method_restricted = 1;
        t = requires[i].requirement;
        w = ap_getword_white(r->pool, &t);
        
        if (strcmp(w, "group") == 0) {
//            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Attempting group authorization");
            // Test the whole line
            result = check_membership(user, t);
            if (result == 0) {
//                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
//                              "[%" APR_PID_T_FMT "] authnz_ds authorize: "
//                              "require group: authorization successful", getpid());
                return OK;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                              "[%" APR_PID_T_FMT "] authnz_ds authorize: "
                              "require group: authorization failed; reason: %i", getpid(), result);
            }
            // Now break the line apart and try each element
            while (t[0]) {
                w = ap_getword_conf(r->pool, &t);
                result = check_membership(user, w);
                if (result == 0) {
//                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
//                                  "[%" APR_PID_T_FMT "] authnz_ds authorize: "
//                                  "require group: authorization successful", getpid());
                    return OK;
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                                  "[%" APR_PID_T_FMT "] authnz_ds authorize: "
                                  "require group: authorization failed; reason: %i", getpid(), 
                                  result);
                }
            }
        }
    }
    
    // If the method hasn't been restricted, then allow access
    if (!method_restricted) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] authnz_ds authorize: agreeing because non-restricted", 
                      getpid());
        return OK;
    }
    
    // If we get here, then the user has not been authorized
    // If we're marked as not authoritative, allow pass-through to lower modules
    if (!conf->auth_authoritative) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] authnz_ds authorize: authorization declined", getpid());
        return DECLINED;
    }
    
    // We're authoritative and the user is not authorized
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "[%" APR_PID_T_FMT "] authnz_ds authorize: authorization denied", getpid());
    return HTTP_UNAUTHORIZED;
}

#pragma mark -
#pragma mark Apache Module Configuration
// -------------------------------------------------------------------------------------------------
static void *create_authnz_ds_dir_config(apr_pool_t *p, char *d)
{
    authn_ds_config_t *conf = (authn_ds_config_t *)apr_pcalloc(p, sizeof(authn_ds_config_t));
    conf->pool = p;
#if APR_HAS_THREADS
    apr_thread_mutex_create(&conf->lock, APR_THREAD_MUTEX_DEFAULT, p);
#endif
    conf->auth_authoritative = 1;
    conf->enable_kerberos = 0;
    conf->enable_basic = 1;
    conf->kerberos_service_name = NULL;
    
    return conf;
}

// -------------------------------------------------------------------------------------------------
static void *create_authnz_ds_server_state(apr_pool_t *p, server_rec *s)
{
    authn_ds_state_t *state = (authn_ds_state_t *)apr_pcalloc(p, sizeof(authn_ds_state_t));
    return state;
}

// -------------------------------------------------------------------------------------------------
static void authnz_ds_child_init(apr_pool_t *pchild, server_rec *s)
{
    apr_status_t status;
    
    // Get the server config
    authn_ds_state_t *state = ap_get_module_config(s->module_config, &authnz_ds_module);
    
    // Derive our own pool from pchild
    status = apr_pool_create(&state->pool, pchild);
    if (status != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, status, pchild, 
                      "Failed to create subpool for authn_ds_module");
        return;
    }
    
    // Set up a thread mutex for when we need to manipulate the cache
#if APR_HAS_THREADS
    status = apr_thread_mutex_create(&state->lock, APR_THREAD_MUTEX_DEFAULT, pchild);
    if (status != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, status, pchild, 
                      "Failed to create mutex for authnz_ds_module");
        return;
    }
#endif
    
    // Create the cache itself
    state->cache = apr_hash_make(state->pool);
}

// -------------------------------------------------------------------------------------------------
static const char * save_kerberos_realms(cmd_parms *cmd, void *vconf, const char *arg)
{
    authn_ds_config_t *conf = (authn_ds_config_t *)vconf;
    conf->kerberos_realms = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

// -------------------------------------------------------------------------------------------------
static const command_rec authnz_ds_cmds[] = 
{
    AP_INIT_FLAG("AuthzDSAuthoritative", ap_set_flag_slot, 
                 (void *)APR_OFFSETOF(authn_ds_config_t, auth_authoritative), OR_AUTHCFG, 
                 "Set to 'off' to allow access control to be passed along to lower modules if "
                 "the UserID and/or group is not known to this module"), 
    
    // Add an option to enable or disable Kerberos
    AP_INIT_FLAG("AuthnDSEnableKerberos", ap_set_flag_slot, 
                 (void *)APR_OFFSETOF(authn_ds_config_t, enable_kerberos), OR_AUTHCFG, 
                 "Set to 'on' to enable Kerberos authentication"), 
    // Add an option to enable or disable Basic
    AP_INIT_FLAG("AuthnDSEnableBasic", ap_set_flag_slot, 
                 (void *)APR_OFFSETOF(authn_ds_config_t, enable_basic), OR_AUTHCFG, 
                 "Set to 'off' to disable Basic authentication"), 
    
    AP_INIT_TAKE1("AuthnDSKeytab", ap_set_file_slot, 
                  (void *)APR_OFFSETOF(authn_ds_config_t, kerberos_keytab), OR_AUTHCFG, 
                  "Specify the location of the Kerberos V5 keytab file"), 
    
    AP_INIT_TAKE1("AuthnDSRealms", save_kerberos_realms, 
                  (void *)APR_OFFSETOF(authn_ds_config_t, kerberos_realms), OR_AUTHCFG, 
                  "Specify the realms that Kerberos can authenticate against"), 
    
    AP_INIT_TAKE1("AuthnDSRealm", save_kerberos_realms, 
                  (void *)APR_OFFSETOF(authn_ds_config_t, kerberos_realms), OR_AUTHCFG, 
                  "Alias for AuthnDSRealms"), 
    
    AP_INIT_TAKE1("AuthnDSServiceName", ap_set_string_slot, 
                  (void *)APR_OFFSETOF(authn_ds_config_t, kerberos_service_name), OR_AUTHCFG, 
                  "The Kerberos service name"), 
    
    { NULL }
};

// -------------------------------------------------------------------------------------------------
static int authnz_ds_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    return OK;
}

// -------------------------------------------------------------------------------------------------
static void register_hooks(apr_pool_t *p)
{
    // Specify that the authorization here should take place BEFORE mod_authz_user
    static const char *const aszPost[] = { "mod_authz_user.c", NULL };
    
    ap_hook_post_config(authnz_ds_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(authnz_ds_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(authn_ds_authenticate, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(authz_ds_authorize, NULL, aszPost, APR_HOOK_MIDDLE);
}

// -------------------------------------------------------------------------------------------------
// Apache 2.x module configuration
// -------------------------------------------------------------------------------------------------
module AP_MODULE_DECLARE_DATA authnz_ds_module = 
{
    STANDARD20_MODULE_STUFF, 
    create_authnz_ds_dir_config,    // Dir config creator
    NULL,                           // Dir merger
    create_authnz_ds_server_state,  // Server config
    NULL,                           // Merge server config
    authnz_ds_cmds,                 // Command apr_table_t
    register_hooks                  // Register hooks
};