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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Negotiate Response: %s", negotiate_response);
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
static int get_gss_creds(request_rec *r, authn_ds_config_t *conf, gss_cred_id_t *serverCreds)
{
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    OM_uint32 majorStatus, minorStatus, minorStatus2;
    gss_name_t serverName = GSS_C_NO_NAME;
    char buffer[1024];
    int haveServerPrincipal;
    
    haveServerPrincipal = 
        conf->kerberos_service_name && strchr(conf->kerberos_service_name, '/') != NULL;
    if (haveServerPrincipal)
        strncpy(buffer, conf->kerberos_service_name, sizeof(buffer));
    else {
        snprintf(buffer, sizeof(buffer), "%s@%s", (conf->kerberos_service_name) ? 
                 conf->kerberos_service_name : SERVICE_NAME, ap_get_server_name(r));
    }
    
    token.value = buffer;
    token.length = strlen(buffer) + 1;
    
    // Using GSS_C_NO_OID here instead of GSS_KRB5_NT_PRINCIPAL_NAME per docs at 
    // http://nixdoc.net/man-pages/Tru64/gss_import_name.3.html since it says that these are 
    // equivalent and the latter would throw a warning during compilation.
    majorStatus = gss_import_name(&minorStatus, &token, (haveServerPrincipal) ? 
                                  GSS_C_NO_OID : GSS_C_NT_HOSTBASED_SERVICE, 
                                  &serverName);
    
    // Zeros out the token so we can use it again to get the display name
    memset(&token, 0, sizeof(token));
    
    if (GSS_ERROR(majorStatus)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", 
                      get_gss_error(r->pool, majorStatus, minorStatus, "gss_import_name failed"));
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    majorStatus = gss_display_name(&minorStatus, serverName, &token, NULL);
    if (GSS_ERROR(majorStatus)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", 
                      get_gss_error(r->pool, majorStatus, minorStatus, "gss_display_name failed"));
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    gss_release_buffer(&minorStatus2, &token);

    majorStatus = gss_acquire_cred(&minorStatus, serverName, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, 
                                   GSS_C_ACCEPT, serverCreds, NULL, NULL);
    gss_release_name(&minorStatus2, &serverName);
    
    if (GSS_ERROR(majorStatus)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", 
                      get_gss_error(r->pool, majorStatus, minorStatus, "gss_acquire_cred failed"));
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    return 0;
}

// -------------------------------------------------------------------------------------------------
static int authn_ds_kerberos(request_rec *r, authn_ds_config_t *conf, const char *auth_line, 
                             char **negotiate_response)
{
    int response = HTTP_UNAUTHORIZED;
    
    authn_ds_state_t *state = 
        (authn_ds_state_t *)ap_get_module_config(r->server->module_config, &authnz_ds_module);
    
    OM_uint32 majorStatus, minorStatus, minorStatus2;
    gss_buffer_desc inputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc outputToken = GSS_C_EMPTY_BUFFER;
    const char *authParam = NULL;
    
    gss_name_t clientName = GSS_C_NO_NAME;
    gss_cred_id_t delegatedCred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_cred_id_t serverCreds = GSS_C_NO_CREDENTIAL;
    
    *negotiate_response = "\0";

    if (conf->kerberos_keytab) {
        apr_status_t s;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Setting keytab environment");
        s = apr_env_set("KRB5_KTNAME", conf->kerberos_keytab, state->pool);
    }
    
    response = get_gss_creds(r, conf, &serverCreds);
    if (response) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "get_gss_creds_failed; bailing");
        goto end;
    }
    
    authParam = ap_getword_white(r->pool, &auth_line);
    if (authParam == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "No authorization parameter in request from client");
        response = HTTP_UNAUTHORIZED;
        goto end;
    }
    
    inputToken.length = apr_base64_decode_len(authParam) + 1;
    inputToken.value = apr_pcalloc(r->connection->pool, inputToken.length);
    if (inputToken.value == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ap_pcalloc failed: not enough memory");
        response = HTTP_INTERNAL_SERVER_ERROR;
        goto end;
    }
    
    inputToken.length = apr_base64_decode(inputToken.value, authParam);
//    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
//                  "Input Token: %s", inputToken.value);
    
    majorStatus = gss_accept_sec_context(&minorStatus, &context, serverCreds, &inputToken, 
                                         GSS_C_NO_CHANNEL_BINDINGS, &clientName, NULL, 
                                         &outputToken, NULL, NULL, &delegatedCred);
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Verification returned code %d", majorStatus);
    
    if (outputToken.length) {
        char *token = NULL;
        size_t length;
        
        length = apr_base64_encode_len(outputToken.length) + 1;
        token = apr_pcalloc(r->connection->pool, length + 1);
        if (token == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ap_pcalloc failed: not enough memory");
            response = HTTP_INTERNAL_SERVER_ERROR;
            gss_release_buffer(&minorStatus2, &outputToken);
            goto end;
        }
        
        apr_base64_encode(token, outputToken.value, outputToken.length);
        token[length] = '\0';
        *negotiate_response = token;
        
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "GSS-API token of length %d bytes will be sent back", outputToken.length);
        gss_release_buffer(&minorStatus2, &outputToken);
        set_auth_headers(r, conf, 0, *negotiate_response);
    }
    
    if (GSS_ERROR(majorStatus)) {
        if (inputToken.length > 7 && memcmp(inputToken.value, "NTLMSSP", 7) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                          "Warning: received token seems to be NTLM which isn't supported.");
        }
        
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", 
                      get_gss_error(r->pool, majorStatus, minorStatus, 
                                    "gss_accept_sec_context failed"));
        
        // Don't offer Negotiate again if we failed here
        *negotiate_response = NULL;
        response = HTTP_UNAUTHORIZED;
        goto end;
    }
    
    // Get the username of the person
    majorStatus = gss_display_name(&minorStatus, clientName, &outputToken, NULL);
    gss_release_name(&minorStatus, &clientName);
    
    if (GSS_ERROR(majorStatus)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", 
                      get_gss_error(r->pool, majorStatus, minorStatus, "gss_display_name failed"));
        response = HTTP_INTERNAL_SERVER_ERROR;
        goto end;
    }
    
    r->ap_auth_type = MECH_NEGOTIATE;
    
    const char *user = outputToken.value;
    const char *realm = strchr(user, '@');
    if (realm == NULL)
        r->user = apr_pstrdup(r->pool, user);
    else
        r->user = apr_pstrndup(r->pool, user, realm - user);
    
    // TODO: Store the credentials?
    
    gss_release_buffer(&minorStatus, &outputToken);
    
    response = OK;
    
end:
    if (delegatedCred != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&minorStatus, &delegatedCred);
        delegatedCred = GSS_C_NO_CREDENTIAL;
    }
    if (outputToken.length)
        gss_release_buffer(&minorStatus, &outputToken);
    if (clientName != GSS_C_NO_NAME)
        gss_release_name(&minorStatus, &clientName);
    if (context != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&minorStatus, &context, GSS_C_NO_BUFFER);
        context = GSS_C_NO_CONTEXT;
    }
    if (serverCreds != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&minorStatus, &serverCreds);
        serverCreds = GSS_C_NO_CREDENTIAL;
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
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "Is initial request: %s", ap_is_initial_req(r) ? "Yes" : "No");
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "Auth type: %s", r->ap_auth_type);
    
    if (ap_is_initial_req(r) || r->ap_auth_type == NULL)
        return 0;
    if (strcmp(r->ap_auth_type, MECH_NEGOTIATE) || 
        (strcmp(r->ap_auth_type, "Basic") && strlen(r->user) != 0)) {
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
    
    char *path = r->the_request;
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
    
    if (authn_already_succeeded(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Already Succeeded");
        return last_response;
    }
    
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