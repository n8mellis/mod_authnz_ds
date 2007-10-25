/*
 * mod_authnz_ds
 *
 * User authentication and authorization via Apple's Directory Services for Apache 2.x
 *
 * Written by: Nathan Mellis (nmellis@maf.org)
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

// These methods aren't exported in the headers
int checkpw(const char* username, const char* password);
int mbr_reset_cache(void);
int mbr_user_name_to_uuid(const char* name, uuid_t uu);
int mbr_group_name_to_uuid(const char* name, uuid_t uu);

#define MECH_NEGOTIATE "Negotiate"


#pragma mark -
#pragma mark Module Config definitions
// -------------------------------------------------------------------------------------------------
module AP_MODULE_DECLARE_DATA authnz_ds_module;
// -------------------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------------------
// authn_ds_config_t definition
// -------------------------------------------------------------------------------------------------
typedef struct {
    apr_pool_t *pool;               // Pool that this config is allocated from
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;       // Lock for this config
#endif
    int auth_authoritative;         // Is this module authoritative (i.e. pass on after failure)
    int enable_kerberos;            // Enables Kerberos authentication
    int enable_basic;               // Enables Basic (password-based) authentication
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

// -------------------------------------------------------------------------------------------------
// authn_ds_cache_entry_t definition
// -------------------------------------------------------------------------------------------------
typedef struct {
    const char *user;
    const char *password;
    apr_time_t time;
} authn_ds_cache_entry_t;



#pragma mark -
#pragma mark Authentication Phase
// -------------------------------------------------------------------------------------------------
// Authentication Phase
// -------------------------------------------------------------------------------------------------
// Inspired by mod_auth_kerb
static void set_auth_headers(request_rec *r, authn_ds_config_t *conf, char *negotiate_response)
{
    const char *auth_name = NULL;
    char *negotiate_params;
    const char *header_name = 
        (r->proxyreq == PROXYREQ_PROXY) ? "Proxy-Authenticate" : "WWW-Authenticate";
    
    // Get the auth name
    auth_name = ap_auth_name(r);
    
    // Add the headers for Negotiate method if enabled
    if (conf->enable_kerberos && negotiate_response != NULL) {
        negotiate_params = (*negotiate_response == '\0') ? MECH_NEGOTIATE :
            apr_pstrcat(r->pool, MECH_NEGOTIATE " ", negotiate_response, NULL);
        apr_table_add(r->err_headers_out, header_name, negotiate_params);
    }
    
    // Add the headers for Basic if enabled
    if (conf->enable_basic) {
        apr_table_add(r->err_headers_out, header_name, 
                      apr_pstrcat(r->pool, "Basic realm=\"", auth_name, "\"", NULL));
    }
}

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
static int authn_ds_kerberos(request_rec *r, authn_ds_config_t *conf, const char *auth_line, 
                             char **negotiate_response)
{
    return OK;
}

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
    
    cache_key = apr_pstrdup(r->pool, (const char *)decoded_line);
    
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
    apr_time_t *now = apr_palloc(r->pool, sizeof(apr_time_t));
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
        apr_hash_set(state->cache, cache_key, APR_HASH_KEY_STRING, now);
        response = OK;
    }
    else {
        response = HTTP_UNAUTHORIZED;
    }
    
end:
#if APR_HAS_THREADS
    apr_thread_mutex_unlock(state->lock);
#endif
    return response;
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
        set_auth_headers(r, conf, "\0");
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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Do Kerberos Authentication");
        response = authn_ds_kerberos(r, conf, auth_line, &negotiate_response);
    }
    else if (strcasecmp(auth_type, "Basic") == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Do Password Authentication");
        response = authn_ds_password(r, conf, auth_line);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Got neither Negotiate nor Basic, declining");
        response = DECLINED;
    }
    
    // If we are still unauthorized, send new headers and let them try again
    if (response == HTTP_UNAUTHORIZED) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Received UNAUTHORIZED, send headers");
        set_auth_headers(r, conf, "\0");
        return HTTP_UNAUTHORIZED;
    }

    last_response = response;
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
    
    return conf;
}

// -------------------------------------------------------------------------------------------------
static void *create_authnz_ds_server_state(apr_pool_t *p, server_rec *s)
{
    authn_ds_state_t *state = (authn_ds_state_t *)apr_pcalloc(p, sizeof(authn_ds_state_t));
    state->pool = p;
#if APR_HAS_THREADS
    apr_thread_mutex_create(&state->lock, APR_THREAD_MUTEX_DEFAULT, p);
#endif
    state->cache = apr_hash_make(p);
    
    return state;
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
    ap_hook_post_config(authnz_ds_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(authn_ds_authenticate, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(authz_ds_authorize, NULL, NULL, APR_HOOK_MIDDLE);
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