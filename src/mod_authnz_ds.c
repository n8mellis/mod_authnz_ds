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


// -------------------------------------------------------------------------------------------------
// authn_ds_config_t definition
// -------------------------------------------------------------------------------------------------
typedef struct {
    apr_pool_t *pool;                // Pool that this config is allocated from
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;       // Lock for this config
#endif
    int auth_authoritative;         // Is this module authoritative (i.e. pass on after failure)
} authn_ds_config_t;

// -------------------------------------------------------------------------------------------------
// authn_ds_request_t definition
// -------------------------------------------------------------------------------------------------
typedef struct {
    char *user;
} authn_ds_request_t;



// -------------------------------------------------------------------------------------------------
module AP_MODULE_DECLARE_DATA authnz_ds_module;
// -------------------------------------------------------------------------------------------------


// -------------------------------------------------------------------------------------------------
static void *create_authnz_ds_dir_config(apr_pool_t *p, char *d)
{
    authn_ds_config_t *sec = (authn_ds_config_t *)apr_pcalloc(p, sizeof(authn_ds_config_t));
    sec->pool = p;
#if APR_HAS_THREADS
    apr_thread_mutex_create(&sec->lock, APR_THREAD_MUTEX_DEFAULT, p);
#endif
    sec->auth_authoritative = 1;
    
    return sec;
}

// -------------------------------------------------------------------------------------------------
// Authentication Phase
// -------------------------------------------------------------------------------------------------
static authn_status authn_ds_check_password(request_rec *r, const char *user, const char *password)
{
    // Make sure that `user` and `password` are not empty
    if (password == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] auth_ds authenticate: no password specified", getpid());
        return AUTH_GENERAL_ERROR;
    }
    if (user == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] auth_ds authenticate: no user specified", getpid());
        return AUTH_GENERAL_ERROR;
    }
    
    // We have the required information, so proceed
    authn_ds_config_t *sec = 
        (authn_ds_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ds_module);

    authn_ds_request_t  *req = 
        (authn_ds_request_t *)apr_pcalloc(r->pool, sizeof(authn_ds_request_t));
    ap_set_module_config(r->request_config, &authnz_ds_module, req);
    
    // Check the password
    int result = checkpw(user, password);
    
    if (result == 0) {
        req->user = apr_pstrdup(r->pool, user);
        return AUTH_GRANTED;
    }
    else if (result == -1) {
        return AUTH_USER_NOT_FOUND;
    }
    else {
        return AUTH_DENIED;
    }
    
    return AUTH_DENIED;
}

// -------------------------------------------------------------------------------------------------
// Authorization Phase
// -------------------------------------------------------------------------------------------------
int check_membership(const char *user, const char *group) {
//    (void)mbr_reset_cache();
    
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
static int authz_ds_check_user_access(request_rec *r)
{
    authn_ds_request_t *req =
    (authn_ds_request_t *)ap_get_module_config(r->request_config, &authnz_ds_module);
    authn_ds_config_t *sec =
        (authn_ds_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ds_module);
    
    const apr_array_header_t *requires_array = ap_requires(r);
    require_line *requires = requires_array ? (require_line *)requires_array->elts : NULL;
    
    // Make sure we have a requirement list
    if (!requires_array) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] authnz_ds authorize: no requirements array", getpid());
        return sec->auth_authoritative ? HTTP_UNAUTHORIZED : DECLINED;
    }
    
    const char *user = r->user;
    
    // Loop through the requirements array until there are no elements left or one is satisfied
    int method_restricted = 0;
    register int i;
    const char *t;
    char *w;
    int result;
    
    for (i = 0; i < requires_array->nelts; i++) {
        // Not sure what this does
        if (!(requires[i].method_mask & (AP_METHOD_BIT << r->method_number)))
            continue;
        
        method_restricted = 1;
        t = requires[i].requirement;
        w = ap_getword_white(r->pool, &t);
        
        if (strcmp(w, "group") == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Attempting group authorization");
            // Test the whole line
            result = check_membership(user, t);
            if (result == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "[%" APR_PID_T_FMT "] authnz_ds authorize: "
                              "require group: authorization successful", getpid());
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
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "[%" APR_PID_T_FMT "] authnz_ds authorize: "
                                  "require group: authorization successful", getpid());
                    return OK;
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                                  "[%" APR_PID_T_FMT "] authnz_ds authorize: "
                                  "require group: authorization failed; reason: %i", getpid(), result);
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
    if (!sec->auth_authoritative) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "[%" APR_PID_T_FMT "] authnz_ds authorize: authorization declined", getpid());
        return DECLINED;
    }
    
    // We're authoritative and the user is not authorized
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                  "[%" APR_PID_T_FMT "] authnz_ds authorize: authorization denied", getpid());
    ap_note_basic_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

// -------------------------------------------------------------------------------------------------
static const command_rec authnz_ds_cmds[] = 
{
    AP_INIT_FLAG("AuthzDSAuthoritative", ap_set_flag_slot, 
                 (void *)APR_OFFSETOF(authn_ds_config_t, auth_authoritative), OR_AUTHCFG, 
                 "Set to 'off' to allow access control to be passed along to lower modules if "
                 "the UserID and/or group is not known to this module"), 
    { NULL }
};

// -------------------------------------------------------------------------------------------------
static int authnz_ds_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    return OK;
}

// -------------------------------------------------------------------------------------------------
// authn_ds_provider definition
// -------------------------------------------------------------------------------------------------
static const authn_provider authn_ds_provider = { &authn_ds_check_password, };

// -------------------------------------------------------------------------------------------------
static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPost[]={ "mod_authz_user.c", NULL };
    
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "ds", "0", &authn_ds_provider);
    ap_hook_post_config(authnz_ds_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(authz_ds_check_user_access, NULL, aszPost, APR_HOOK_MIDDLE);
}

// -------------------------------------------------------------------------------------------------
// Apache 2.x module configuration
// -------------------------------------------------------------------------------------------------
module AP_MODULE_DECLARE_DATA authnz_ds_module = 
{
    STANDARD20_MODULE_STUFF, 
    create_authnz_ds_dir_config,    // Dir config creator
    NULL,                           // Dir merger
    NULL,                           // Server config
    NULL,                           // Merge server config
    authnz_ds_cmds,                 // Command apr_table_t
    register_hooks                  // Register hooks
};