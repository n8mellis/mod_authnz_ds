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

#include <DirectoryService/DirectoryService.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


// -------------------------------------------------------------------------------------------------
// Helper functions for accessing Directory Services
// -------------------------------------------------------------------------------------------------
tDirStatus AppendStringToBuffer(tDataBufferPtr inBuffer, const char *inString, long inLength)
{
    tDirStatus dsStatus = eDSBufferTooSmall;
    
    // Ensure that neither of our parameters are NULL
    if (inString == NULL || inBuffer == NULL) {
        return eDSNullParameter;
    }
    
    // Check to see if we have enough room in the buffer for the string and the 4-byte length
    if (inBuffer->fBufferSize >= (inBuffer->fBufferLength + 4 + inLength)) {
        char *pBufferEnd = inBuffer->fBufferData + inBuffer->fBufferLength;
        
        // Prepend the data with the length of the string
        bcopy(&inLength, pBufferEnd, sizeof(long));
        pBufferEnd += sizeof(long);
        
        // Now add the string to the buffer
        bcopy(inString, pBufferEnd, inLength);
        
        // Increase the buffer accordingly
        inBuffer->fBufferLength += 4 + inLength;
        
        // Set successful error status
        dsStatus = eDSNoErr;
    }
    
    return dsStatus;
} // AppendStringToBuffer

// -------------------------------------------------------------------------------------------------
tDirStatus OpenSearchNode(tDirReference inDSRef, tDirNodeReference *outNodeRef)
{
    tDataBufferPtr  pWorkingBuffer  = NULL;
    tDataListPtr    pSearchNode     = NULL;
    tDirStatus      dsStatus;
    tContextData    dsContext       = NULL;
    unsigned long   ulReturnCount   = 0;
    
    // Verify none of the parameters are NULL, if so return eDSNullParameter
    if (outNodeRef == NULL || inDSRef == 0) {
        return eDSNullParameter;
    }
    
    // Allocate a buffer to hold return information; default=4k
    pWorkingBuffer = dsDataBufferAllocate(inDSRef, 4096);
    if (pWorkingBuffer == NULL) {
        return eMemoryAllocError;
    }
    
    // Locate the name of the search node
    dsStatus = dsFindDirNodes(inDSRef, pWorkingBuffer, NULL, eDSSearchNodeName, &ulReturnCount, 
                              &dsContext);
    if (dsStatus == eDSNoErr) {
        // Pass 1 for the node index since there should only be one value
        dsStatus = dsGetDirNodeName(inDSRef, pWorkingBuffer, 1, &pSearchNode);
    }
    
    // If we ended up with a context, we should release it
    if (dsContext != NULL) {
        dsReleaseContinueData(inDSRef, dsContext);
        dsContext = NULL;
    }
    
    // Release the current working buffer
    if (pWorkingBuffer != NULL) {
        dsDataBufferDeAllocate(inDSRef, pWorkingBuffer);
        pWorkingBuffer = NULL;
    }
    
    // Open Search Node
    if (dsStatus == eDSNoErr && pSearchNode != NULL) {
        dsStatus = dsOpenDirNode(inDSRef, pSearchNode, outNodeRef);
    }
    
    // Deallocate the tDataListPtr item used to locate the search node
    if (pSearchNode != NULL) {
        dsDataListDeallocate(inDSRef, pSearchNode);
        // Need to free pointer since dsDataListDeallocate only frees the list items
        free(pSearchNode);
        pSearchNode = NULL;
    }
    
    return dsStatus;
} // OpenSearchNode

// -------------------------------------------------------------------------------------------------
tDirStatus LocateUserNode(tDirReference inDSRef, tDirNodeReference inSearchNode, 
                          const char *inUsername, char **outRecordName, char **outNodeName)
{
    tDirStatus      dsStatus        = eDSRecordNotFound;
    tDataListPtr    pAttribsToGet   = NULL;
    tDataListPtr    pRecTypeList    = NULL;
    tDataListPtr    pRecNameList    = NULL;
    tDataBufferPtr  pSearchBuffer   = NULL;
    unsigned long   ulRecCount      = 0;    // Do not limit the number of records we are expecting
    unsigned long   ulBufferSize    = 2048; // Start with a 2k buffer
    
    // Ensure that none of the parameters are NULL
    if (inDSRef == 0 || inSearchNode == 0 || inUsername == NULL || outRecordName == NULL || 
        outNodeName == NULL)
    {
        return eDSNullParameter;
    }
    
    // We will want the actual record name and the name of thenode where the user resides
    pAttribsToGet = dsBuildListFromStrings(
        inDSRef, kDSNAttrRecordName, kDSNAttrMetaNodeLocation, NULL);
    if (pAttribsToGet == NULL) {
        dsStatus = eMemoryAllocError;
        goto cleanup;
    }
    
    // Build a list to search for user record
    pRecNameList = dsBuildListFromStrings(inDSRef, inUsername, NULL);
    if (pRecNameList == NULL) {
        dsStatus = eMemoryAllocError;
        goto cleanup;
    }
    
    // Build a list of record types to search; in this case, users
    pRecTypeList = dsBuildListFromStrings(inDSRef, kDSStdRecordTypeUsers, NULL);
    if (pRecTypeList == NULL) {
        dsStatus = eMemoryAllocError;
        goto cleanup;
    }
    
    // Allocate a working buffer; this may be grown if we receive a eDSBufferTooSmall error
    pSearchBuffer = dsDataBufferAllocate(inDSRef, ulBufferSize);
    if (pSearchBuffer == NULL) {
        dsStatus = eMemoryAllocError;
        goto cleanup;
    }
    
    // Now search for the record
    dsStatus = dsGetRecordList(inSearchNode, pSearchBuffer, pRecNameList, eDSExact, pRecTypeList, 
                               pAttribsToGet, 0, &ulRecCount, NULL);
    
    // If there was not an error and we only found 1 record for this user
    if (dsStatus == eDSNoErr && ulRecCount == 1) {
        tAttributeListRef   dsAttributeListRef  = 0;
        tRecordEntryPtr     dsRecordEntryPtr    = 0;
        int ii;
        
        // Get the first record entry from the buffer since we only expect one result
        dsStatus = dsGetRecordEntry(inSearchNode, pSearchBuffer, 1, &dsAttributeListRef, 
                                    &dsRecordEntryPtr);
        if (dsStatus == eDSNoErr) {
            // Loop through the attributes in the record to get the data we requested
            // NOTE: all indexes in the Open Directory API start with 1, not 0
            for (ii = 1; ii <= dsRecordEntryPtr->fRecordAttributeCount; ii++) {
                tAttributeEntryPtr      dsAttributeEntryPtr         = NULL;
                tAttributeValueEntryPtr dsAttributeValueEntryPtr    = NULL;
                tAttributeValueListRef  dsAttributeValueListRef     = 0;
                
                // Get the attribute entry from the record
                dsStatus = dsGetAttributeEntry(inSearchNode, pSearchBuffer, dsAttributeListRef, 
                                               ii, &dsAttributeValueListRef, &dsAttributeEntryPtr);
                
                // Get the value from the attribute if we were successful at getting an entry
                if (dsStatus == eDSNoErr) {
                    dsStatus = dsGetAttributeValue(inSearchNode, pSearchBuffer, 1, 
                                                   dsAttributeValueListRef, 
                                                   &dsAttributeValueEntryPtr);
                }
                
                // If we were successful, see which attribute we were getting and fill in the 
                // return values appropriately
                if (dsStatus == eDSNoErr) {
                    // Always check for the specific attributes, since a plugin is not restricted 
                    // from returning more data than you requested
                    
                    // Check the signature of the attribute and see if it is the metanode location
                    if (strcmp(dsAttributeEntryPtr->fAttributeSignature.fBufferData, 
                               kDSNAttrMetaNodeLocation) == 0)
                    {
                        *outNodeName = (char *) calloc(
                            dsAttributeValueEntryPtr->fAttributeValueData.fBufferSize + 1, 
                            sizeof(char));
                        if (*outNodeName != NULL) {
                            strncpy(*outNodeName, 
                                    dsAttributeValueEntryPtr->fAttributeValueData.fBufferData, 
                                    dsAttributeValueEntryPtr->fAttributeValueData.fBufferSize);
                        }
                    }
                    // If not, check to see if it is the record name
                    else if (strcmp(dsAttributeEntryPtr->fAttributeSignature.fBufferData, 
                                   kDSNAttrRecordName) == 0)
                    {
                        *outRecordName = (char *) calloc(
                            dsAttributeValueEntryPtr->fAttributeValueData.fBufferSize + 1, 
                            sizeof(char));
                        if (*outRecordName != NULL) {
                            strncpy(*outRecordName, 
                                    dsAttributeValueEntryPtr->fAttributeValueData.fBufferData, 
                                    dsAttributeValueEntryPtr->fAttributeValueData.fBufferSize);
                        }
                    }
                }
                
                // Close any value list references that may have been opened
                if (dsAttributeValueListRef != 0) {
                    dsCloseAttributeList(dsAttributeValueListRef);
                    dsAttributeValueListRef = 0;
                }
                
                // Free the attribute value entry if we got an entry
                if (dsAttributeValueEntryPtr != NULL) {
                    dsDeallocAttributeValueEntry(inDSRef, dsAttributeValueEntryPtr);
                    dsAttributeValueEntryPtr = NULL;
                }
                
                // Free the attribute entry itself as well
                if (dsAttributeEntryPtr != NULL) {
                    dsDeallocAttributeEntry(inDSRef, dsAttributeEntryPtr);
                    dsAttributeEntryPtr = NULL;
                }
            }
            
            // Close any reference to the attribute list
            if (dsAttributeListRef != 0) {
                dsCloseAttributeList(dsAttributeListRef);
                dsAttributeListRef = 0;
            }
            
            //Deallocate the record entry
            if (dsRecordEntryPtr != NULL) {
                dsDeallocRecordEntry(inDSRef, dsRecordEntryPtr);
                dsRecordEntryPtr = NULL;
            }
        }
    }
    else if (dsStatus == eDSNoErr && ulRecCount > 1) {
        // We have more than 1 user, then we shouldn't attempt to authenticate.
        // Return a eDSAuthInvalidUserName since we don't know which user to authenticate
        dsStatus = eDSAuthInvalidUserName;
    }
    
cleanup:
    // If we allocated pAttribsToGet, clean it up
    if (pAttribsToGet != NULL) {
        dsDataListDeallocate(inDSRef, pAttribsToGet);
        // Need to free the pointer since dsDataListDeallocate only frees the list items
        free(pAttribsToGet);
        pAttribsToGet = NULL;
    }
    
    // If we allocated pRecTypeList, clean it up
    if (pRecTypeList != NULL) {
        dsDataListDeallocate(inDSRef, pRecTypeList);
        // Need to free the pointer since dsDataListDeallocate only frees the list items
        free(pRecTypeList);
        pRecTypeList = NULL;
    }
    
    // If we allocated pRecNameList, clean it up
    if (pRecNameList != NULL) {
        dsDataListDeallocate(inDSRef, pRecNameList);
        // Need to free the pointer since dsDataListDeallocate only frees the list items
        free(pRecNameList);
        pRecNameList = NULL;
    }
    
    // If we allocated pSearchBuffer, clean it up
    if (pSearchBuffer != NULL) {
        dsDataBufferDeAllocate(inDSRef, pSearchBuffer);
        pSearchBuffer = NULL;
    }
    
    return dsStatus;
} // LocateUserNode

// -------------------------------------------------------------------------------------------------
tDirStatus DoPasswordAuth(tDirReference inDSRef, tDirNodeReference inNodeRef, 
                          const char *inAuthMethod, const char *inRecordName, 
                          const char *inPassword)
{
    tDirStatus      dsStatus        = eDSAuthFailed;
    tDataNodePtr    pAuthMethod     = NULL;
    tDataBufferPtr  pAuthStepData   = NULL;
    tDataBufferPtr  pAuthRespData   = NULL;
    tContextData    pContextData    = NULL;
    
    // If any of our parameters are NULL, return eDSNullParameter
    // If a password is not set for a user, an empty string should be sent for the password
    if (inDSRef == 0 || inNodeRef == 0 || inRecordName == NULL || inPassword == NULL) {
        return eDSNullParameter;
    }
    
    // Since this is password based, we can only support password-based methods
    if (strcmp(inAuthMethod, kDSStdAuthNodeNativeNoClearText) == 0 || 
        strcmp(inAuthMethod, kDSStdAuthNodeNativeClearTextOK) == 0 || 
        strcmp(inAuthMethod, kDSStdAuthClearText) == 0 || 
        strcmp(inAuthMethod, kDSStdAuthCrypt) == 0)
    {
        // Turn the specific method into a tDataNode
        pAuthMethod = dsDataNodeAllocateString(inDSRef, inAuthMethod);
        if (pAuthMethod == NULL) {
            dsStatus = eMemoryAllocError;
            goto cleanup;
        }
        
        // Allocate a buffer large enough to hold all the username and password plus length bytes
        pAuthStepData = 
            dsDataBufferAllocate(inDSRef, 4 + strlen(inRecordName) + 4 + strlen(inPassword));
        if (pAuthStepData == NULL) {
            dsStatus = eMemoryAllocError;
            goto cleanup;
        }
        
        // Allocate a buffer for the out step data even though we don't expect anything
        // NOTE: it is a required parameter
        pAuthRespData = dsDataBufferAllocate(inDSRef, 128);
        if (pAuthRespData == NULL) {
            dsStatus = eMemoryAllocError;
            goto cleanup;
        }
        
        // Now place the username and password into the buffer
        AppendStringToBuffer(pAuthStepData, inRecordName, strlen(inRecordName));
        AppendStringToBuffer(pAuthStepData, inPassword, strlen(inPassword));
        
        // Attempt the authentication
        dsStatus = 
            dsDoDirNodeAuth(inNodeRef, pAuthMethod, 1, pAuthStepData, pAuthRespData, &pContextData);
    }
    else {
        // Return a parameter error if the auth type is not password-based
        dsStatus = eDSAuthParameterError;
    }
    
cleanup:
    // Release pContextData if we had continue data
    if (pContextData != NULL) {
        dsReleaseContinueData(inDSRef, pContextData);
        pContextData = NULL;
    }
    
	// Deallocate memory for pAuthRespData if it was allocated
	if (pAuthRespData != NULL) {
		dsDataNodeDeAllocate(inDSRef, pAuthRespData);
		pAuthRespData = NULL;
	}
	
	// Deallocate memory for pAuthStepData if it was allocated
	if (pAuthStepData != NULL) {
		dsDataBufferDeAllocate(inDSRef, pAuthStepData);
		pAuthStepData = NULL;
	}
	
	// Deallocate memory for pAuthMethod if it was allocated
	if (pAuthMethod != NULL) {
		dsDataNodeDeAllocate(inDSRef, pAuthMethod);
		pAuthMethod = NULL;
	}
	
	return dsStatus;
}


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
// Authenication Phase
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
    authn_status        auth_status     = AUTH_GRANTED;
    tDirReference       dsRef           = 0;
    tDirNodeReference   dsSearchNodeRef = 0;
    tDirNodeReference   dsUserNodeRef   = 0;
    tDirStatus          dsStatus;
    char               *pRecordName     = NULL;
    char               *pNodeName       = NULL;
    
    // Open a connection to Directory Services
    dsStatus = dsOpenDirService(&dsRef);
    if (dsStatus == eDSNoErr) {
        // Open the search node
        dsStatus = OpenSearchNode(dsRef, &dsSearchNodeRef);
        if (dsStatus == eDSNoErr) {
            // Locate the user
            dsStatus = LocateUserNode(dsRef, dsSearchNodeRef, user, &pRecordName, &pNodeName);
            if (dsStatus == eDSNoErr) {
                // We should have what we need, but let's check to make sure
                if (pNodeName != NULL && pNodeName[0] != '\0' && 
                    pRecordName != NULL && pRecordName[0] != '\0')
                {
                    // We found the user, so try to authenticate them
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                                  "Located user '%s' = '%s' on node '%s'", 
                                  user, pRecordName, pNodeName);
                    
                    // We need to create a tDataListPtr from the "/plugin/node" path, 
                    // using "/" as the separator
                    tDataListPtr dsUserNodePath = dsBuildFromPath(dsRef, pNodeName, "/");
                    
                    dsStatus = dsOpenDirNode(dsRef, dsUserNodePath, &dsUserNodeRef);
                    if (dsStatus == eDSNoErr) {
                        // Authenticate the user
                        dsStatus = DoPasswordAuth(dsRef, dsUserNodeRef, 
                                                  kDSStdAuthNodeNativeClearTextOK, 
                                                  pRecordName, password);
                        if (dsStatus == eDSNoErr) {
                            auth_status = AUTH_GRANTED;
                        }
                        else {
                            auth_status = AUTH_DENIED;
                        }
                    }
                    
                    // Free the data list since it's no longer needed
                    dsDataListDeallocate(dsRef, dsUserNodePath);
                    free(dsUserNodePath);
                    dsUserNodePath = NULL;
                }
                else {
                    // Could not find the user
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                                  "Unable to locate user '%s'", user);
                    auth_status = AUTH_USER_NOT_FOUND;
                }
                
                // Free any node name that may have been returned
                if (pNodeName != NULL) {
                    free(pNodeName);
                    pNodeName = NULL;
                }
                
                // Free any record name that may have been returned
                if (pRecordName != NULL) {
                    free(pRecordName);
                    pRecordName = NULL;
                }
            }
            
            // Close the search node
            dsCloseDirNode(dsSearchNodeRef);
            dsSearchNodeRef = 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                          "Unable to locate and open the Search Node");
            auth_status = AUTH_GENERAL_ERROR;
        }
        
        // Close the connection to Directory Services
        dsCloseDirService(dsRef);
        dsRef = 0;
    }

    return auth_status;
}

// -------------------------------------------------------------------------------------------------
// Authorization Phase
// -------------------------------------------------------------------------------------------------
static int authz_ds_check_user_access(request_rec *r)
{
    return OK;
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