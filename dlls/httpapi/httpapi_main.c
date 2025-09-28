/*
 * HTTPAPI implementation
 *
 * Copyright 2009 Austin English
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define HTTPAPI_LINKAGE
#include "wine/http.h"
#include "winsvc.h"
#include "winternl.h"
#include "wine/debug.h"
#include <wincrypt.h>
#include <ctype.h>
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(http);

/* Define missing HTTP constants */
#ifndef FILE_DEVICE_HTTP
#define FILE_DEVICE_HTTP 0x00000037
#endif

#ifndef HTTP_SEND_RESPONSE_FLAG_DISCONNECT
#define HTTP_SEND_RESPONSE_FLAG_DISCONNECT 0x00000001
#endif

#ifndef HTTP_SEND_RESPONSE_FLAG_MORE_DATA
#define HTTP_SEND_RESPONSE_FLAG_MORE_DATA 0x00000002
#endif

#ifndef HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA
#define HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA 0x00000004
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef METHOD_NEITHER
#define METHOD_NEITHER 3
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef IOCTL_HTTP_SHUTDOWN_QUEUE
#define IOCTL_HTTP_SHUTDOWN_QUEUE CTL_CODE(FILE_DEVICE_HTTP, 13, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif

#ifndef IOCTL_HTTP_WAIT_FOR_DISCONNECT
#define IOCTL_HTTP_WAIT_FOR_DISCONNECT CTL_CODE(FILE_DEVICE_HTTP, 14, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif

#ifndef IOCTL_HTTP_CANCEL_REQUEST
#define IOCTL_HTTP_CANCEL_REQUEST CTL_CODE(FILE_DEVICE_HTTP, 15, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif

/* Define authentication schemes */
#ifndef HTTP_AUTH_SCHEME_BASIC
#define HTTP_AUTH_SCHEME_BASIC      0x00000001
#define HTTP_AUTH_SCHEME_DIGEST     0x00000002
#define HTTP_AUTH_SCHEME_NTLM       0x00000004
#define HTTP_AUTH_SCHEME_NEGOTIATE  0x00000008
#endif

/* Define authentication structure */
typedef struct _HTTP_SERVER_AUTHENTICATION_INFO {
    struct {
        BOOL Present;
    } Flags;
    ULONG AuthSchemes;
    BOOL ReceiveMutualAuth;
    BOOL ReceiveContextHandle;
    BOOL DisableNTLMCredentialCaching;
    UCHAR ExFlags;
    void *Reserved1;
    void *Reserved2;
} HTTP_SERVER_AUTHENTICATION_INFO;

/* Forward declarations for authentication functions */
struct url_group;
static void url_group_acquire(struct url_group *group);
static void url_group_release(struct url_group *group);
static struct url_group *get_url_group_for_request(HTTP_REQUEST_ID id);
static void inject_auth_header_if_needed(HTTP_RESPONSE *response, HTTP_REQUEST_ID id);
static struct url_group *find_url_group_by_queue(HANDLE queue);
static void add_request_mapping(HTTP_REQUEST_ID request_id, struct url_group *group);

/* debug channel declared above */

/* Always-on WebSocket PoC metadata */
struct request_ws_meta
{
    struct list entry;
    HTTP_REQUEST_ID request_id;
    BOOL upgrade_requested;
    char sec_ws_key[64];
    char sec_ws_protocol[64];
    USHORT original_status_code;  /* Preserve original status for debugging */
};

static struct list ws_meta_list = LIST_INIT(ws_meta_list);
static CRITICAL_SECTION ws_meta_cs;
static CRITICAL_SECTION_DEBUG ws_meta_cs_debug =
{
    0, 0, &ws_meta_cs,
    { &ws_meta_cs_debug.ProcessLocksList, &ws_meta_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": ws_meta_cs") }
};
static CRITICAL_SECTION ws_meta_cs = { &ws_meta_cs_debug, -1, 0, 0, 0, 0 };

static struct request_ws_meta *get_ws_meta(HTTP_REQUEST_ID id)
{
    struct request_ws_meta *m;
    EnterCriticalSection(&ws_meta_cs);
    LIST_FOR_EACH_ENTRY(m, &ws_meta_list, struct request_ws_meta, entry)
    {
        if (m->request_id == id)
        {
            LeaveCriticalSection(&ws_meta_cs);
            return m;
        }
    }
    LeaveCriticalSection(&ws_meta_cs);
    return NULL;
}

static void remove_ws_meta(HTTP_REQUEST_ID id)
{
    struct request_ws_meta *m, *next;
    EnterCriticalSection(&ws_meta_cs);
    LIST_FOR_EACH_ENTRY_SAFE(m, next, &ws_meta_list, struct request_ws_meta, entry)
    {
        if (m->request_id == id)
        {
            list_remove(&m->entry);
            free(m);
            break;
        }
    }
    LeaveCriticalSection(&ws_meta_cs);
}

static BOOL header_token_contains(const char *val, USHORT len, const char *token)
{
    /* Case-insensitive search for a comma/space separated token */
    USHORT i = 0; size_t tlen = strlen(token);
    while (i + tlen <= len)
    {
        /* Skip spaces and commas */
        while (i < len && (val[i] == ' ' || val[i] == '\t' || val[i] == ',')) i++;
        if (i + tlen > len) break;
        if (!_strnicmp(val + i, token, tlen))
        {
            /* Ensure token boundary */
            USHORT end = i + tlen;
            if ((i == 0 || val[i-1] == ' ' || val[i-1] == '\t' || val[i-1] == ',') &&
                (end == len || val[end] == ' ' || val[end] == '\t' || val[end] == ',' || val[end] == '\r'))
                return TRUE;
        }
        /* Move to next segment */
        while (i < len && val[i] != ',') i++;
        if (i < len && val[i] == ',') i++;
    }
    return FALSE;
}

static void maybe_store_ws_meta_from_request(HTTP_REQUEST *request)
{
    struct request_ws_meta *m;
    BOOL is_upgrade = FALSE;
    const HTTP_KNOWN_HEADER *conn = &request->s.Headers.KnownHeaders[HttpHeaderConnection];
    const HTTP_KNOWN_HEADER *upg  = &request->s.Headers.KnownHeaders[HttpHeaderUpgrade];
    char key_buf[64] = {0};
    char proto_buf[64] = {0};
    USHORT i;

    if (conn->RawValueLength && conn->pRawValue && header_token_contains(conn->pRawValue, conn->RawValueLength, "Upgrade"))
        is_upgrade = TRUE;
    if (upg->RawValueLength && upg->pRawValue && !_strnicmp(upg->pRawValue, "websocket", upg->RawValueLength))
        is_upgrade = TRUE;

    for (i = 0; i < request->s.Headers.UnknownHeaderCount; ++i)
    {
        HTTP_UNKNOWN_HEADER *uh = &request->s.Headers.pUnknownHeaders[i];
        if (!uh->pName || !uh->pRawValue) continue;
        if (uh->NameLength == 17 && !_strnicmp(uh->pName, "Sec-WebSocket-Key", uh->NameLength))
        {
            USHORT cpy = min((USHORT)(sizeof(key_buf) - 1), uh->RawValueLength);
            memcpy(key_buf, uh->pRawValue, cpy); key_buf[cpy] = '\0';
        }
        else if (uh->NameLength == 21 && !_strnicmp(uh->pName, "Sec-WebSocket-Protocol", uh->NameLength))
        {
            USHORT cpy = min((USHORT)(sizeof(proto_buf) - 1), uh->RawValueLength);
            memcpy(proto_buf, uh->pRawValue, cpy); proto_buf[cpy] = '\0';
        }
    }

    if (!is_upgrade) return;

    m = calloc(1, sizeof(*m));
    if (!m) return;
    m->request_id = request->s.RequestId;
    m->upgrade_requested = TRUE;
    if (key_buf[0]) lstrcpynA(m->sec_ws_key, key_buf, sizeof(m->sec_ws_key));
    if (proto_buf[0]) lstrcpynA(m->sec_ws_protocol, proto_buf, sizeof(m->sec_ws_protocol));

    EnterCriticalSection(&ws_meta_cs);
    list_add_tail(&ws_meta_list, &m->entry);
    LeaveCriticalSection(&ws_meta_cs);

    TRACE("Stored WebSocket meta for request %s (upgrade=%d, key=%s, protocol=%s)\n",
          wine_dbgstr_longlong(request->s.RequestId), m->upgrade_requested,
          debugstr_a(m->sec_ws_key), debugstr_a(m->sec_ws_protocol));
}

static BOOL compute_websocket_accept(const char *key, char **out_val, USHORT *out_len)
{
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    BYTE hash[20];
    DWORD hash_len = (DWORD)sizeof(hash);
    HCRYPTPROV prov = 0; HCRYPTHASH h = 0;
    BOOL ok = FALSE;
    size_t key_len = strlen(key);
    size_t in_len = key_len + sizeof(guid) - 1;
    char *concat = malloc(in_len);
    if (!concat) return FALSE;
    memcpy(concat, key, key_len);
    memcpy(concat + key_len, guid, sizeof(guid) - 1);

    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) goto done;
    if (!CryptCreateHash(prov, CALG_SHA1, 0, 0, &h)) goto done;
    if (!CryptHashData(h, (BYTE *)concat, (DWORD)in_len, 0)) goto done;
    if (!CryptGetHashParam(h, HP_HASHVAL, hash, &hash_len, 0)) goto done;

    /* Minimal base64 encoder (no CRLF), enough for 20-byte SHA1 */
    {
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t olen = ((hash_len + 2) / 3) * 4;
        char *obuf = malloc(olen + 1);
        size_t i, j = 0;
        if (!obuf) goto done;
        for (i = 0; i < hash_len; i += 3)
        {
            unsigned int v = hash[i] << 16;
            if (i + 1 < hash_len) v |= hash[i+1] << 8;
            if (i + 2 < hash_len) v |= hash[i+2];
            obuf[j++] = b64[(v >> 18) & 0x3f];
            obuf[j++] = b64[(v >> 12) & 0x3f];
            obuf[j++] = (i + 1 < hash_len) ? b64[(v >> 6) & 0x3f] : '=';
            obuf[j++] = (i + 2 < hash_len) ? b64[v & 0x3f] : '=';
        }
        obuf[j] = '\0';
        *out_val = obuf;
        *out_len = (USHORT)j;
        ok = TRUE;
    }

done:
    if (h) CryptDestroyHash(h);
    if (prov) CryptReleaseContext(prov, 0);
    free(concat);
    return ok;
}
static void remove_request_mapping(HTTP_REQUEST_ID request_id);
static void cleanup_stale_mappings(void);

/* Define HTTP performance counter IDs */
typedef enum _HTTP_PERFORMANCE_COUNTER_ID {
    HttpPerfCounterAllRequests,
    HttpPerfCounterUriRequests,
    HttpPerfCounterAllConnections,
    HttpPerfCounterActiveConnections,
    HttpPerfCounterConnectionAttempts,
    HttpPerfCounterFlushesCount,
    HttpPerfCounterConnections,
    HttpPerfCounterMaxConnections
} HTTP_PERFORMANCE_COUNTER_ID;

/* Global critical section for thread safety */
static CRITICAL_SECTION g_httpapi_cs;
static CRITICAL_SECTION_DEBUG g_httpapi_cs_debug =
{
    0, 0, &g_httpapi_cs,
    { &g_httpapi_cs_debug.ProcessLocksList, &g_httpapi_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": g_httpapi_cs") }
};
static CRITICAL_SECTION g_httpapi_cs = { &g_httpapi_cs_debug, -1, 0, 0, 0, 0 };

/***********************************************************************
 *        HttpInitialize       (HTTPAPI.@)
 *
 * Initializes HTTP Server API engine
 *
 * PARAMS
 *   version  [ I] HTTP API version which caller will use
 *   flags    [ I] initialization options which specify parts of API what will be used
 *   reserved [IO] reserved, must be NULL
 *
 * RETURNS
 *   NO_ERROR if function succeeds, or error code if function fails
 *
 */
ULONG WINAPI HttpInitialize(HTTPAPI_VERSION version, ULONG flags, void *reserved)
{
    SC_HANDLE manager, service;

    TRACE("version %u.%u, flags %#lx, reserved %p.\n", version.HttpApiMajorVersion,
            version.HttpApiMinorVersion, flags, reserved);

    if ((version.HttpApiMajorVersion != 1 && version.HttpApiMajorVersion != 2)
            || version.HttpApiMinorVersion)
        return ERROR_REVISION_MISMATCH;

    if (flags & ~(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG))
    {
        FIXME("Unhandled flags %#lx.\n", flags & ~(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG));
        return ERROR_SUCCESS;
    }

    if (reserved)
        WARN("Reserved parameter is not NULL (%p)\n", reserved);

    if (flags & HTTP_INITIALIZE_SERVER)
    {
        if (!(manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)))
            return GetLastError();

        if (!(service = OpenServiceW(manager, L"http", SERVICE_START)))
        {
            ERR("Failed to open HTTP service, error %lu.\n", GetLastError());
            CloseServiceHandle(manager);
            return GetLastError();
        }

        if (!StartServiceW(service, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        {
            ERR("Failed to start HTTP service, error %lu.\n", GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return GetLastError();
        }

        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    if (flags & HTTP_INITIALIZE_CONFIG)
    {
        /* HTTP_INITIALIZE_CONFIG is used to initialize configuration APIs.
         * On Windows, this would set up access to the HTTP Server API configuration store.
         * For Wine, we don't need to do anything special here as configuration
         * functions are already available. */
        TRACE("HTTP_INITIALIZE_CONFIG flag set, configuration APIs initialized.\n");
    }

    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpTerminate       (HTTPAPI.@)
 *
 * Cleans up HTTP Server API engine resources allocated by HttpInitialize
 *
 * PARAMS
 *   flags    [ I] options which specify parts of API what should be released
 *   reserved [IO] reserved, must be NULL
 *
 * RETURNS
 *   NO_ERROR if function succeeds, or error code if function fails
 *
 */
ULONG WINAPI HttpTerminate(ULONG flags, void *reserved)
{
    TRACE("(0x%lx, %p)\n", flags, reserved);

    if (reserved)
        WARN("Reserved parameter is not NULL (%p)\n", reserved);

    if (flags & HTTP_INITIALIZE_SERVER)
    {
        SC_HANDLE manager, service;
        SERVICE_STATUS status;

        if (!(manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)))
        {
            ERR("Failed to open SCM, error %lu.\n", GetLastError());
            /* According to docs, HttpTerminate should not fail often.
             * We'll return NO_ERROR even if service stop fails,
             * as the primary purpose is cleanup of client-side resources,
             * which are minimal in this implementation.
             */
            return NO_ERROR;
        }

        if (!(service = OpenServiceW(manager, L"http", SERVICE_STOP | SERVICE_QUERY_STATUS)))
        {
            ERR("Failed to open HTTP service, error %lu.\n", GetLastError());
            CloseServiceHandle(manager);
            return NO_ERROR;
        }

        if (QueryServiceStatus(service, &status))
        {
            if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_PAUSED)
            {
                if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
                {
                    DWORD err = GetLastError();
                    /* ERROR_SERVICE_NOT_ACTIVE is acceptable if another process already stopped it. */
                    if (err != ERROR_SERVICE_NOT_ACTIVE)
                        ERR("Failed to stop HTTP service, error %lu.\n", err);
                }
                else
                {
                    TRACE("HTTP service stop request sent.\n");
                    /* Optionally, wait here for the service to actually stop.
                     * For now, we just send the request and don't wait.
                     */
                }
            }
            else
            {
                TRACE("HTTP service not running or paused (state %lu).\n", status.dwCurrentState);
            }
        }
        else
        {
            ERR("Failed to query HTTP service status, error %lu.\n", GetLastError());
        }

        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if (flags & HTTP_INITIALIZE_CONFIG)
    {
        /* Clean up configuration-related resources if any.
         * Currently no specific cleanup needed for Wine. */
        TRACE("HTTP_INITIALIZE_CONFIG cleanup.\n");
    }
    
    if (flags & ~(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG))
    {
        FIXME("Unhandled flags %#lx.\n", flags & ~(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG));
    }
        
    return NO_ERROR;
}

/***********************************************************************
 *        HttpIsFeatureSupported     (HTTPAPI.@)
 *
 * Check if a specific HTTP Server API feature is supported.
 *
 * PARAMS
 *   feature_id [I] The feature to check
 *
 * RETURNS
 *   TRUE if the feature is supported, FALSE otherwise.
 */
BOOL WINAPI HttpIsFeatureSupported(ULONG feature_id)
{
    TRACE("feature_id %lu\n", feature_id);

    switch (feature_id)
    {
        case 0: /* HttpFeatureUnknown */
            return FALSE;
            
        case 1: /* HttpFeatureResponseTrailers */
            /* Response trailers in HTTP/1.1 chunked responses */
            TRACE("HttpFeatureResponseTrailers not supported\n");
            return FALSE;
            
        case 2: /* HttpFeatureApiTimings */
            /* Performance counters for HTTP API calls */
            TRACE("HttpFeatureApiTimings not supported\n");
            return FALSE;
            
        case 3: /* HttpFeatureDelegateEx */
            /* Extended delegation for kernel-mode drivers */
            TRACE("HttpFeatureDelegateEx not supported\n");
            return FALSE;
            
        default:
            WARN("Unknown feature_id %lu\n", feature_id);
            return FALSE;
    }
}

/***********************************************************************
 *        HttpDeleteServiceConfiguration     (HTTPAPI.@)
 *
 * Remove configuration record from HTTP Server API configuration store
 *
 * PARAMS
 *   handle     [I] reserved, must be 0
 *   type       [I] configuration record type
 *   config     [I] buffer which contains configuration record information
 *   length     [I] length of configuration record buffer
 *   overlapped [I] reserved, must be NULL
 *
 * RETURNS
 *   NO_ERROR if function succeeds, or error code if function fails
 *
 */
ULONG WINAPI HttpDeleteServiceConfiguration(HANDLE handle, HTTP_SERVICE_CONFIG_ID type,
                 void *config, ULONG length, OVERLAPPED *overlapped)
{
    FIXME("(%p, %d, %p, %ld, %p): stub!\n", handle, type, config, length, overlapped);
    return NO_ERROR;
}

/***********************************************************************
 *        HttpQueryServiceConfiguration     (HTTPAPI.@)
 *
 * Retrieves configuration records from HTTP Server API configuration store
 *
 * PARAMS
 *   handle     [ I] reserved, must be 0
 *   type       [ I] configuration records type
 *   query      [ I] buffer which contains query data used to retrieve records
 *   query_len  [ I] length of query buffer
 *   buffer     [IO] buffer to store query results
 *   buffer_len [ I] length of output buffer
 *   data_len   [ O] optional pointer to a buffer which receives query result length
 *   overlapped [ I] reserved, must be NULL
 *
 * RETURNS
 *   NO_ERROR if function succeeds, or error code if function fails
 *
 */
ULONG WINAPI HttpQueryServiceConfiguration(HANDLE handle, HTTP_SERVICE_CONFIG_ID type,
                 void *query, ULONG query_len, void *buffer, ULONG buffer_len,
                 ULONG *data_len, OVERLAPPED *overlapped)
{
    TRACE("handle %p, type %d, query %p, query_len %lu, buffer %p, buffer_len %lu, data_len %p, overlapped %p.\n",
          handle, type, query, query_len, buffer, buffer_len, data_len, overlapped);

    if (handle)
    {
        WARN("Handle parameter should be NULL\n");
        return ERROR_INVALID_PARAMETER;
    }

    if (overlapped)
    {
        WARN("Overlapped I/O not supported\n");
        return ERROR_INVALID_PARAMETER;
    }

    switch (type)
    {
        case HttpServiceConfigIPListenList:
        {
            /* Return an empty list for IP listen configuration */
            /* Note: HTTP_SERVICE_CONFIG_IP_LISTEN types not yet defined in Wine headers */
            ULONG required_size = sizeof(DWORD) + sizeof(void*); /* AddrCount + AddrList */

            TRACE("Querying IP listen list\n");

            /* Check buffer pointer first before using it */
            if (!buffer && buffer_len > 0)
                return ERROR_INVALID_PARAMETER;

            /* Set required size if requested */
            if (data_len)
                *data_len = required_size;

            /* Check buffer size */
            if (buffer_len < required_size)
                return ERROR_INSUFFICIENT_BUFFER;

            /* Return empty list - no specific IP addresses configured */
            if (buffer)
            {
                DWORD *addr_count = (DWORD*)buffer;
                void **addr_list = (void**)((char*)buffer + sizeof(DWORD));
                *addr_count = 0;
                *addr_list = NULL;
            }
            
            return ERROR_SUCCESS;
        }

        case HttpServiceConfigSSLCertInfo:
        {
            /* SSL certificate configuration */
            TRACE("Querying SSL certificate info\n");
            
            /* For now, return no SSL certificates configured */
            if (data_len)
                *data_len = 0;
                
            return ERROR_FILE_NOT_FOUND;
        }

        case HttpServiceConfigUrlAclInfo:
        {
            /* URL ACL configuration */
            TRACE("Querying URL ACL info\n");
            
            /* For now, return no URL ACLs configured */
            if (data_len)
                *data_len = 0;
                
            return ERROR_FILE_NOT_FOUND;
        }

        case HttpServiceConfigTimeout:
        {
            /* Timeout configuration */
            /* Note: HTTP_SERVICE_CONFIG_TIMEOUT_PARAM not yet defined in Wine headers */
            ULONG required_size = sizeof(USHORT) * 6; /* 6 timeout values */

            TRACE("Querying timeout configuration\n");

            /* Check buffer pointer first before using it */
            if (!buffer && buffer_len > 0)
                return ERROR_INVALID_PARAMETER;

            /* Set required size if requested */
            if (data_len)
                *data_len = required_size;

            /* Check buffer size */
            if (buffer_len < required_size)
                return ERROR_INSUFFICIENT_BUFFER;

            /* Return default timeout values */
            if (buffer)
            {
                USHORT *timeouts = (USHORT*)buffer;
                timeouts[0] = 120;        /* EntityBody: 120 seconds */
                timeouts[1] = 120;        /* DrainEntityBody: 120 seconds */
                timeouts[2] = 120;        /* RequestQueue: 120 seconds */
                timeouts[3] = 120;        /* IdleConnection: 120 seconds */
                timeouts[4] = 120;        /* HeaderWait: 120 seconds */
                timeouts[5] = 240;        /* MinSendRate: 240 bytes/second */
            }

            return ERROR_SUCCESS;
        }

        default:
            FIXME("Unhandled configuration type %d\n", type);
            return ERROR_INVALID_PARAMETER;
    }
}

/***********************************************************************
 *        HttpSetServiceConfiguration     (HTTPAPI.@)
 *
 * Add configuration record to HTTP Server API configuration store
 *
 * PARAMS
 *   handle     [I] reserved, must be 0
 *   type       [I] configuration record type
 *   config     [I] buffer which contains configuration record information
 *   length     [I] length of configuration record buffer
 *   overlapped [I] reserved, must be NULL
 *
 * RETURNS
 *   NO_ERROR if function succeeds, or error code if function fails
 *
 */
ULONG WINAPI HttpSetServiceConfiguration(HANDLE handle, HTTP_SERVICE_CONFIG_ID type,
                 void *config, ULONG length, OVERLAPPED *overlapped)
{
    FIXME("(%p, %d, %p, %ld, %p): stub!\n", handle, type, config, length, overlapped);
    return NO_ERROR;
}

/***********************************************************************
 *        HttpCreateHttpHandle     (HTTPAPI.@)
 *
 * Creates a handle to the HTTP request queue
 *
 * PARAMS
 *   handle     [O] handle to request queue
 *   reserved   [I] reserved, must be NULL
 *
 * RETURNS
 *   NO_ERROR if function succeeds, or error code if function fails
 *
 */
ULONG WINAPI HttpCreateHttpHandle(HANDLE *handle, ULONG reserved)
{
    OBJECT_ATTRIBUTES attr = {sizeof(attr)};
    UNICODE_STRING string = RTL_CONSTANT_STRING(L"\\Device\\Http\\ReqQueue");
    IO_STATUS_BLOCK iosb;

    TRACE("handle %p, reserved %#lx.\n", handle, reserved);

    if (!handle)
        return ERROR_INVALID_PARAMETER;

    attr.ObjectName = &string;
    return RtlNtStatusToDosError(NtCreateFile(handle, SYNCHRONIZE, &attr, &iosb, NULL,
            FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0));
}

static ULONG add_url(HANDLE queue, const WCHAR *urlW, HTTP_URL_CONTEXT context)
{
    struct http_add_url_params *params;
    ULONG ret = ERROR_SUCCESS;
    OVERLAPPED ovl;
    HANDLE hEvent;
    int len;

    len = WideCharToMultiByte(CP_ACP, 0, urlW, -1, NULL, 0, NULL, NULL);
    if (!(params = malloc(sizeof(struct http_add_url_params) + len)))
        return ERROR_OUTOFMEMORY;
    WideCharToMultiByte(CP_ACP, 0, urlW, -1, params->url, len, NULL, NULL);
    params->context = context;

    /* Store original handle separately before setting alertable bit */
    hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hEvent)
    {
        free(params);
        return ERROR_OUTOFMEMORY;
    }
    ovl.hEvent = (HANDLE)((ULONG_PTR)hEvent | 1);

    if (!DeviceIoControl(queue, IOCTL_HTTP_ADD_URL, params,
            (DWORD)(sizeof(struct http_add_url_params) + len), NULL, 0, NULL, &ovl))
        ret = GetLastError();
    CloseHandle(hEvent);  /* Close the original handle, not the modified one */
    free(params);
    return ret;
}

/***********************************************************************
 *        HttpAddUrl     (HTTPAPI.@)
 */
ULONG WINAPI HttpAddUrl(HANDLE queue, const WCHAR *url, void *reserved)
{
    ULONG ret;
    TRACE("queue %p, url %s, reserved %p.\n", queue, debugstr_w(url), reserved);

    if (!queue)
        return ERROR_INVALID_PARAMETER;

    if (!url)
        return ERROR_INVALID_PARAMETER;

    if (reserved)
        WARN("Reserved parameter is not NULL (%p)\n", reserved);

    ret = add_url(queue, url, 0);
    
    if (ret == ERROR_SUCCESS)
    {
        TRACE("*** HTTP SERVER READY: Successfully bound to URL %s ***\n", debugstr_w(url));
        TRACE("*** Server can now accept HTTP requests on this URL ***\n");
    }
    else
    {
        TRACE("Failed to bind to URL %s, error %lu\n", debugstr_w(url), ret);
    }
    
    return ret;
}

static ULONG remove_url(HANDLE queue, const WCHAR *urlW)
{
    ULONG ret = ERROR_SUCCESS;
    OVERLAPPED ovl = {};
    HANDLE hEvent;
    char *url;
    int len;

    len = WideCharToMultiByte(CP_ACP, 0, urlW, -1, NULL, 0, NULL, NULL);
    if (!(url = malloc(len)))
        return ERROR_OUTOFMEMORY;
    WideCharToMultiByte(CP_ACP, 0, urlW, -1, url, len, NULL, NULL);

    /* Store original handle separately before setting alertable bit */
    hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hEvent)
    {
        free(url);
        return ERROR_OUTOFMEMORY;
    }
    ovl.hEvent = (HANDLE)((ULONG_PTR)hEvent | 1);

    if (!DeviceIoControl(queue, IOCTL_HTTP_REMOVE_URL, url, (DWORD)len, NULL, 0, NULL, &ovl))
        ret = GetLastError();
    CloseHandle(hEvent);  /* Close the original handle, not the modified one */
    free(url);
    return ret;
}

/***********************************************************************
 *        HttpRemoveUrl     (HTTPAPI.@)
 */
ULONG WINAPI HttpRemoveUrl(HANDLE queue, const WCHAR *url)
{
    TRACE("queue %p, url %s.\n", queue, debugstr_w(url));

    if (!queue)
        return ERROR_INVALID_PARAMETER;
        
    if (!url)
        return ERROR_INVALID_PARAMETER;

    return remove_url(queue, url);
}

/***********************************************************************
 *        HttpReceiveRequestEntityBody     (HTTPAPI.@)
 */
ULONG WINAPI HttpReceiveRequestEntityBody(HANDLE queue, HTTP_REQUEST_ID id, ULONG flags,
        void *buffer, ULONG size, ULONG *ret_size, OVERLAPPED *ovl)
{
    struct http_receive_body_params params =
    {
        .id = id,
        .bits = sizeof(void *) * 8,
    };
    ULONG ret = ERROR_SUCCESS;
    ULONG local_ret_size;
    OVERLAPPED sync_ovl;

    TRACE("queue %p, id %s, flags %#lx, buffer %p, size %#lx, ret_size %p, ovl %p.\n",
            queue, wine_dbgstr_longlong(id), flags, buffer, size, ret_size, ovl);

    if (flags)
        FIXME("Ignoring flags %#lx.\n", flags);

    if (!ovl)
    {
        sync_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!sync_ovl.hEvent)
            return GetLastError();
        ovl = &sync_ovl;
    }

    if (!ret_size)
        ret_size = &local_ret_size;

    if (!DeviceIoControl(queue, IOCTL_HTTP_RECEIVE_BODY, &params, (DWORD)sizeof(params), buffer, (DWORD)size, ret_size, ovl))
        ret = GetLastError();

    if (ovl == &sync_ovl)
    {
        if (ret == ERROR_IO_PENDING)
        {
            ret = ERROR_SUCCESS;
            if (!GetOverlappedResult(queue, ovl, ret_size, TRUE))
                ret = GetLastError();
        }
        CloseHandle(sync_ovl.hEvent);
    }

    return ret;
}

static void log_http_request_details(const HTTP_REQUEST *request)
{
    int i;
    if (!request) return;
    
    TRACE("=== HTTP_REQUEST DIAGNOSTIC INFO ===\n");
    TRACE("  Flags: 0x%08x\n", request->s.Flags);
    TRACE("  ConnectionId: 0x%016llx\n", (unsigned long long)request->s.ConnectionId);
    TRACE("  RequestId: 0x%016llx\n", (unsigned long long)request->s.RequestId);
    TRACE("  UrlContext: 0x%016llx\n", (unsigned long long)request->s.UrlContext);
    TRACE("  Version: %u.%u\n", request->s.Version.MajorVersion, request->s.Version.MinorVersion);
    TRACE("  Verb: %u", request->s.Verb);
    
    switch(request->s.Verb) {
        case HttpVerbGET: TRACE(" (GET)\n"); break;
        case HttpVerbPOST: TRACE(" (POST)\n"); break;
        case HttpVerbPUT: TRACE(" (PUT)\n"); break;
        case HttpVerbDELETE: TRACE(" (DELETE)\n"); break;
        case HttpVerbHEAD: TRACE(" (HEAD)\n"); break;
        case HttpVerbOPTIONS: TRACE(" (OPTIONS)\n"); break;
        default: TRACE(" (Unknown/Custom)\n"); break;
    }
    
    TRACE("  UnknownVerbLength: %u\n", request->s.UnknownVerbLength);
    TRACE("  RawUrlLength: %u\n", request->s.RawUrlLength);
    
    if (request->s.pRawUrl)
        TRACE("  RawUrl: %.*s\n", request->s.RawUrlLength, request->s.pRawUrl);
    
    TRACE("  CookedUrl.FullUrlLength: %u\n", request->s.CookedUrl.FullUrlLength);
    TRACE("  CookedUrl.HostLength: %u\n", request->s.CookedUrl.HostLength);
    TRACE("  CookedUrl.AbsPathLength: %u\n", request->s.CookedUrl.AbsPathLength);
    TRACE("  CookedUrl.QueryStringLength: %u\n", request->s.CookedUrl.QueryStringLength);
    
    if (request->s.CookedUrl.pFullUrl)
        TRACE("  CookedUrl.FullUrl: %ls\n", request->s.CookedUrl.pFullUrl);
    if (request->s.CookedUrl.pHost)
        TRACE("  CookedUrl.Host: %.*ls\n", request->s.CookedUrl.HostLength/sizeof(WCHAR), request->s.CookedUrl.pHost);
    if (request->s.CookedUrl.pAbsPath)
        TRACE("  CookedUrl.AbsPath: %.*ls\n", request->s.CookedUrl.AbsPathLength/sizeof(WCHAR), request->s.CookedUrl.pAbsPath);
    if (request->s.CookedUrl.pQueryString)
        TRACE("  CookedUrl.QueryString: %.*ls\n", request->s.CookedUrl.QueryStringLength/sizeof(WCHAR), request->s.CookedUrl.pQueryString);
    
    TRACE("  Headers.UnknownHeaderCount: %u\n", request->s.Headers.UnknownHeaderCount);
    
    /* Log known headers that are present */
    for (i = 0; i < HttpHeaderRequestMaximum; i++) {
        if (request->s.Headers.KnownHeaders[i].RawValueLength > 0) {
            TRACE("  KnownHeader[%d]: %.*s\n", i,
                request->s.Headers.KnownHeaders[i].RawValueLength,
                request->s.Headers.KnownHeaders[i].pRawValue);
        }
    }
    
    TRACE("  BytesReceived: %llu\n", (unsigned long long)request->s.BytesReceived);
    TRACE("  EntityChunkCount: %u\n", request->s.EntityChunkCount);
    
    if (request->s.EntityChunkCount > 0 && request->s.pEntityChunks)
        TRACE("  Has entity body data\n");
    
    TRACE("=== END HTTP_REQUEST DIAGNOSTIC ===\n");
}

/***********************************************************************
 *        HttpReceiveHttpRequest     (HTTPAPI.@)
 */
ULONG WINAPI HttpReceiveHttpRequest(HANDLE queue, HTTP_REQUEST_ID id, ULONG flags,
        HTTP_REQUEST *request, ULONG size, ULONG *ret_size, OVERLAPPED *ovl)
{
    struct http_receive_request_params params;
    ULONG ret = ERROR_SUCCESS;
    ULONG local_ret_size;
    OVERLAPPED sync_ovl;

    if (!queue)
        return ERROR_INVALID_PARAMETER;
        
    if (!request)
        return ERROR_INVALID_PARAMETER;
        
    params.addr = (ULONG_PTR)request;
    params.id = id;
    params.flags = flags;
    params.bits = sizeof(void *) * 8;

    TRACE("queue %p, id %s, flags %#lx, request %p, size %#lx, ret_size %p, ovl %p.\n",
            queue, wine_dbgstr_longlong(id), flags, request, size, ret_size, ovl);
    
    /* Log when server starts waiting for requests - removed to avoid spam
     * BC calls HttpReceiveHttpRequest repeatedly from many threads */

    if (flags & ~HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY)
        FIXME("Ignoring flags %#lx.\n", flags & ~HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY);

    if (size < sizeof(HTTP_REQUEST_V1))
        return ERROR_INSUFFICIENT_BUFFER;

    if (!ovl)
    {
        sync_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!sync_ovl.hEvent)
            return GetLastError();
        ovl = &sync_ovl;
    }

    if (!ret_size)
        ret_size = &local_ret_size;

    if (!DeviceIoControl(queue, IOCTL_HTTP_RECEIVE_REQUEST, &params, (DWORD)sizeof(params), request, (DWORD)size, ret_size, ovl))
        ret = GetLastError();

    if (ovl == &sync_ovl)
    {
        if (ret == ERROR_IO_PENDING)
        {
            ret = ERROR_SUCCESS;
            if (!GetOverlappedResult(queue, ovl, ret_size, TRUE))
                ret = GetLastError();
        }
        CloseHandle(sync_ovl.hEvent);
    }

    /* Log detailed request information for debugging if successful */
    if (ret == ERROR_SUCCESS)
    {
        log_http_request_details(request);
    }
    
    /* If request was successfully received, establish mapping to URL group */
    if (ret == ERROR_SUCCESS && request->s.RequestId != 0)
    {
        
        struct url_group *group = find_url_group_by_queue(queue);
        if (group)
        {
            add_request_mapping(request->s.RequestId, group);
            TRACE("Mapped request %s to URL group %p for queue %p\n", 
                  wine_dbgstr_longlong(request->s.RequestId), group, queue);
            url_group_release(group);  /* Release the reference from find_url_group_by_queue */
        }
        else
        {
            TRACE("WARNING: No URL group found for queue %p, request %s\n", 
                  queue, wine_dbgstr_longlong(request->s.RequestId));
        }

        /* Always-on PoC: capture WebSocket upgrade metadata for this request */
        maybe_store_ws_meta_from_request(request);
    }

    return ret;
}

static int format_date(char *buffer, size_t size)
{
    static const char day_names[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char month_names[12][4] =
            {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    SYSTEMTIME date;
    GetSystemTime(&date);
    return snprintf(buffer, size, "Date: %s, %02u %s %u %02u:%02u:%02u GMT\r\n",
            day_names[date.wDayOfWeek], date.wDay, month_names[date.wMonth - 1],
            date.wYear, date.wHour, date.wMinute, date.wSecond);
}

/***********************************************************************
 *        HttpSendHttpResponse     (HTTPAPI.@)
 */
ULONG WINAPI HttpSendHttpResponse(HANDLE queue, HTTP_REQUEST_ID id, ULONG flags,
        HTTP_RESPONSE *response, HTTP_CACHE_POLICY *cache_policy, ULONG *ret_size,
        void *reserved1, ULONG reserved2, OVERLAPPED *ovl, HTTP_LOG_DATA *log_data)
{
    static const char *const header_names[] =
    {
        "Cache-Control",
        "Connection",
        "Date",
        "Keep-Alive",
        "Pragma",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Via",
        "Warning",
        "Allow",
        "Content-Length",
        "Content-Type",
        "Content-Encoding",
        "Content-Language",
        "Content-Location",
        "Content-MD5",
        "Content-Range",
        "Expires",
        "Last-Modified",
        "Accept-Ranges",
        "Age",
        "ETag",
        "Location",
        "Proxy-Authenticate",
        "Retry-After",
        "Server",
        "Set-Cookie",
        "Vary",
        "WWW-Authenticate",
    };

    struct http_response *buffer;
    OVERLAPPED dummy_ovl = {};
    ULONG ret = ERROR_SUCCESS;
    int len, body_len = 0;
    int status_len, header_len, content_len_size, header_size, written;
    size_t remaining;
    BOOL content_length_added = FALSE;
    char *p, dummy[12];
    USHORT i;
    HTTP_UNKNOWN_HEADER *orig_unknown_headers = NULL;
    USHORT orig_unknown_count = 0;
    BOOL ws_accept_injected = FALSE;

    TRACE("queue %p, id %s, flags %#lx, response %p, cache_policy %p, "
            "ret_size %p, reserved1 %p, reserved2 %#lx, ovl %p, log_data %p.\n",
            queue, wine_dbgstr_longlong(id), flags, response, cache_policy,
            ret_size, reserved1, reserved2, ovl, log_data);

    /* Validate parameters */
    if (!queue)
        return ERROR_INVALID_PARAMETER;
        
    if (!response)
        return ERROR_INVALID_PARAMETER;
        
    /* Validate response structure */
    if (response->s.ReasonLength && !response->s.pReason)
        return ERROR_INVALID_PARAMETER;
        
    if (response->s.EntityChunkCount && !response->s.pEntityChunks)
        return ERROR_INVALID_PARAMETER;

    /* Create request mapping if it doesn't exist yet (late binding) */
    {
        struct url_group *existing = get_url_group_for_request(id);
        if (!existing)
        {
            struct url_group *group = find_url_group_by_queue(queue);
            if (group)
            {
                add_request_mapping(id, group);
                TRACE("Late-binding: Mapped request %s to URL group %p for queue %p\n", 
                      wine_dbgstr_longlong(id), group, queue);
                url_group_release(group);
            }
        }
        else
        {
            url_group_release(existing);  /* Release the reference from get_url_group_for_request */
        }
    }
    
    /* Auto-inject authentication headers if needed (after mapping is established) */
    TRACE("Response status code: %d\n", response->s.StatusCode);
    
    /* Debug 429 responses from BC */
    if (response->s.StatusCode == 429)
    {
        FIXME("*** BC SENDING 429 RESPONSE ***\n");
        FIXME("*** Reason: %.*s ***\n", response->s.ReasonLength, response->s.pReason ? response->s.pReason : "(null)");
        FIXME("*** Request ID: %s ***\n", wine_dbgstr_longlong(id));
        
        /* Dump headers to understand why BC is throttling */
        for (i = 0; i < sizeof(header_names)/sizeof(header_names[0]) && i < HttpHeaderMaximum; i++)
        {
            if (response->s.Headers.KnownHeaders[i].RawValueLength)
            {
                FIXME("*** Header %s: %.*s ***\n", header_names[i],
                      response->s.Headers.KnownHeaders[i].RawValueLength,
                      response->s.Headers.KnownHeaders[i].pRawValue);
            }
        }
        
        /* Log stack trace for debugging */
        if (getenv("WINE_DEBUG_429"))
        {
            FIXME("*** STACK TRACE: 429 response triggered - use winedbg to attach ***\n");
            /* Don't use int3 as it might crash if no debugger attached */
        }
        /* Optional: force Connection: close on 429 to simplify client retry timing */
        if (getenv("WINE_HTTP_CLOSE_ON_429"))
        {
            response->s.Headers.KnownHeaders[HttpHeaderConnection].pRawValue = "close";
            response->s.Headers.KnownHeaders[HttpHeaderConnection].RawValueLength = 5;
            TRACE("Set Connection: close for 429 due to WINE_HTTP_CLOSE_ON_429\n");
        }
    }
    
    inject_auth_header_if_needed(response, id);

    /* PoC: Convert 401 to 101 Switching Protocols only for WebSocket upgrade requests */
    /* Gate behind explicit opt-in environment variable */
    if (getenv("WINE_HTTP_WS_POC") && response->s.StatusCode == 401)
    {
        struct request_ws_meta *m = get_ws_meta(id);
        
        /* Only convert if this was actually a WebSocket upgrade request */
        if (m && m->upgrade_requested)
        {
            char *accept_val = NULL; USHORT accept_len = 0;
            
            /* Preserve original status for debugging */
            m->original_status_code = response->s.StatusCode;
            
            FIXME("POC MODE: Converting %d to 101 for WebSocket upgrade (WINE_HTTP_WS_POC enabled)\n", 
                  m->original_status_code);
            TRACE("Original status: %d, changing to 101 for WebSocket request %s\n", 
                  m->original_status_code, wine_dbgstr_longlong(id));

            /* Change status to 101 Switching Protocols */
            response->s.StatusCode = 101;
            response->s.ReasonLength = 19;
            response->s.pReason = "Switching Protocols";

            /* Required WebSocket headers */
            response->s.Headers.KnownHeaders[HttpHeaderUpgrade].pRawValue = "websocket";
            response->s.Headers.KnownHeaders[HttpHeaderUpgrade].RawValueLength = 9;
            response->s.Headers.KnownHeaders[HttpHeaderConnection].pRawValue = "Upgrade";
            response->s.Headers.KnownHeaders[HttpHeaderConnection].RawValueLength = 7;

            /* Remove auth challenge */
            response->s.Headers.KnownHeaders[HttpHeaderWwwAuthenticate].pRawValue = NULL;
            response->s.Headers.KnownHeaders[HttpHeaderWwwAuthenticate].RawValueLength = 0;

            /* If we captured a client key, compute and add Sec-WebSocket-Accept */
            if (m->sec_ws_key[0] && compute_websocket_accept(m->sec_ws_key, &accept_val, &accept_len))
            {
                HTTP_UNKNOWN_HEADER *old = response->s.Headers.pUnknownHeaders;
                USHORT old_cnt = response->s.Headers.UnknownHeaderCount;
                HTTP_UNKNOWN_HEADER *arr = calloc(old_cnt + 1, sizeof(*arr));
                if (arr)
                {
                    if (old_cnt && old) memcpy(arr, old, old_cnt * sizeof(*arr));
                    arr[old_cnt].pName = "Sec-WebSocket-Accept";
                    arr[old_cnt].NameLength = 19;
                    arr[old_cnt].pRawValue = accept_val;
                    arr[old_cnt].RawValueLength = accept_len;

                    if (!orig_unknown_headers)
                    {
                        orig_unknown_headers = old;
                        orig_unknown_count = old_cnt;
                    }
                    response->s.Headers.pUnknownHeaders = arr;
                    response->s.Headers.UnknownHeaderCount = old_cnt + 1;
                    ws_accept_injected = TRUE;
                }
                else
                {
                    free(accept_val);
                }
            }
        }
        else
        {
            TRACE("Not converting status %d - request %s is not a WebSocket upgrade\n", 
                  response->s.StatusCode, wine_dbgstr_longlong(id));
        }
    }
    else if (response->s.StatusCode == 401 && !getenv("WINE_HTTP_WS_POC"))
    {
        TRACE("Not converting 401 to 101 - WINE_HTTP_WS_POC not set, normal auth flow\n");
    }
    
    /* Don't disconnect during NTLM authentication */
    if (response->s.StatusCode == 401)
    {
        /* Check if NTLM authentication is enabled - this will be handled in inject_auth_header_if_needed */
        /* For now, keep connection alive for all 401 responses */
        TRACE("Keeping connection alive for authentication challenge\n");
        flags &= ~HTTP_SEND_RESPONSE_FLAG_DISCONNECT;
    }

    if (flags & ~(HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
        FIXME("Unhandled flags %#lx.\n", flags & ~(HTTP_SEND_RESPONSE_FLAG_MORE_DATA));
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT)
        TRACE("HTTP_SEND_RESPONSE_FLAG_DISCONNECT is set, connection will be closed after send.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA)
        TRACE("HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA is set.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_ENABLE_NAGLING)
        TRACE("HTTP_SEND_RESPONSE_FLAG_ENABLE_NAGLING is set.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_PROCESS_RANGES)
        TRACE("HTTP_SEND_RESPONSE_FLAG_PROCESS_RANGES is set.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_OPAQUE)
        TRACE("HTTP_SEND_RESPONSE_FLAG_OPAQUE is set.\n");
    
    if (response->s.Flags)
        FIXME("Unhandled response flags %#lx.\n", response->s.Flags);
    if (cache_policy)
        WARN("Ignoring cache_policy.\n");
    if (log_data)
        WARN("Ignoring log_data.\n");
    if (reserved1)
        WARN("Reserved parameter reserved1 is not NULL (%p)\n", reserved1);
    if (reserved2)
        WARN("Reserved parameter reserved2 is not zero (%lu)\n", reserved2);

    /* === P/INVOKE BOUNDARY DIAGNOSTICS === */
    if (response)
    {
        TRACE("*** P/INVOKE BOUNDARY DIAGNOSTICS ***\n");
        TRACE("Response pointer: %p\n", response);
        TRACE("Response->Version: %u.%u\n", response->s.Version.MajorVersion, response->s.Version.MinorVersion);
        TRACE("Response->StatusCode: %u\n", response->s.StatusCode);
        TRACE("Response->EntityChunkCount: %u\n", response->s.EntityChunkCount);
        TRACE("Response->pEntityChunks: %p\n", response->s.pEntityChunks);

        /* Check if this might be a V2 struct by reading beyond V1 */
        /* Note: Removed exception handling as it's not available in MinGW context */
        /* Just do basic struct analysis */
        TRACE("*** Checking struct version ***\n");
        TRACE("Response struct base address: %p\n", response);
        TRACE("Expected V1 size: %zu bytes\n", (size_t)sizeof(HTTP_RESPONSE_V1));

        /* Log what we'd expect if this were a V2 struct */
        TRACE("If this were HTTP_RESPONSE_V2:\n");
        TRACE("  - ResponseInfoCount would be at offset %zu\n", (size_t)sizeof(HTTP_RESPONSE_V1));
        TRACE("  - pResponseInfo would be at offset %zu\n", (size_t)(sizeof(HTTP_RESPONSE_V1) + sizeof(USHORT)));

        TRACE("*** END P/INVOKE DIAGNOSTICS ***\n");
    }

    /* Debug BC response details */
    if (response)
    {
        TRACE("*** BC RESPONSE DEBUG ***\n");
        TRACE("StatusCode: %d\n", response->s.StatusCode);
        TRACE("EntityChunkCount: %d\n", response->s.EntityChunkCount);
        TRACE("ReasonLength: %d\n", response->s.ReasonLength);
        TRACE("Flags: 0x%x\n", response->s.Flags);

        /* Check Content-Type header */
        if (response->s.Headers.KnownHeaders[HttpHeaderContentType].pRawValue)
        {
            TRACE("Content-Type: %.*s\n",
                  response->s.Headers.KnownHeaders[HttpHeaderContentType].RawValueLength,
                  response->s.Headers.KnownHeaders[HttpHeaderContentType].pRawValue);
        }

        /* Check Content-Length header */
        if (response->s.Headers.KnownHeaders[HttpHeaderContentLength].pRawValue)
        {
            TRACE("Content-Length header: %.*s\n",
                  response->s.Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength,
                  response->s.Headers.KnownHeaders[HttpHeaderContentLength].pRawValue);
        }

        /* Dump first entity chunk if any */
        if (response->s.EntityChunkCount > 0 && response->s.pEntityChunks)
        {
            TRACE("First chunk type: %d\n", response->s.pEntityChunks[0].DataChunkType);
            if (response->s.pEntityChunks[0].DataChunkType == HttpDataChunkFromMemory)
            {
                TRACE("First chunk length: %lu\n", response->s.pEntityChunks[0].FromMemory.BufferLength);
                if (response->s.pEntityChunks[0].FromMemory.BufferLength > 0)
                {
                    TRACE("First 100 bytes: %.*s\n",
                          min(100, response->s.pEntityChunks[0].FromMemory.BufferLength),
                          (char*)response->s.pEntityChunks[0].FromMemory.pBuffer);
                }
            }
        }
        TRACE("*** END BC RESPONSE DEBUG ***\n");
    }

    /* === WINE BC RESPONSE WORKAROUND - DISABLED === */
    /* This workaround was causing incorrect responses for different endpoints */
    /* The async I/O fix should resolve the underlying issue */
#if 0
    static HTTP_DATA_CHUNK synthetic_chunk;
    static char synthetic_soap_xml[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<discovery xmlns=\"http://schemas.xmlsoap.org/disco/\" "
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
        "<contractRef ref=\"http://localhost:7047/BC/WS/SystemService\" "
        "xmlns=\"http://schemas.xmlsoap.org/disco/scl/\"/>"
        "</discovery>";

    static char synthetic_api_json[] =
        "{\"@odata.context\":\"http://localhost:7048/BC/api/v2.0/$metadata#companies\","
        "\"value\":[{\"id\":\"00000000-0000-0000-0000-000000000001\","
        "\"systemVersion\":\"1\",\"name\":\"CRONUS USA, Inc.\","
        "\"displayName\":\"CRONUS USA, Inc.\",\"businessProfileId\":\"\"}]}";

    if (response && response->s.StatusCode == 200 && response->s.EntityChunkCount == 0)
    {
        /* Check if this looks like a BC endpoint that should have a body */
        int needs_workaround = 0;
        int is_api_endpoint = 0;

        /* Check Content-Type header for XML (SOAP) */
        if (response->s.Headers.KnownHeaders[HttpHeaderContentType].pRawValue)
        {
            const char *content_type = response->s.Headers.KnownHeaders[HttpHeaderContentType].pRawValue;
            if (strstr(content_type, "xml") || strstr(content_type, "soap"))
            {
                needs_workaround = 1;
                TRACE("BC workaround: Detected XML/SOAP Content-Type\n");
            }
            else if (strstr(content_type, "json") || strstr(content_type, "odata"))
            {
                needs_workaround = 1;
                is_api_endpoint = 1;
                TRACE("BC workaround: Detected JSON/OData Content-Type\n");
            }
        }
        /* For API endpoints without Content-Type, check for OData headers */
        else if (response->s.Headers.UnknownHeaderCount > 0)
        {
            ULONG i;
            for (i = 0; i < response->s.Headers.UnknownHeaderCount; i++)
            {
                if (response->s.Headers.pUnknownHeaders[i].pName &&
                    strstr(response->s.Headers.pUnknownHeaders[i].pName, "OData"))
                {
                    needs_workaround = 1;
                    is_api_endpoint = 1;
                    TRACE("BC workaround: Detected OData header\n");
                    break;
                }
            }
        }

        /* Fallback: If no Content-Type and it's a 200 with no body, likely BC API endpoint */
        if (!needs_workaround && !response->s.Headers.KnownHeaders[HttpHeaderContentType].pRawValue)
        {
            needs_workaround = 1;
            is_api_endpoint = 1;
            TRACE("BC workaround: No Content-Type on 200 response, assuming API endpoint\n");
        }

        /* Apply workaround if this endpoint should have a body */
        if (needs_workaround)
        {
            TRACE("*** BC RESPONSE WORKAROUND ACTIVATED ***\n");

            /* Setup synthetic chunk based on endpoint type */
            synthetic_chunk.DataChunkType = HttpDataChunkFromMemory;

            if (is_api_endpoint)
            {
                TRACE("Injecting synthetic API/OData JSON response\n");
                synthetic_chunk.FromMemory.pBuffer = synthetic_api_json;
                synthetic_chunk.FromMemory.BufferLength = strlen(synthetic_api_json);

                /* Ensure Content-Type is set for API responses */
                if (!response->s.Headers.KnownHeaders[HttpHeaderContentType].pRawValue)
                {
                    ((HTTP_RESPONSE_V1*)response)->Headers.KnownHeaders[HttpHeaderContentType].pRawValue = "application/json; odata.metadata=minimal; charset=utf-8";
                    ((HTTP_RESPONSE_V1*)response)->Headers.KnownHeaders[HttpHeaderContentType].RawValueLength = strlen("application/json; odata.metadata=minimal; charset=utf-8");
                }
            }
            else
            {
                TRACE("Injecting synthetic SOAP XML response\n");
                synthetic_chunk.FromMemory.pBuffer = synthetic_soap_xml;
                synthetic_chunk.FromMemory.BufferLength = strlen(synthetic_soap_xml);
            }

            /* Inject into response - modify the const response temporarily */
            ((HTTP_RESPONSE_V1*)response)->EntityChunkCount = 1;
            ((HTTP_RESPONSE_V1*)response)->pEntityChunks = &synthetic_chunk;

            /* Fix Content-Length header to match injected body */
            static char content_length_value[20];
            snprintf(content_length_value, sizeof(content_length_value), "%lu", synthetic_chunk.FromMemory.BufferLength);
            ((HTTP_RESPONSE_V1*)response)->Headers.KnownHeaders[HttpHeaderContentLength].pRawValue = content_length_value;
            ((HTTP_RESPONSE_V1*)response)->Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength = strlen(content_length_value);

            TRACE("Injected %lu bytes of %s\n", synthetic_chunk.FromMemory.BufferLength,
                  is_api_endpoint ? "JSON" : "XML");
            TRACE("Updated Content-Length to: %s\n", content_length_value);
        }
    }
#endif
    /* === END BC SOAP WORKAROUND (DISABLED) === */

    status_len = snprintf(dummy, sizeof(dummy), "%hu", response->s.StatusCode);
    if (status_len < 0 || status_len >= sizeof(dummy))
        return ERROR_INSUFFICIENT_BUFFER;
    len = 12 + status_len + response->s.ReasonLength;
    TRACE("Initial len: status line = %d bytes\n", len);
    for (i = 0; i < response->s.EntityChunkCount; ++i)
    {
        if (response->s.pEntityChunks[i].DataChunkType != HttpDataChunkFromMemory)
        {
            FIXME("Unhandled data chunk type %u.\n", response->s.pEntityChunks[i].DataChunkType);
            return ERROR_CALL_NOT_IMPLEMENTED;
        }
        body_len += response->s.pEntityChunks[i].FromMemory.BufferLength;
    }
    len += body_len;
    for (i = 0; i < HttpHeaderResponseMaximum; ++i)
    {
        if (i == HttpHeaderContentLength)
        {
            TRACE("Checking Content-Length (i=%d): RawValueLength=%d, MORE_DATA flag=%d\n",
                  i, response->s.Headers.KnownHeaders[i].RawValueLength,
                  !!(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA));
        }
        if (i == HttpHeaderDate)
        {
            len += 37;  /* sizeof("Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n") - 1 */
            TRACE("Counting Date header: 37 bytes (auto-generated)\n");
        }
        else if (i == HttpHeaderServer && !response->s.Headers.KnownHeaders[i].RawValueLength)
        {
            len += sizeof("Server: Microsoft-HTTPAPI/2.0\r\n") - 1;
            TRACE("Counting Server header: 31 bytes (auto-generated)\n");
        }
        else if (response->s.Headers.KnownHeaders[i].RawValueLength && 
                 response->s.Headers.KnownHeaders[i].pRawValue)
        {
            /* Skip counting Date header since we always auto-generate it */
            if (i == HttpHeaderDate)
            {
                TRACE("Skipping provided Date header in count (using auto-generated instead)\n");
                continue;
            }
            
            /* Count provided Content-Length header normally */
            /* We only auto-generate when no Content-Length was provided at all */
            
            header_len = strlen(header_names[i]) + 2 + response->s.Headers.KnownHeaders[i].RawValueLength + 2;
            if (i == HttpHeaderWwwAuthenticate)
            {
                TRACE("Counting WWW-Authenticate header: name='%s' (%d), value_len=%d, total=%d\n",
                      header_names[i], (int)strlen(header_names[i]), 
                      response->s.Headers.KnownHeaders[i].RawValueLength, header_len);
            }
            len += header_len;
        }
        else if (i == HttpHeaderContentLength && !(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
        {
            char dummy[12];
            content_len_size = snprintf(dummy, sizeof(dummy), "%d", body_len);
            if (content_len_size < 0 || content_len_size >= sizeof(dummy))
                return ERROR_INSUFFICIENT_BUFFER;
            header_size = strlen(header_names[i]) + 2 + content_len_size + 2;
            len += header_size;
            TRACE("Counting Content-Length header: %d bytes (value=%d)\n", header_size, body_len);
        }
    }
    for (i = 0; i < response->s.Headers.UnknownHeaderCount; ++i)
    {
        len += response->s.Headers.pUnknownHeaders[i].NameLength + 2;
        len += response->s.Headers.pUnknownHeaders[i].RawValueLength + 2;
    }
    
    /* Add Content-Length: 0 for 401 responses to support NTLM */
    /* Windows always sends Content-Length: 0 for 401 responses */
    if (response->s.StatusCode == 401 && 
        !response->s.Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength &&
        !(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA) && body_len == 0)
    {
        len += sizeof("Content-Length: 0\r\n") - 1;
        TRACE("Adding Content-Length: 0 header for 401 response\n");
    }
    
    len += 2;
    TRACE("Final calculated len = %d bytes (including final \\r\\n)\n", len);

    if (!(buffer = malloc(offsetof(struct http_response, buffer) + len)))
        return ERROR_OUTOFMEMORY;
    buffer->id = id;
    buffer->is_body = FALSE;
    buffer->more_data = !!(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA);
    buffer->response_flags = flags;
    buffer->len = len;
    /* Use safer string operations with bounds checking */
    p = buffer->buffer;
    remaining = len;
    
    written = snprintf(p, remaining, "HTTP/1.1 %u %.*s\r\n", response->s.StatusCode,
            response->s.ReasonLength, response->s.pReason ? response->s.pReason : "");
    if (written < 0 || (size_t)written >= remaining)
    {
        ERR("Buffer overflow prevented in status line\n");
        free(buffer);
        return ERROR_INSUFFICIENT_BUFFER;
    }
    p += written;
    remaining -= written;

    /* Track if we've already added Content-Length for 401 responses */
    
    /* Add Content-Length: 0 for 401 responses FIRST (before other headers) */
    /* Windows always sends Content-Length: 0 as the first header for 401 responses */
    if (response->s.StatusCode == 401 && 
        !response->s.Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength &&
        !(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA) && body_len == 0)
    {
        TRACE("401 response without Content-Length detected, auto-adding Content-Length: 0\n");
        written = snprintf(p, remaining, "Content-Length: 0\r\n");
        if (written < 0 || (size_t)written >= remaining)
        {
            ERR("Buffer overflow prevented in Content-Length header (needed=%d, available=%zu)\n",
                written, remaining);
            free(buffer);
            return ERROR_INSUFFICIENT_BUFFER;
        }
        p += written;
        remaining -= written;
        content_length_added = TRUE;
        TRACE("Successfully added Content-Length: 0 header (%d bytes written)\n", written);
    }
    else if (response->s.StatusCode == 401)
    {
        TRACE("401 response: Content-Length conditions not met (has_header=%d, more_data=%d, body_len=%d)\n",
              response->s.Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength > 0,
              !!(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA),
              body_len);
    }

    for (i = 0; i < HttpHeaderResponseMaximum; ++i)
    {
        const HTTP_KNOWN_HEADER *header = &response->s.Headers.KnownHeaders[i];
        if (i == HttpHeaderDate)
        {
            written = format_date(p, remaining);
            if (written < 0 || (size_t)written >= remaining)
            {
                ERR("Buffer overflow prevented in Date header\n");
                free(buffer);
                return ERROR_INSUFFICIENT_BUFFER;
            }
            p += written;
            remaining -= written;
            TRACE("Writing Date header (%d bytes)\n", written);
        }
        else if (i == HttpHeaderServer && !header->RawValueLength)
        {
            written = snprintf(p, remaining, "Server: Microsoft-HTTPAPI/2.0\r\n");
            if (written < 0 || (size_t)written >= remaining)
            {
                ERR("Buffer overflow prevented in Server header\n");
                free(buffer);
                return ERROR_INSUFFICIENT_BUFFER;
            }
            p += written;
            remaining -= written;
            TRACE("Writing Server header (%d bytes)\n", written);
        }
        else if (header->RawValueLength && header->pRawValue)
        {
            /* Skip writing Date header - we always auto-generate it */
            if (i == HttpHeaderDate)
            {
                TRACE("Skipping provided Date header in writing (using auto-generated)\n");
                continue;
            }
            
            /* For Content-Length, write the provided header value */
            /* We only auto-generate when no Content-Length was provided at all */
            
            /* Validate header has actual value pointer */
            if (!header->pRawValue)
            {
                TRACE("Skipping header %s with NULL pRawValue (length=%d)\n", 
                      header_names[i], header->RawValueLength);
                continue;
            }
            
            if (i == HttpHeaderWwwAuthenticate)
            {
                TRACE("Writing WWW-Authenticate header: '%s: %.*s' (name=%d chars, value=%d chars)\n",
                      header_names[i], header->RawValueLength, header->pRawValue,
                      (int)strlen(header_names[i]), header->RawValueLength);
            }
            written = snprintf(p, remaining, "%s: %.*s\r\n",
                    header_names[i], header->RawValueLength, header->pRawValue);
            if (written < 0 || (size_t)written >= remaining)
            {
                ERR("Buffer overflow prevented in header %s\n", header_names[i]);
                free(buffer);
                return ERROR_INSUFFICIENT_BUFFER;
            }
            p += written;
            remaining -= written;
        }
        else if (i == HttpHeaderContentLength && !(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA) && !content_length_added)
        {
            /* Write auto-generated Content-Length when no explicit one is provided and not already added */
            written = snprintf(p, remaining, "Content-Length: %d\r\n", body_len);
            if (written < 0 || (size_t)written >= remaining)
            {
                ERR("Buffer overflow prevented in Content-Length header\n");
                free(buffer);
                return ERROR_INSUFFICIENT_BUFFER;
            }
            p += written;
            remaining -= written;
            TRACE("Writing Content-Length header (value=%d, %d bytes)\n", body_len, written);
        }
    }
    for (i = 0; i < response->s.Headers.UnknownHeaderCount; ++i)
    {
        const HTTP_UNKNOWN_HEADER *header = &response->s.Headers.pUnknownHeaders[i];
        
        /* Validate unknown header pointers */
        if (!header->pName || !header->pRawValue)
        {
            TRACE("Skipping unknown header with NULL name or value\n");
            continue;
        }
        
        written = snprintf(p, remaining, "%.*s: %.*s\r\n", header->NameLength,
                header->pName, header->RawValueLength, header->pRawValue);
        if (written < 0 || (size_t)written >= remaining)
        {
            ERR("Buffer overflow prevented in unknown header\n");
            free(buffer);
            return ERROR_INSUFFICIENT_BUFFER;
        }
        p += written;
        remaining -= written;
    }
    
    /* Final blank line */
    if (remaining < 2)
    {
        ERR("Buffer overflow prevented in final CRLF\n");
        free(buffer);
        return ERROR_INSUFFICIENT_BUFFER;
    }
    memcpy(p, "\r\n", 2);
    p += 2;
    remaining -= 2;
    for (i = 0; i < response->s.EntityChunkCount; ++i)
    {
        const HTTP_DATA_CHUNK *chunk = &response->s.pEntityChunks[i];
        if (remaining < chunk->FromMemory.BufferLength)
        {
            ERR("Buffer overflow prevented in entity body\n");
            free(buffer);
            return ERROR_INSUFFICIENT_BUFFER;
        }
        memcpy(p, chunk->FromMemory.pBuffer, chunk->FromMemory.BufferLength);
        p += chunk->FromMemory.BufferLength;
        remaining -= chunk->FromMemory.BufferLength;
    }

    /* Verify we've filled exactly the expected amount */
    if (p - buffer->buffer != len)
    {
        ERR("Buffer size mismatch! Expected %d bytes, but wrote %ld bytes\n", len, (long)(p - buffer->buffer));
    }
    
    /* Always trace the last few bytes of the buffer for debugging */
    TRACE("Response buffer length: %d, actual written: %ld\n", len, (long)(p - buffer->buffer));
    TRACE("Last 32 bytes of buffer:\n");
    for (i = (len > 32 ? len - 32 : 0); i < len; i++)
    {
        TRACE("%02x ", (unsigned char)buffer->buffer[i]);
    }
    TRACE(" [END]\n");

    if (!ovl)
        ovl = &dummy_ovl;

    {
        DWORD bytes_transferred = 0;
        if (!DeviceIoControl(queue, IOCTL_HTTP_SEND_RESPONSE, buffer,
                (DWORD)(offsetof(struct http_response, buffer) + len), NULL, 0, &bytes_transferred, ovl))
        {
            ret = GetLastError();
            TRACE("HttpSendHttpResponse: DeviceIoControl failed, GetLastError() = %u\n", ret);
            if (ret == ERROR_IO_PENDING && ovl != &dummy_ovl)
                ovl->InternalHigh = len;
        }
        else
        {
            if (ovl != &dummy_ovl) ovl->InternalHigh = len;
            if (ret_size) *ret_size = len;
            TRACE("HttpSendHttpResponse: DeviceIoControl succeeded, returning ERROR_SUCCESS (0)\n");
        }
    }

    free(buffer);

    /* If we temporarily extended UnknownHeaders (added Sec-WebSocket-Accept), restore and free
       For PoC simplicity: if we detect our header at the end, assume array was ours and reset. */
    {
        USHORT cnt = response->s.Headers.UnknownHeaderCount;
        if (ws_accept_injected && cnt && response->s.Headers.pUnknownHeaders)
        {
            HTTP_UNKNOWN_HEADER *last = &response->s.Headers.pUnknownHeaders[cnt - 1];
            if (last->pName && last->NameLength == 19 && !strncmp(last->pName, "Sec-WebSocket-Accept", 19))
            {
                char *val = (char *)last->pRawValue;
                HTTP_UNKNOWN_HEADER *arr = response->s.Headers.pUnknownHeaders;
                free(val);
                free(arr);
                response->s.Headers.pUnknownHeaders = orig_unknown_headers;
                response->s.Headers.UnknownHeaderCount = orig_unknown_count;
            }
        }
    }
    
    /* Clean up request mapping ONLY if DISCONNECT flag is set */
    /* Don't clean up based on absence of MORE_DATA flag - BC/ASP.NET sends headers first, body later */
    /* Don't clean up for 401 responses as they expect authentication continuation */
    /* Don't clean up for 101 Switching Protocols as WebSocket continues on same connection */
    if (ret == ERROR_SUCCESS &&
        response->s.StatusCode != 401 &&
        response->s.StatusCode != 101 &&
        (flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT))
    {
        remove_request_mapping(id);
        TRACE("Cleaned up mapping for disconnected request %s\n", wine_dbgstr_longlong(id));
    }
    else if (ret == ERROR_SUCCESS && response->s.StatusCode == 401)
    {
        TRACE("Keeping request mapping for 401 authentication challenge (request %s)\n", wine_dbgstr_longlong(id));
    }
    else if (ret == ERROR_SUCCESS && response->s.StatusCode == 101)
    {
        TRACE("Keeping request mapping for 101 WebSocket upgrade (request %s)\n", wine_dbgstr_longlong(id));
    }
    else if (ret == ERROR_SUCCESS)
    {
        TRACE("Keeping request mapping for request %s (may call HttpSendResponseEntityBody later)\n", wine_dbgstr_longlong(id));
    }

    TRACE("HttpSendHttpResponse returning: %u (Status: %u, Flags: 0x%x, EntityChunkCount: %u)\n",
          ret, response->s.StatusCode, flags, response->s.EntityChunkCount);

    return ret;
}

/***********************************************************************
 *        HttpSendResponseEntityBody     (HTTPAPI.@)
 *
 * Sends entity-body data for a response.
 *
 * PARAMS
 *   queue              [I] The request queue handle
 *   id                 [I] The ID of the request to which this response corresponds
 *   flags              [I] Flags to control the response
 *   entity_chunk_count [I] The number of entities pointed to by entity_chunks
 *   entity_chunks      [I] The entities to be sent
 *   ret_size           [O] The number of bytes sent
 *   reserved1          [I] Reserved, must be NULL
 *   reserved2          [I] Reserved, must be zero
 *   ovl                [I] Must be set to an OVERLAP pointer when making async calls
 *   log_data           [I] Optional log data structure for logging the call
 *
 * RETURNS
 *   NO_ERROR on success, or an error code on failure.
 */
ULONG WINAPI HttpSendResponseEntityBody(HANDLE queue, HTTP_REQUEST_ID id,
       ULONG flags, USHORT entity_chunk_count, HTTP_DATA_CHUNK *entity_chunks,
       ULONG *ret_size, void *reserved1, ULONG reserved2, OVERLAPPED *ovl,
       HTTP_LOG_DATA *log_data)
{
    struct http_response *buffer;
    OVERLAPPED dummy_ovl = {};
    ULONG ret = NO_ERROR;
    int len = 0;
    char *p;
    USHORT i;

    if (!queue)
        return ERROR_INVALID_PARAMETER;
        
    if (!id)
        return ERROR_CONNECTION_INVALID;
        
    if (entity_chunk_count && !entity_chunks)
        return ERROR_INVALID_PARAMETER;
        
    if (reserved1)
        WARN("Reserved1 parameter is not NULL (%p)\n", reserved1);
        
    if (reserved2)
        WARN("Reserved2 parameter is not zero (%lu)\n", reserved2);

    TRACE("queue %p, id %s, flags %#lx, entity_chunk_count %u, entity_chunks %p, "
            "ret_size %p, reserved1 %p, reserved2 %#lx, ovl %p, log_data %p\n",
            queue, wine_dbgstr_longlong(id), flags, entity_chunk_count, entity_chunks,
            ret_size, reserved1, reserved2, ovl, log_data);

    /* === ASYNC I/O DIAGNOSTIC === */
    if (ovl)
    {
        TRACE("=== HttpSendResponseEntityBody ASYNC CALL: ovl=%p, InternalHigh=%zu ===\n",
              ovl, (size_t)ovl->InternalHigh);
    }
    else
    {
        TRACE("=== HttpSendResponseEntityBody SYNC CALL: ret_size=%p ===\n", ret_size);
    }

    if (!id)
        return ERROR_CONNECTION_INVALID;

    if (flags & ~(HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
        FIXME("Unhandled flags %#lx.\n", flags & ~(HTTP_SEND_RESPONSE_FLAG_MORE_DATA));
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT)
        TRACE("HTTP_SEND_RESPONSE_FLAG_DISCONNECT is set, connection will be closed after send.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA)
        TRACE("HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA is set.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_ENABLE_NAGLING)
        TRACE("HTTP_SEND_RESPONSE_FLAG_ENABLE_NAGLING is set.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_PROCESS_RANGES)
        TRACE("HTTP_SEND_RESPONSE_FLAG_PROCESS_RANGES is set.\n");
    
    if (flags & HTTP_SEND_RESPONSE_FLAG_OPAQUE)
        TRACE("HTTP_SEND_RESPONSE_FLAG_OPAQUE is set.\n");
    
    if (log_data)
        WARN("Ignoring log_data.\n");

    /* Compute the length of the body. */
    for (i = 0; i < entity_chunk_count; ++i)
    {
        if (entity_chunks[i].DataChunkType != HttpDataChunkFromMemory)
        {
            FIXME("Unhandled data chunk type %u.\n", entity_chunks[i].DataChunkType);
            return ERROR_CALL_NOT_IMPLEMENTED;
        }
        len += entity_chunks[i].FromMemory.BufferLength;
    }

    if (!(buffer = malloc(offsetof(struct http_response, buffer) + len)))
        return ERROR_OUTOFMEMORY;
    buffer->id = id;
    buffer->is_body = TRUE;
    buffer->more_data = !!(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA);
    buffer->response_flags = flags;
    buffer->len = len;

    p = buffer->buffer;
    for (i = 0; i < entity_chunk_count; ++i)
    {
        const HTTP_DATA_CHUNK *chunk = &entity_chunks[i];
        memcpy(p, chunk->FromMemory.pBuffer, chunk->FromMemory.BufferLength);
        p += chunk->FromMemory.BufferLength;
    }

    if (!ovl)
    {
        ovl = &dummy_ovl;
        if (ret_size)
            *ret_size = len;
    }

    DWORD bytes_transferred = 0;
    if (!DeviceIoControl(queue, IOCTL_HTTP_SEND_RESPONSE, buffer,
            (DWORD)(offsetof(struct http_response, buffer) + len), NULL, 0, &bytes_transferred, ovl))
    {
        ret = GetLastError();
        /* For async operations, bytes will be reported through the OVERLAPPED structure */
        if (ret == ERROR_IO_PENDING && ovl != &dummy_ovl)
        {
            /* Async operation - store expected bytes in OVERLAPPED's InternalHigh */
            /* This will be used when GetOverlappedResult is called */
            ovl->InternalHigh = len;
            TRACE("Async entity body send initiated, %u bytes queued for transmission\n", len);

            /* When the async operation completes, the caller should use GetOverlappedResult
               to retrieve the actual bytes transferred */
        }
    }
    else
    {
        /* Synchronous completion */
        if (ret_size)
        {
            /* For entity body sends, we sent 'len' bytes of payload */
            *ret_size = len;
            TRACE("Sync entity body send completed, %u bytes sent\n", len);
        }
        /* Also set bytes in OVERLAPPED for async callers */
        if (ovl != &dummy_ovl)
        {
            ovl->InternalHigh = len;
        }
    }

    free(buffer);

    /* === ASYNC I/O COMPLETION DIAGNOSTIC === */
    if (ovl != &dummy_ovl)
    {
        TRACE("=== HttpSendResponseEntityBody ASYNC RESULT: ret=%lu, InternalHigh=%zu ===\n",
              ret, (size_t)ovl->InternalHigh);
        if (ret == ERROR_IO_PENDING)
        {
            TRACE("=== ASYNC: Operation pending, bytes will be available after GetOverlappedResult ===\n");
        }
    }
    else if (ret_size)
    {
        TRACE("=== HttpSendResponseEntityBody SYNC RESULT: ret=%lu, *ret_size=%lu ===\n",
              ret, ret_size ? *ret_size : 0);
    }

    /* Clean up request mapping if this is the final entity body */
    if (ret == ERROR_SUCCESS &&
        (flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT ||
         !(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA)))
    {
        remove_request_mapping(id);
        remove_ws_meta(id);
        TRACE("Cleaned up mapping for completed request %s (entity body)\n", wine_dbgstr_longlong(id));
    }

    return ret;
}

/* Structure to hold individual URLs within a URL group */
struct url_group_url
{
    struct list entry;
    WCHAR *url;
    HTTP_URL_CONTEXT context;
};

struct url_group
{
    LONG refcount;
    struct list entry, session_entry;
    HANDLE queue;
    struct list urls;  /* List of url_group_url entries */
    /* Authentication settings */
    BOOL auth_enabled;
    ULONG auth_schemes;
    HTTP_SERVER_AUTHENTICATION_INFO auth_info;
};

static struct list url_groups = LIST_INIT(url_groups);

/* Request to URL group mapping structure */
struct request_url_group_mapping
{
    struct list entry;
    HTTP_REQUEST_ID request_id;
    struct url_group *group;
    ULONGLONG timestamp;  /* For cleanup of stale entries */
};

static struct list request_mappings = LIST_INIT(request_mappings);
static CRITICAL_SECTION request_mapping_cs;
static CRITICAL_SECTION_DEBUG request_mapping_cs_debug =
{
    0, 0, &request_mapping_cs,
    { &request_mapping_cs_debug.ProcessLocksList, &request_mapping_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": request_mapping_cs") }
};
static CRITICAL_SECTION request_mapping_cs = { &request_mapping_cs_debug, -1, 0, 0, 0, 0 };

static struct url_group *get_url_group(HTTP_URL_GROUP_ID id)
{
    struct url_group *group;
    
    if (!id) return NULL;
    
    EnterCriticalSection(&g_httpapi_cs);
    LIST_FOR_EACH_ENTRY(group, &url_groups, struct url_group, entry)
    {
        if ((HTTP_URL_GROUP_ID)(ULONG_PTR)group == id)
        {
            url_group_acquire(group);  /* Increment refcount before releasing lock */
            LeaveCriticalSection(&g_httpapi_cs);
            return group;
        }
    }
    LeaveCriticalSection(&g_httpapi_cs);
    return NULL;
}

static void url_group_acquire(struct url_group *group)
{
    if (!group)
        return;
    InterlockedIncrement(&group->refcount);
}

static void url_group_release(struct url_group *group)
{
    if (!group)
        return;
        
    if (!InterlockedDecrement(&group->refcount))
    {
        struct url_group_url *url_entry, *url_next;
        
        EnterCriticalSection(&g_httpapi_cs);
        
        /* Remove from all lists */
        list_remove(&group->entry);
        list_remove(&group->session_entry);
        
        /* Free all URLs */
        LIST_FOR_EACH_ENTRY_SAFE(url_entry, url_next, &group->urls, 
                                struct url_group_url, entry)
        {
            list_remove(&url_entry->entry);
            free(url_entry->url);
            free(url_entry);
        }
        
        LeaveCriticalSection(&g_httpapi_cs);
        
        free(group);
    }
}

/* Find URL group by queue handle */
static struct url_group *find_url_group_by_queue(HANDLE queue)
{
    struct url_group *group;
    
    EnterCriticalSection(&g_httpapi_cs);
    LIST_FOR_EACH_ENTRY(group, &url_groups, struct url_group, entry)
    {
        if (group->queue == queue)
        {
            url_group_acquire(group);
            LeaveCriticalSection(&g_httpapi_cs);
            return group;
        }
    }
    LeaveCriticalSection(&g_httpapi_cs);
    return NULL;
}

/* Add mapping between request ID and URL group */
static void add_request_mapping(HTTP_REQUEST_ID request_id, struct url_group *group)
{
    struct request_url_group_mapping *mapping;
    
    if (!group) return;
    
    mapping = calloc(1, sizeof(*mapping));
    if (!mapping)
    {
        WARN("Failed to allocate request mapping\n");
        return;
    }
    
    mapping->request_id = request_id;
    mapping->group = group;
    mapping->timestamp = GetTickCount64();
    url_group_acquire(group);  /* Take reference */
    
    EnterCriticalSection(&request_mapping_cs);
    list_add_tail(&request_mappings, &mapping->entry);
    LeaveCriticalSection(&request_mapping_cs);
    
    TRACE("Mapped request %s to URL group %p\n", 
          wine_dbgstr_longlong(request_id), group);
}

/* Remove mapping for a request ID */
static void remove_request_mapping(HTTP_REQUEST_ID request_id)
{
    struct request_url_group_mapping *mapping, *next;
    
    EnterCriticalSection(&request_mapping_cs);
    LIST_FOR_EACH_ENTRY_SAFE(mapping, next, &request_mappings, 
                            struct request_url_group_mapping, entry)
    {
        if (mapping->request_id == request_id)
        {
            list_remove(&mapping->entry);
            url_group_release(mapping->group);
            free(mapping);
            TRACE("Removed mapping for request %s\n", 
                  wine_dbgstr_longlong(request_id));
            break;
        }
    }
    LeaveCriticalSection(&request_mapping_cs);
}

/* Clean up stale mappings (older than 5 minutes) */
static void cleanup_stale_mappings(void)
{
    struct request_url_group_mapping *mapping, *next;
    ULONGLONG current_time = GetTickCount64();
    const ULONGLONG STALE_TIMEOUT = 300000; /* 5 minutes */
    
    EnterCriticalSection(&request_mapping_cs);
    LIST_FOR_EACH_ENTRY_SAFE(mapping, next, &request_mappings,
                            struct request_url_group_mapping, entry)
    {
        if (current_time - mapping->timestamp > STALE_TIMEOUT)
        {
            TRACE("Removing stale mapping for request %s\n",
                  wine_dbgstr_longlong(mapping->request_id));
            list_remove(&mapping->entry);
            url_group_release(mapping->group);
            free(mapping);
        }
    }
    LeaveCriticalSection(&request_mapping_cs);
}

struct server_session
{
    struct list entry;
    struct list groups;
    LONG refcount;
    /* Authentication settings */
    BOOL auth_enabled;
    ULONG auth_schemes;
    HTTP_SERVER_AUTHENTICATION_INFO auth_info;
};

static struct list server_sessions = LIST_INIT(server_sessions);

static void server_session_acquire(struct server_session *session)
{
    if (!session)
        return;
    InterlockedIncrement(&session->refcount);
}

static void server_session_release(struct server_session *session)
{
    if (!session)
        return;
        
    if (!InterlockedDecrement(&session->refcount))
    {
        struct url_group *group, *group_next;
        struct list groups_to_release;
        
        list_init(&groups_to_release);
        
        EnterCriticalSection(&g_httpapi_cs);
        
        /* Move all groups to temporary list to avoid nested lock acquisition */
        LIST_FOR_EACH_ENTRY_SAFE(group, group_next, &session->groups, struct url_group, session_entry)
        {
            list_remove(&group->session_entry);
            list_add_tail(&groups_to_release, &group->session_entry);
        }
        
        list_remove(&session->entry);
        LeaveCriticalSection(&g_httpapi_cs);
        
        /* Now release groups without holding the global lock */
        LIST_FOR_EACH_ENTRY_SAFE(group, group_next, &groups_to_release, struct url_group, session_entry)
        {
            url_group_release(group);
        }
        
        free(session);
    }
}

static struct server_session *get_server_session(HTTP_SERVER_SESSION_ID id)
{
    struct server_session *session;
    
    if (!id) return NULL;
    
    EnterCriticalSection(&g_httpapi_cs);
    LIST_FOR_EACH_ENTRY(session, &server_sessions, struct server_session, entry)
    {
        if ((HTTP_SERVER_SESSION_ID)(ULONG_PTR)session == id)
        {
            server_session_acquire(session);  /* Increment refcount before releasing lock */
            LeaveCriticalSection(&g_httpapi_cs);
            return session;
        }
    }
    LeaveCriticalSection(&g_httpapi_cs);
    return NULL;
}

/***********************************************************************
 *        HttpCreateServerSession     (HTTPAPI.@)
 */
ULONG WINAPI HttpCreateServerSession(HTTPAPI_VERSION version, HTTP_SERVER_SESSION_ID *id, ULONG reserved)
{
    struct server_session *session;

    TRACE("version %u.%u, id %p, reserved %lu.\n", version.HttpApiMajorVersion,
            version.HttpApiMinorVersion, id, reserved);

    if (!id)
        return ERROR_INVALID_PARAMETER;

    if ((version.HttpApiMajorVersion != 1 && version.HttpApiMajorVersion != 2)
            || version.HttpApiMinorVersion)
        return ERROR_REVISION_MISMATCH;

    if (!(session = malloc(sizeof(*session))))
        return ERROR_OUTOFMEMORY;

    session->refcount = 1;  /* Initialize refcount */
    
    EnterCriticalSection(&g_httpapi_cs);
    list_add_tail(&server_sessions, &session->entry);
    list_init(&session->groups);
    LeaveCriticalSection(&g_httpapi_cs);

    *id = (ULONG_PTR)session;
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpCloseServerSession     (HTTPAPI.@)
 */
ULONG WINAPI HttpCloseServerSession(HTTP_SERVER_SESSION_ID id)
{
    struct server_session *session = NULL, *iter;

    TRACE("id %s.\n", wine_dbgstr_longlong(id));

    /* Find and remove session from global list atomically */
    EnterCriticalSection(&g_httpapi_cs);
    LIST_FOR_EACH_ENTRY(iter, &server_sessions, struct server_session, entry)
    {
        if ((HTTP_SERVER_SESSION_ID)(ULONG_PTR)iter == id)
        {
            session = iter;
            list_remove(&session->entry); /* Remove from global list to prevent reuse */
            break;
        }
    }
    LeaveCriticalSection(&g_httpapi_cs);

    if (!session)
        return ERROR_INVALID_PARAMETER;

    /* Release the original reference, which will trigger cleanup if it's the last one */
    server_session_release(session);
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpCreateUrlGroup     (HTTPAPI.@)
 */
ULONG WINAPI HttpCreateUrlGroup(HTTP_SERVER_SESSION_ID session_id, HTTP_URL_GROUP_ID *group_id, ULONG reserved)
{
    struct server_session *session;
    struct url_group *group;

    TRACE("session_id %s, group_id %p, reserved %#lx.\n",
          wine_dbgstr_longlong(session_id), group_id, reserved);

    if (!(session = get_server_session(session_id)))
        return ERROR_INVALID_PARAMETER;

    if (!(group = calloc(1, sizeof(*group))))
    {
        server_session_release(session);  /* Release reference from get_server_session() */
        return ERROR_OUTOFMEMORY;
    }
    
    group->refcount = 1;  /* Initialize refcount */
    
    EnterCriticalSection(&g_httpapi_cs);
    list_init(&group->urls);
    list_add_tail(&url_groups, &group->entry);
    list_add_tail(&session->groups, &group->session_entry);
    LeaveCriticalSection(&g_httpapi_cs);

    *group_id = (ULONG_PTR)group;

    server_session_release(session);  /* Release reference from get_server_session() */
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpCloseUrlGroup     (HTTPAPI.@)
 */
ULONG WINAPI HttpCloseUrlGroup(HTTP_URL_GROUP_ID id)
{
    struct url_group *group;
    struct url_group_url *url_entry, *url_next;

    TRACE("id %s.\n", wine_dbgstr_longlong(id));

    if (!(group = get_url_group(id)))
        return ERROR_INVALID_PARAMETER;

    /* Remove all URLs from the queue first */
    if (group->queue)
    {
        EnterCriticalSection(&g_httpapi_cs);
        LIST_FOR_EACH_ENTRY_SAFE(url_entry, url_next, &group->urls, struct url_group_url, entry)
        {
            if (url_entry->url)
            {
                LeaveCriticalSection(&g_httpapi_cs);
                remove_url(group->queue, url_entry->url);
                EnterCriticalSection(&g_httpapi_cs);
            }
        }
        LeaveCriticalSection(&g_httpapi_cs);
    }

    url_group_release(group);  /* Release reference from get_url_group() */
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpSetUrlGroupProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpSetUrlGroupProperty(HTTP_URL_GROUP_ID id, HTTP_SERVER_PROPERTY property, void *value, ULONG length)
{
    struct url_group *group;

    TRACE("id %s, property %u, value %p, length %lu.\n",
            wine_dbgstr_longlong(id), property, value, length);

    if (!value)
        return ERROR_INVALID_PARAMETER;

    if (!(group = get_url_group(id)))
        return ERROR_INVALID_PARAMETER;

    switch (property)
    {
        case HttpServerAuthenticationProperty:
        {
            const HTTP_SERVER_AUTHENTICATION_INFO *auth_info = value;
            
            if (length < sizeof(HTTP_SERVER_AUTHENTICATION_INFO))
            {
                url_group_release(group);
                return ERROR_INSUFFICIENT_BUFFER;
            }
            
            /* Store authentication settings for this URL group */
            group->auth_enabled = auth_info->Flags.Present;
            group->auth_schemes = auth_info->AuthSchemes;
            memcpy(&group->auth_info, auth_info, sizeof(HTTP_SERVER_AUTHENTICATION_INFO));
            
            TRACE("URL group authentication set: enabled=%d, schemes=%#lx\n", group->auth_enabled, group->auth_schemes);
            
            if (group->auth_schemes & HTTP_AUTH_SCHEME_NTLM)
                TRACE("  NTLM authentication enabled\n");
            if (group->auth_schemes & HTTP_AUTH_SCHEME_NEGOTIATE)
                TRACE("  Negotiate authentication enabled\n");
            if (group->auth_schemes & HTTP_AUTH_SCHEME_BASIC)
                TRACE("  Basic authentication enabled\n");
            if (group->auth_schemes & HTTP_AUTH_SCHEME_DIGEST)
                TRACE("  Digest authentication enabled\n");
            
            /* TODO: Store realm, domain, and other auth parameters */
            if (auth_info->ReceiveMutualAuth)
                FIXME("ReceiveMutualAuth not implemented\n");
            
            url_group_release(group);
            return ERROR_SUCCESS;
        }
        case HttpServerBindingProperty:
        {
            const HTTP_BINDING_INFO *info = value;
            WCHAR **url_snapshot = NULL;
            HTTP_URL_CONTEXT *context_snapshot = NULL;
            DWORD url_count = 0, i;
            
            if (length < sizeof(HTTP_BINDING_INFO))
            {
                url_group_release(group);  /* Release reference from get_url_group() */
                return ERROR_INSUFFICIENT_BUFFER;
            }

            TRACE("Binding URL group %s to queue %p.\n", wine_dbgstr_longlong(id), info->RequestQueueHandle);
            
            /* Create a snapshot of URLs under lock to avoid race conditions */
            EnterCriticalSection(&g_httpapi_cs);
            group->queue = info->RequestQueueHandle;
            
            if (!list_empty(&group->urls))
            {
                struct url_group_url *url_entry;
                
                /* Count URLs first */
                LIST_FOR_EACH_ENTRY(url_entry, &group->urls, struct url_group_url, entry)
                {
                    url_count++;
                }
                
                /* Allocate snapshot arrays */
                url_snapshot = calloc(url_count, sizeof(WCHAR*));
                context_snapshot = calloc(url_count, sizeof(HTTP_URL_CONTEXT));
                
                if (!url_snapshot || !context_snapshot)
                {
                    LeaveCriticalSection(&g_httpapi_cs);
                    free(url_snapshot);
                    free(context_snapshot);
                    url_group_release(group);
                    return ERROR_OUTOFMEMORY;
                }
                
                /* Copy URLs and contexts */
                i = 0;
                LIST_FOR_EACH_ENTRY(url_entry, &group->urls, struct url_group_url, entry)
                {
                    url_snapshot[i] = wcsdup(url_entry->url);
                    if (!url_snapshot[i])
                    {
                        /* Clean up on allocation failure */
                        DWORD j;
                        LeaveCriticalSection(&g_httpapi_cs);
                        for (j = 0; j < i; j++)
                            free(url_snapshot[j]);
                        free(url_snapshot);
                        free(context_snapshot);
                        url_group_release(group);
                        return ERROR_OUTOFMEMORY;
                    }
                    context_snapshot[i] = url_entry->context;
                    i++;
                }
            }
            LeaveCriticalSection(&g_httpapi_cs);
            
            /* Now add URLs without holding the lock */
            for (i = 0; i < url_count; i++)
            {
                ULONG ret = add_url(group->queue, url_snapshot[i], context_snapshot[i]);
                if (ret)
                {
                    WARN("Failed to add URL %s to queue: %lu\n", debugstr_w(url_snapshot[i]), ret);
                    /* Don't fail the binding, continue with other URLs */
                }
                else if (wcsstr(url_snapshot[i], L"BusinessCentral") || wcsstr(url_snapshot[i], L":7049"))
                {
                    TRACE("*** BUSINESS CENTRAL SERVER READY: URL %s successfully bound via group to queue %p ***\n", 
                          debugstr_w(url_snapshot[i]), group->queue);
                    TRACE("*** BC Server is now ready to accept HTTP requests ***\n");
                }
                free(url_snapshot[i]);
            }
            
            free(url_snapshot);
            free(context_snapshot);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_SUCCESS;
        }
        case HttpServerLoggingProperty:
            WARN("Ignoring logging property.\n");
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_SUCCESS;
        case HttpServerQosProperty:
        {
            const HTTP_QOS_SETTING_INFO *qos_info = value;
            
            if (length < sizeof(HTTP_QOS_SETTING_INFO))
            {
                url_group_release(group);  /* Release reference from get_url_group() */
                return ERROR_INSUFFICIENT_BUFFER;
            }
                
            TRACE("QoS property set, QosType %u.\n", qos_info->QosType);
            /* QoS settings are not implemented in Wine's HTTP.sys driver yet.
             * Return success to allow applications to continue. */
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_SUCCESS;
        }
        case HttpServerTimeoutsProperty:
        {
            /* The timeout property structure contains various timeout values like:
             * EntityBodyTimeout, DrainEntityBodyTimeout, RequestQueueTimeout,
             * IdleConnectionTimeout, HeaderWaitTimeout, MinSendRate.
             * For now, we just accept the settings and return success. */
            TRACE("Timeouts property set, length %lu.\n", length);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_SUCCESS;
        }
        default:
            FIXME("Unhandled property %u.\n", property);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/***********************************************************************
 *        HttpAddUrlToUrlGroup     (HTTPAPI.@)
 */
ULONG WINAPI HttpAddUrlToUrlGroup(HTTP_URL_GROUP_ID id, const WCHAR *url,
        HTTP_URL_CONTEXT context, ULONG reserved)
{
    struct url_group *group;
    struct url_group_url *url_entry;
    ULONG ret;

    TRACE("id %s, url %s, context %s, reserved %#lx.\n", wine_dbgstr_longlong(id),
            debugstr_w(url), wine_dbgstr_longlong(context), reserved);

    if (wcsstr(url, L"BusinessCentral") || wcsstr(url, L":7049"))
    {
        TRACE("*** BUSINESS CENTRAL SERVER BINDING: Adding URL %s to group %s ***\n", 
              debugstr_w(url), wine_dbgstr_longlong(id));
    }

    if (!url)
        return ERROR_INVALID_PARAMETER;

    if (!(group = get_url_group(id)))
        return ERROR_INVALID_PARAMETER;

    if (reserved)
        WARN("Reserved parameter is not zero (%lu)\n", reserved);

    /* Check if URL already exists in this group */
    EnterCriticalSection(&g_httpapi_cs);
    LIST_FOR_EACH_ENTRY(url_entry, &group->urls, struct url_group_url, entry)
    {
        if (!wcscmp(url_entry->url, url))
        {
            LeaveCriticalSection(&g_httpapi_cs);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_ALREADY_EXISTS;
        }
    }

    /* Add new URL to the group */
    if (!(url_entry = calloc(1, sizeof(*url_entry))))
    {
        LeaveCriticalSection(&g_httpapi_cs);
        url_group_release(group);  /* Release reference from get_url_group() */
        return ERROR_OUTOFMEMORY;
    }

    if (!(url_entry->url = wcsdup(url)))
    {
        free(url_entry);
        LeaveCriticalSection(&g_httpapi_cs);
        url_group_release(group);  /* Release reference from get_url_group() */
        return ERROR_OUTOFMEMORY;
    }
    url_entry->context = context;
    list_add_tail(&group->urls, &url_entry->entry);
    LeaveCriticalSection(&g_httpapi_cs);

    /* If the group is already bound to a queue, add the URL immediately */
    if (group->queue)
    {
        TRACE("Group already bound to queue %p, adding URL immediately\n", group->queue);
        ret = add_url(group->queue, url, context);
        if (ret)
        {
            WARN("Failed to add URL %s to queue: %lu\n", debugstr_w(url), ret);
            list_remove(&url_entry->entry);
            free(url_entry->url);
            free(url_entry);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ret;
        }
        if (wcsstr(url, L"BusinessCentral") || wcsstr(url, L":7049"))
        {
            TRACE("*** BUSINESS CENTRAL SERVER READY: URL %s successfully bound to queue %p ***\n", 
                  debugstr_w(url), group->queue);
            TRACE("*** BC Server can now accept HTTP requests on this endpoint ***\n");
        }
    }
    
    TRACE("URL %s added to group %s\n", debugstr_w(url), wine_dbgstr_longlong(id));
    url_group_release(group);  /* Release reference from get_url_group() */
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpRemoveUrlFromUrlGroup     (HTTPAPI.@)
 */
ULONG WINAPI HttpRemoveUrlFromUrlGroup(HTTP_URL_GROUP_ID id, const WCHAR *url, ULONG flags)
{
    struct url_group *group;
    struct url_group_url *url_entry;

    TRACE("id %s, url %s, flags %#lx.\n", wine_dbgstr_longlong(id), debugstr_w(url), flags);

    if (!url)
        return ERROR_INVALID_PARAMETER;

    if (!(group = get_url_group(id)))
        return ERROR_INVALID_PARAMETER;

    if (flags)
        FIXME("Ignoring flags %#lx.\n", flags);

    /* Find and remove the URL from the group */
    EnterCriticalSection(&g_httpapi_cs);
    LIST_FOR_EACH_ENTRY(url_entry, &group->urls, struct url_group_url, entry)
    {
        if (!wcscmp(url_entry->url, url))
        {
            /* Remove from queue if bound */
            if (group->queue)
            {
                ULONG ret;
                LeaveCriticalSection(&g_httpapi_cs);
                ret = remove_url(group->queue, url);
                if (ret && ret != ERROR_FILE_NOT_FOUND)
                {
                    url_group_release(group);  /* Release reference from get_url_group() */
                    return ret;
                }
                EnterCriticalSection(&g_httpapi_cs);
            }
            
            /* Remove from group's URL list */
            list_remove(&url_entry->entry);
            LeaveCriticalSection(&g_httpapi_cs);
            
            free(url_entry->url);
            free(url_entry);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_httpapi_cs);

    url_group_release(group);  /* Release reference from get_url_group() */
    return ERROR_FILE_NOT_FOUND;
}

/***********************************************************************
 *        get_url_group_for_request
 *
 * Find the URL group associated with a request ID
 */
static struct url_group *get_url_group_for_request(HTTP_REQUEST_ID id)
{
    struct request_url_group_mapping *mapping;
    struct url_group *group = NULL;
    
    /* First try to find the mapping */
    EnterCriticalSection(&request_mapping_cs);
    LIST_FOR_EACH_ENTRY(mapping, &request_mappings, struct request_url_group_mapping, entry)
    {
        if (mapping->request_id == id)
        {
            group = mapping->group;
            url_group_acquire(group);  /* Take reference for caller */
            LeaveCriticalSection(&request_mapping_cs);
            TRACE("Found mapped URL group %p for request %s\n", group, wine_dbgstr_longlong(id));
            return group;
        }
    }
    LeaveCriticalSection(&request_mapping_cs);
    
    /* No mapping found - return NULL and let late binding handle it */
    TRACE("WARNING: No URL group mapping found for request %s\n", wine_dbgstr_longlong(id));
    return NULL;
}

/***********************************************************************
 *        inject_auth_header_if_needed
 *
 * Auto-inject WWW-Authenticate header for 401 responses when auth is configured
 */
static void inject_auth_header_if_needed(HTTP_RESPONSE *response, HTTP_REQUEST_ID id)
{
    struct url_group *group;
    
    TRACE("inject_auth_header_if_needed called for request %s, status %d\n", 
          wine_dbgstr_longlong(id), response->s.StatusCode);
    
    /* Only inject for 401 responses without existing WWW-Authenticate */
    if (response->s.StatusCode != 401)
    {
        TRACE("Not a 401 response (status=%d), skipping auth header injection\n", response->s.StatusCode);
        return;
    }
        
    if (response->s.Headers.KnownHeaders[HttpHeaderWwwAuthenticate].pRawValue)
    {
        TRACE("401 response already has WWW-Authenticate: %s\n", 
              response->s.Headers.KnownHeaders[HttpHeaderWwwAuthenticate].pRawValue);
        return;
    }
    
    /* Get URL group to check auth settings */
    group = get_url_group_for_request(id);
    if (!group)
    {
        TRACE("No URL group found for request %s, cannot inject auth header\n", wine_dbgstr_longlong(id));
        return;
    }
    
    if (!group->auth_enabled)
    {
        TRACE("URL group for request %s has auth_enabled=%d, forcing NTLM for BC compatibility\n", 
              wine_dbgstr_longlong(id), group->auth_enabled);
        /* HACK: Force NTLM authentication for Business Central compatibility 
         * BC Server expects Wine to add WWW-Authenticate header but doesn't configure auth */
        EnterCriticalSection(&g_httpapi_cs);
        group->auth_enabled = TRUE;
        group->auth_schemes = HTTP_AUTH_SCHEME_NTLM;
        LeaveCriticalSection(&g_httpapi_cs);
    }
    else if (!(group->auth_schemes & HTTP_AUTH_SCHEME_NTLM))
    {
        TRACE("URL group has auth but not NTLM (schemes=0x%lx), adding NTLM for BC compatibility\n", 
              group->auth_schemes);
        /* Add NTLM to existing auth schemes for BC compatibility */
        EnterCriticalSection(&g_httpapi_cs);
        group->auth_schemes |= HTTP_AUTH_SCHEME_NTLM;
        LeaveCriticalSection(&g_httpapi_cs);
    }
    
    /* Inject appropriate authentication header */
    TRACE("URL group auth_schemes = 0x%lx, HTTP_AUTH_SCHEME_NTLM = 0x%x\n", 
          group->auth_schemes, HTTP_AUTH_SCHEME_NTLM);
    
    if (group->auth_schemes & HTTP_AUTH_SCHEME_NTLM)
    {
        TRACE("Auto-injecting WWW-Authenticate: NTLM for 401 response\n");
        response->s.Headers.KnownHeaders[HttpHeaderWwwAuthenticate].pRawValue = "NTLM";
        response->s.Headers.KnownHeaders[HttpHeaderWwwAuthenticate].RawValueLength = 4;
    }
    else
    {
        TRACE("NTLM not in auth_schemes, not injecting header\n");
    }
    /* Add other schemes as needed */
    
    url_group_release(group);
}

/***********************************************************************
 *        HttpQueryUrlGroupProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpQueryUrlGroupProperty(HTTP_URL_GROUP_ID id, HTTP_SERVER_PROPERTY property,
        void *buffer, ULONG length, ULONG *ret_length)
{
    struct url_group *group;

    TRACE("id %s, property %u, buffer %p, length %lu, ret_length %p.\n",
            wine_dbgstr_longlong(id), property, buffer, length, ret_length);

    if (!(group = get_url_group(id)))
        return ERROR_INVALID_PARAMETER;

    switch (property)
    {
        case HttpServerBindingProperty:
        {
            HTTP_BINDING_INFO info = {.RequestQueueHandle = group->queue};
            ULONG size = sizeof(info);

            if (ret_length)
                *ret_length = size;

            if (length < size)
            {
                url_group_release(group);  /* Release reference from get_url_group() */
                return ERROR_INSUFFICIENT_BUFFER;
            }

            memcpy(buffer, &info, size);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_SUCCESS;
        }
        
        default:
            FIXME("Unhandled property %u.\n", property);
            url_group_release(group);  /* Release reference from get_url_group() */
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/***********************************************************************
 *        HttpCreateRequestQueue     (HTTPAPI.@)
 */
ULONG WINAPI HttpCreateRequestQueue(HTTPAPI_VERSION version, const WCHAR *name,
        SECURITY_ATTRIBUTES *sa, ULONG flags, HANDLE *handle)
{
    OBJECT_ATTRIBUTES attr = {sizeof(attr)};
    UNICODE_STRING string = RTL_CONSTANT_STRING(L"\\Device\\Http\\ReqQueue");
    IO_STATUS_BLOCK iosb;

    TRACE("version %u.%u, name %s, sa %p, flags %#lx, handle %p.\n",
            version.HttpApiMajorVersion, version.HttpApiMinorVersion,
            debugstr_w(name), sa, flags, handle);
            
    if (!handle)
        return ERROR_INVALID_PARAMETER;
        
    if ((version.HttpApiMajorVersion != 1 && version.HttpApiMajorVersion != 2)
            || version.HttpApiMinorVersion)
        return ERROR_REVISION_MISMATCH;

    if (name)
        FIXME("Unhandled name %s.\n", debugstr_w(name));
    if (flags)
        FIXME("Unhandled flags %#lx.\n", flags);

    attr.ObjectName = &string;
    if (sa && sa->bInheritHandle)
        attr.Attributes |= OBJ_INHERIT;
    attr.SecurityDescriptor = sa ? sa->lpSecurityDescriptor : NULL;
    
    return RtlNtStatusToDosError(NtCreateFile(handle, SYNCHRONIZE, &attr, &iosb, NULL,
            FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0));
}

/***********************************************************************
 *        HttpCloseRequestQueue     (HTTPAPI.@)
 */
ULONG WINAPI HttpCloseRequestQueue(HANDLE handle)
{
    TRACE("handle %p.\n", handle);
    
    if (!handle)
        return ERROR_INVALID_PARAMETER;
        
    if (!CloseHandle(handle))
        return GetLastError();
        
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpShutdownRequestQueue     (HTTPAPI.@)
 */
ULONG WINAPI HttpShutdownRequestQueue(HANDLE queue)
{
    ULONG ret = ERROR_SUCCESS;
    OVERLAPPED ovl = {};

    TRACE("queue %p.\n", queue);

    if (!queue)
        return ERROR_INVALID_PARAMETER;

    ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ovl.hEvent)
        return GetLastError();

    if (!DeviceIoControl(queue, IOCTL_HTTP_SHUTDOWN_QUEUE, NULL, 0, NULL, 0, NULL, &ovl))
    {
        ret = GetLastError();
        if (ret == ERROR_IO_PENDING)
        {
            /* Wait for the operation to complete */
            if (WaitForSingleObject(ovl.hEvent, INFINITE) == WAIT_FAILED)
                ret = GetLastError();
            else
                ret = ERROR_SUCCESS;
        }
    }

    CloseHandle(ovl.hEvent);
    return ret;
}

/***********************************************************************
 *        HttpSetRequestQueueProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpSetRequestQueueProperty(HANDLE queue, HTTP_SERVER_PROPERTY property,
        void *value, ULONG length, ULONG reserved1, void *reserved2)
{
    FIXME("queue %p, property %u, value %p, length %lu, reserved1 %#lx, reserved2 %p, stub!\n",
            queue, property, value, length, reserved1, reserved2);
            
    if (!queue)
        return ERROR_INVALID_PARAMETER;
        
    if (!value && length)
        return ERROR_INVALID_PARAMETER;
        
    if (reserved1)
        WARN("Reserved1 parameter is not zero (%lu)\n", reserved1);
        
    if (reserved2)
        WARN("Reserved2 parameter is not NULL (%p)\n", reserved2);
        
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/***********************************************************************
 *        HttpQueryRequestQueueProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpQueryRequestQueueProperty(HANDLE queue, HTTP_SERVER_PROPERTY property,
        void *buffer, ULONG length, ULONG reserved1, ULONG *ret_length, void *reserved2)
{
    TRACE("queue %p, property %u, buffer %p, length %lu, reserved1 %#lx, ret_length %p, reserved2 %p.\n",
            queue, property, buffer, length, reserved1, ret_length, reserved2);

    if (!queue)
        return ERROR_INVALID_PARAMETER;
        
    if (!buffer && length)
        return ERROR_INVALID_PARAMETER;
        
    if (!ret_length)
        return ERROR_INVALID_PARAMETER;
        
    if (reserved1)
        WARN("Reserved1 parameter is not zero (%lu)\n", reserved1);
        
    if (reserved2)
        WARN("Reserved2 parameter is not NULL (%p)\n", reserved2);

    switch (property)
    {
        default:
            FIXME("Unhandled property %u.\n", property);
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/***********************************************************************
 *        HttpSetServerSessionProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpSetServerSessionProperty(HTTP_SERVER_SESSION_ID id,
        HTTP_SERVER_PROPERTY property, void *value, ULONG length)
{
    struct server_session *session;
    
    TRACE("id %s, property %u, value %p, length %lu.\n",
            wine_dbgstr_longlong(id), property, value, length);
    
    if (!value && length)
        return ERROR_INVALID_PARAMETER;
        
    if (!(session = get_server_session(id)))
        return ERROR_INVALID_PARAMETER;

    switch (property)
    {
        case HttpServerAuthenticationProperty:
        {
            const HTTP_SERVER_AUTHENTICATION_INFO *auth_info = value;
            
            if (length < sizeof(HTTP_SERVER_AUTHENTICATION_INFO))
            {
                server_session_release(session);
                return ERROR_INSUFFICIENT_BUFFER;
            }
            
            /* Store authentication settings for this session */
            session->auth_enabled = auth_info->Flags.Present;
            session->auth_schemes = auth_info->AuthSchemes;
            memcpy(&session->auth_info, auth_info, sizeof(HTTP_SERVER_AUTHENTICATION_INFO));
            
            TRACE("Server session authentication set: enabled=%d, schemes=%#lx\n", session->auth_enabled, session->auth_schemes);
            
            if (session->auth_schemes & HTTP_AUTH_SCHEME_NTLM)
                TRACE("  NTLM authentication enabled for session\n");
            if (session->auth_schemes & HTTP_AUTH_SCHEME_NEGOTIATE)
                TRACE("  Negotiate authentication enabled for session\n");
            if (session->auth_schemes & HTTP_AUTH_SCHEME_BASIC)
                TRACE("  Basic authentication enabled for session\n");
            if (session->auth_schemes & HTTP_AUTH_SCHEME_DIGEST)
                TRACE("  Digest authentication enabled for session\n");
            
            server_session_release(session);
            return ERROR_SUCCESS;
        }
        
        case HttpServerQosProperty:
        {
            const HTTP_QOS_SETTING_INFO *info = value;
            if (length < sizeof(HTTP_QOS_SETTING_INFO))
                return ERROR_INSUFFICIENT_BUFFER;
                
            FIXME("Ignoring QoS setting %u.\n", info->QosType);
            return ERROR_SUCCESS;
        }
        default:
            FIXME("Unhandled property %u.\n", property);
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/***********************************************************************
 *        HttpQueryServerSessionProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpQueryServerSessionProperty(HTTP_SERVER_SESSION_ID id,
        HTTP_SERVER_PROPERTY property, void *buffer, ULONG length, ULONG *ret_length)
{
    struct server_session *session;

    TRACE("id %s, property %u, buffer %p, length %lu, ret_length %p.\n",
            wine_dbgstr_longlong(id), property, buffer, length, ret_length);

    if (!buffer && length)
        return ERROR_INVALID_PARAMETER;
    
    if (!ret_length)
        return ERROR_INVALID_PARAMETER;

    if (!(session = get_server_session(id)))
        return ERROR_INVALID_PARAMETER;

    switch (property)
    {
        case HttpServerQosProperty:
            FIXME("Unimplemented QoS property query.\n");
            return ERROR_CALL_NOT_IMPLEMENTED;
            
        default:
            FIXME("Unhandled property %u.\n", property);
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/***********************************************************************
 *        HttpCancelHttpRequest     (HTTPAPI.@)
 */
ULONG WINAPI HttpCancelHttpRequest(HANDLE queue, HTTP_REQUEST_ID id, OVERLAPPED *lpOverlapped)
{
    struct http_cancel_request_params params = {
        .id = id,
    };
    OVERLAPPED local_ovl;
    ULONG ret = ERROR_SUCCESS;
    DWORD bytes_returned;
    OVERLAPPED *current_ovl = lpOverlapped;

    TRACE("queue %p, id %s, lpOverlapped %p.\n", queue, wine_dbgstr_longlong(id), lpOverlapped);

    if (!queue)
        return ERROR_INVALID_PARAMETER;

    if (!id)
        return ERROR_INVALID_PARAMETER;

    if (!current_ovl) /* Synchronous cancel operation */
    {
        memset(&local_ovl, 0, sizeof(local_ovl));
        local_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!local_ovl.hEvent)
            return GetLastError();
        current_ovl = &local_ovl;
    }

    /* The IOCTL_HTTP_CANCEL_REQUEST takes cancel request params as input */
    if (!DeviceIoControl(queue, IOCTL_HTTP_CANCEL_REQUEST, &params, (DWORD)sizeof(params),
                         NULL, 0, &bytes_returned, current_ovl))
    {
        ret = GetLastError();
    }

    if (!lpOverlapped && ret == ERROR_IO_PENDING)
    {
        if (GetOverlappedResult(queue, current_ovl, &bytes_returned, TRUE))
            ret = ERROR_SUCCESS;
        else
            ret = GetLastError();
    }

    if (!lpOverlapped && local_ovl.hEvent)
        CloseHandle(local_ovl.hEvent);
    
    return (ret == ERROR_SUCCESS) ? NO_ERROR : ret;
}

/***********************************************************************
 *        HttpControlService     (HTTPAPI.@)
 */
ULONG WINAPI HttpControlService(HTTP_SERVICE_CONFIG_ID config_id, ULONG control_code, void *context)
{
    SC_HANDLE manager, service;
    SERVICE_STATUS status;
    DWORD err; /* For GetLastError() */
    DWORD query_err; /* For GetLastError() from QueryServiceStatus */

    TRACE("config_id %d, control_code %#lx, context %p.\n", config_id, control_code, context);

    /* MSDN implies context is only for HttpServiceConfigSSLCertInfo and HttpServiceConfigUrlAclInfo,
     * and is a pointer to the respective structure. For stopping the service, it's not used.
     * We'll ignore context for now, but real implementation might need to validate it based on config_id.
     */

    if (config_id >= HttpServiceConfigMax) /* HttpServiceConfigMax is the upper bound for valid enum values */
        return ERROR_INVALID_PARAMETER;

    switch (control_code)
    {
        case SERVICE_CONTROL_STOP:
        {
            /* Typically, HttpServiceConfigHttpSys would be the relevant config_id for controlling the http service itself.
             * However, the API allows any valid config_id. We'll proceed assuming stopping is generic.
             */
            TRACE("Attempting to stop HTTP service.\n");

            if (!(manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)))
            {
                err = GetLastError();
                ERR("Failed to open SCM, error %lu.\n", err);
                return err;
            }

            if (!(service = OpenServiceW(manager, L"http", SERVICE_STOP | SERVICE_QUERY_STATUS)))
            {
                err = GetLastError();
                ERR("Failed to open HTTP service, error %lu.\n", err);
                CloseServiceHandle(manager);
                return err;
            }

            if (QueryServiceStatus(service, &status))
            {
                if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_PAUSED)
                {
                    if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
                    {
                        err = GetLastError();
                        if (err != ERROR_SERVICE_NOT_ACTIVE) /* Acceptable if already stopped */
                        {
                            ERR("Failed to stop HTTP service, error %lu.\n", err);
                            CloseServiceHandle(service);
                            CloseServiceHandle(manager);
                            return err;
                        }
                         TRACE("HTTP service was not active or already stopped (err %lu).\n", err);
                    }
                    else
                    {
                        TRACE("HTTP service stop request sent.\n");
                    }
                }
                else
                {
                    TRACE("HTTP service not running or paused (state %lu), no stop needed.\n", status.dwCurrentState);
                }
            }
            else
            {
                query_err = GetLastError();
                ERR("Failed to query HTTP service status, error %lu.\n", query_err);
                /* Continue to close handles, but return error */
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
                return query_err;
            }

            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return NO_ERROR;
        }
        case SERVICE_CONTROL_PAUSE:
        case SERVICE_CONTROL_CONTINUE:
            FIXME("Service control %lu is not implemented for http.sys.\n", control_code);
            return ERROR_CALL_NOT_IMPLEMENTED;
        default:
            FIXME("Unknown control code %lu.\n", control_code);
            return ERROR_INVALID_PARAMETER;
    }
}

/***********************************************************************
 *        HttpAddFragmentToCache     (HTTPAPI.@)
 */
ULONG WINAPI HttpAddFragmentToCache(HANDLE cache, const WCHAR *fragment_name, const HTTP_DATA_CHUNK *fragments,
        ULONG fragment_count, HTTP_CACHE_POLICY *cache_policy, OVERLAPPED *overlapped)
{
    TRACE("cache %p, fragment_name %s, fragments %p, fragment_count %lu, cache_policy %p, overlapped %p.\n",
            cache, debugstr_w(fragment_name), fragments, fragment_count, cache_policy, overlapped);

    if (!cache)
        return ERROR_INVALID_PARAMETER;

    if (!fragment_name)
        return ERROR_INVALID_PARAMETER;

    if (!fragments && fragment_count)
        return ERROR_INVALID_PARAMETER;

    FIXME("Not implemented - response cache not supported.\n");
    return ERROR_FILE_NOT_FOUND;
}

/***********************************************************************
 *        HttpFlushResponseCache     (HTTPAPI.@)
 */
ULONG WINAPI HttpFlushResponseCache(HANDLE queue, const WCHAR *url, ULONG flags, OVERLAPPED *overlapped)
{
    TRACE("queue %p, url %s, flags %#lx, overlapped %p.\n", queue, debugstr_w(url), flags, overlapped);

    if (!queue)
        return ERROR_INVALID_PARAMETER;

    if (!url)
        return ERROR_INVALID_PARAMETER;

    if (flags)
        FIXME("Unhandled flags %#lx.\n", flags);

    FIXME("Not implemented - response cache not supported.\n");
    return NO_ERROR;
}

/***********************************************************************
 *        HttpGetCounters     (HTTPAPI.@)
 */
ULONG WINAPI HttpGetCounters(HANDLE queue, HTTP_PERFORMANCE_COUNTER_ID counter_id, 
                            void *buffer, ULONG buffer_length, ULONG reserved)
{
    TRACE("queue %p, counter_id %d, buffer %p, buffer_length %lu, reserved %lu.\n", 
          queue, counter_id, buffer, buffer_length, reserved);

    if (!queue)
        return ERROR_INVALID_PARAMETER;

    if (!buffer)
        return ERROR_INVALID_PARAMETER;

    if (reserved)
        WARN("Reserved parameter is not zero (%lu)\n", reserved);

    switch (counter_id)
    {
        case HttpPerfCounterAllRequests:
        case HttpPerfCounterUriRequests:
        case HttpPerfCounterAllConnections:
        case HttpPerfCounterActiveConnections:
            FIXME("Unsupported counter %d.\n", counter_id);
            return ERROR_FILE_NOT_FOUND;
        default:
            FIXME("Unknown counter %d.\n", counter_id);
            return ERROR_INVALID_PARAMETER;
    }
}

/***********************************************************************
 *        HttpReadFragmentFromCache     (HTTPAPI.@)
 */
ULONG WINAPI HttpReadFragmentFromCache(HANDLE cache, const WCHAR *url, HTTP_BYTE_RANGE *byte_range,
                                      void *buffer, ULONG *buffer_length, OVERLAPPED *overlapped)
{
    TRACE("cache %p, url %s, byte_range %p, buffer %p, buffer_length %p, overlapped %p.\n",
          cache, debugstr_w(url), byte_range, buffer, buffer_length, overlapped);

    if (!cache)
        return ERROR_INVALID_PARAMETER;

    if (!url)
        return ERROR_INVALID_PARAMETER;

    if (!buffer)
        return ERROR_INVALID_PARAMETER;

    if (!buffer_length)
        return ERROR_INVALID_PARAMETER;

    FIXME("Not implemented - response cache not supported.\n");
    return ERROR_FILE_NOT_FOUND;
}

/***********************************************************************
 *        HttpWaitForDisconnect     (HTTPAPI.@)
 */
ULONG WINAPI HttpWaitForDisconnect(HANDLE queue, HTTP_CONNECTION_ID connection_id, OVERLAPPED *overlapped)
{
    struct http_wait_for_disconnect_params params = {
        .id = connection_id,
    };
    ULONG ret = ERROR_SUCCESS;
    OVERLAPPED local_ovl;
    OVERLAPPED *povl = overlapped;
    DWORD bytes_returned;

    TRACE("queue %p, connection_id %s, overlapped %p.\n",
          queue, wine_dbgstr_longlong(connection_id), overlapped);

    if (!queue)
        return ERROR_INVALID_PARAMETER;

    if (!connection_id)
        return ERROR_INVALID_PARAMETER;

    if (!povl)
    {
        memset(&local_ovl, 0, sizeof(local_ovl));
        local_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!local_ovl.hEvent)
            return GetLastError();
        povl = &local_ovl;
    }

    if (!DeviceIoControl(queue, IOCTL_HTTP_WAIT_FOR_DISCONNECT, &params, (DWORD)sizeof(params),
                         NULL, 0, &bytes_returned, povl))
    {
        ret = GetLastError();
    }

    if (!overlapped && ret == ERROR_IO_PENDING)
    {
        if (GetOverlappedResult(queue, povl, &bytes_returned, TRUE))
            ret = ERROR_SUCCESS;
        else
            ret = GetLastError();
    }

    if (!overlapped && local_ovl.hEvent)
        CloseHandle(local_ovl.hEvent);

    /* Don't mask connection errors - let the caller handle them */

    return (ret == ERROR_SUCCESS) ? NO_ERROR : ret;
}

/***********************************************************************
 *        HttpWaitForDisconnectEx     (HTTPAPI.@)
 */
ULONG WINAPI HttpWaitForDisconnectEx(HANDLE queue, HTTP_CONNECTION_ID connection_id,
                                     ULONG reserved, OVERLAPPED *overlapped)
{
    struct http_wait_for_disconnect_params params = {
        .id = connection_id,
    };
    ULONG ret = ERROR_SUCCESS;
    OVERLAPPED local_ovl;
    OVERLAPPED *povl = overlapped;
    DWORD bytes_returned;

    TRACE("queue %p, connection_id %s, reserved %lu, overlapped %p.\n",
          queue, wine_dbgstr_longlong(connection_id), reserved, overlapped);

    if (!queue)
        return ERROR_INVALID_PARAMETER;

    if (!connection_id)
        return ERROR_INVALID_PARAMETER;

    if (reserved)
        WARN("Reserved parameter is not zero (%lu)\n", reserved);

    if (!povl)
    {
        memset(&local_ovl, 0, sizeof(local_ovl));
        local_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!local_ovl.hEvent)
            return GetLastError();
        povl = &local_ovl;
    }

    if (!DeviceIoControl(queue, IOCTL_HTTP_WAIT_FOR_DISCONNECT, &params, (DWORD)sizeof(params),
                         NULL, 0, &bytes_returned, povl))
    {
        ret = GetLastError();
    }

    if (!overlapped && ret == ERROR_IO_PENDING)
    {
        if (GetOverlappedResult(queue, povl, &bytes_returned, TRUE))
            ret = ERROR_SUCCESS;
        else
            ret = GetLastError();
    }

    if (!overlapped && local_ovl.hEvent)
        CloseHandle(local_ovl.hEvent);
    
    /* Don't mask connection errors - let the caller handle them */

    return (ret == ERROR_SUCCESS) ? NO_ERROR : ret;
}

/***********************************************************************
 *        DllMain     (HTTPAPI.@)
 */
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(instance);
        break;
    case DLL_PROCESS_DETACH:
        if (!reserved)  /* Process termination, not FreeLibrary */
        {
            struct server_session *session, *session_next;
            struct url_group *group, *group_next;
            
            EnterCriticalSection(&g_httpapi_cs);
            
            /* Clean up all server sessions and their groups */
            LIST_FOR_EACH_ENTRY_SAFE(session, session_next, &server_sessions, 
                                    struct server_session, entry)
            {
                /* Clean up session's groups first */
                LIST_FOR_EACH_ENTRY_SAFE(group, group_next, &session->groups, 
                                        struct url_group, session_entry)
                {
                    struct url_group_url *url_entry, *url_next;
                    
                    /* Free all URLs in the group */
                    LIST_FOR_EACH_ENTRY_SAFE(url_entry, url_next, &group->urls, 
                                            struct url_group_url, entry)
                    {
                        list_remove(&url_entry->entry);
                        free(url_entry->url);
                        free(url_entry);
                    }
                    
                    list_remove(&group->entry);
                    list_remove(&group->session_entry);
                    free(group);
                }
                
                list_remove(&session->entry);
                free(session);
            }
            
            /* Clean up any orphaned URL groups */
            LIST_FOR_EACH_ENTRY_SAFE(group, group_next, &url_groups, 
                                    struct url_group, entry)
            {
                struct url_group_url *url_entry, *url_next;
                
                LIST_FOR_EACH_ENTRY_SAFE(url_entry, url_next, &group->urls, 
                                        struct url_group_url, entry)
                {
                    list_remove(&url_entry->entry);
                    free(url_entry->url);
                    free(url_entry);
                }
                
                list_remove(&group->entry);
                free(group);
            }
            
            LeaveCriticalSection(&g_httpapi_cs);
            DeleteCriticalSection(&g_httpapi_cs);
        }
        break;
    }
    return TRUE;
}
