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
#include "wine/list.h"
#include "winhttp.h"

WINE_DEFAULT_DEBUG_CHANNEL(http);

#define MAX_CACHE_ENTRIES 1000

struct cache_entry {
    struct list entry;
    WCHAR *url;
    void *data;
    ULONG data_length;
};

static struct list cache_list = LIST_INIT(cache_list);
static ULONG cache_count = 0;

struct http_wait_for_disconnect_params
{
    HTTP_CONNECTION_ID connection_id;
    ULONG bits;
    ULONG flags;
};

struct http_cancel_request_params
{
    HTTP_REQUEST_ID RequestId;
    ULONG Bits;
};

#define IOCTL_HTTP_WAIT_FOR_DISCONNECT CTL_CODE(FILE_DEVICE_NETWORK, 0x32, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HTTP_WAIT_FOR_DISCONNECT_EX CTL_CODE(FILE_DEVICE_NETWORK, 0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HTTP_CANCEL_REQUEST CTL_CODE(FILE_DEVICE_NETWORK, 0x31, METHOD_BUFFERED, FILE_ANY_ACCESS)


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

    if (flags & ~HTTP_INITIALIZE_SERVER)
    {
        FIXME("Unhandled flags %#lx.\n", flags);
        return ERROR_SUCCESS;
    }

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
    return ERROR_SUCCESS;
}

ULONG WINAPI HttpWaitForDisconnect(HANDLE ReqQueueHandle, HTTP_CONNECTION_ID ConnectionId, LPOVERLAPPED pOverlapped)
{
    struct http_wait_for_disconnect_params params;
    ULONG ret = NO_ERROR;
    OVERLAPPED sync_ovl;

    TRACE("ReqQueueHandle %p, ConnectionId %s, pOverlapped %p.\n",
            ReqQueueHandle, wine_dbgstr_longlong(ConnectionId), pOverlapped);

    if (!ReqQueueHandle)
        return ERROR_INVALID_PARAMETER;

    if (!pOverlapped)
    {
        sync_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        pOverlapped = &sync_ovl;
    }

    params.connection_id = ConnectionId;
    params.bits = sizeof(void *) * 8;
    params.flags = 0;

    if (!DeviceIoControl(ReqQueueHandle, IOCTL_HTTP_WAIT_FOR_DISCONNECT,
            &params, sizeof(params), NULL, 0, NULL, pOverlapped))
        ret = GetLastError();

    if (pOverlapped == &sync_ovl)
    {
        if (ret == ERROR_IO_PENDING)
        {
            ret = NO_ERROR;
            if (!GetOverlappedResult(ReqQueueHandle, pOverlapped, NULL, TRUE))
                ret = GetLastError();
        }
        CloseHandle(sync_ovl.hEvent);
    }

    return ret;
}

ULONG WINAPI HttpWaitForDisconnectEx(HANDLE ReqQueueHandle, HTTP_CONNECTION_ID ConnectionId, ULONG Flags, LPOVERLAPPED pOverlapped)
{
    struct http_wait_for_disconnect_params params;
    ULONG ret = NO_ERROR;
    OVERLAPPED sync_ovl;

    TRACE("ReqQueueHandle %p, ConnectionId %s, Flags %#lx, pOverlapped %p.\n",
            ReqQueueHandle, wine_dbgstr_longlong(ConnectionId), Flags, pOverlapped);

    if (!ReqQueueHandle)
        return ERROR_INVALID_PARAMETER;

    if (!pOverlapped)
    {
        sync_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        pOverlapped = &sync_ovl;
    }

    if (Flags)
        FIXME("Unhandled Flags %#lx.\n", Flags);

    params.connection_id = ConnectionId;
    params.bits = sizeof(void *) * 8;
    params.flags = Flags;

    if (!DeviceIoControl(ReqQueueHandle, IOCTL_HTTP_WAIT_FOR_DISCONNECT_EX,
            &params, sizeof(params), NULL, 0, NULL, pOverlapped))
        ret = GetLastError();

    if (pOverlapped == &sync_ovl)
    {
        if (ret == ERROR_IO_PENDING)
        {
            ret = NO_ERROR;
            if (!GetOverlappedResult(ReqQueueHandle, pOverlapped, NULL, TRUE))
                ret = GetLastError();
        }
        CloseHandle(sync_ovl.hEvent);
    }

    return ret;
}

ULONG WINAPI HttpCancelHttpRequest(HANDLE RequestQueueHandle, HTTP_REQUEST_ID RequestId, LPOVERLAPPED pOverlapped)
{
    struct http_cancel_request_params params;
    ULONG ret = NO_ERROR;
    OVERLAPPED sync_ovl;

    TRACE("RequestQueueHandle %p, RequestId %s, pOverlapped %p.\n",
            RequestQueueHandle, wine_dbgstr_longlong(RequestId), pOverlapped);

    if (!RequestQueueHandle)
        return ERROR_INVALID_PARAMETER;

    if (!pOverlapped)
    {
        sync_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        pOverlapped = &sync_ovl;
    }

    params.RequestId = RequestId;
    params.Bits = sizeof(void *) * 8;

    if (!DeviceIoControl(RequestQueueHandle, IOCTL_HTTP_CANCEL_REQUEST,
            &params, sizeof(params), NULL, 0, NULL, pOverlapped))
        ret = GetLastError();

    if (pOverlapped == &sync_ovl)
    {
        if (ret == ERROR_IO_PENDING)
        {
            ret = NO_ERROR;
            if (!GetOverlappedResult(RequestQueueHandle, pOverlapped, NULL, TRUE))
                ret = GetLastError();
        }
        CloseHandle(sync_ovl.hEvent);
    }

    return ret;
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
ULONG WINAPI HttpTerminate(ULONG flags, PVOID reserved)
{
    SC_HANDLE manager, service;
    ULONG ret = NO_ERROR;

    TRACE("flags %#lx, reserved %p.\n", flags, reserved);

    if (flags & ~HTTP_INITIALIZE_SERVER)
    {
        FIXME("Unhandled flags %#lx.\n", flags);
        return NO_ERROR;
    }

    if (reserved)
        return ERROR_INVALID_PARAMETER;

    /* Stop the HTTP service */
    if (!(manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)))
        return GetLastError();

    if (!(service = OpenServiceW(manager, L"http", SERVICE_STOP)))
    {
        ERR("Failed to open HTTP service, error %lu.\n", GetLastError());
        CloseServiceHandle(manager);
        return GetLastError();
    }

    if (!ControlService(service, SERVICE_CONTROL_STOP, NULL) 
            && GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
    {
        ERR("Failed to stop HTTP service, error %lu.\n", GetLastError());
        ret = GetLastError();
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    /* Clean up any cached data */
    HttpFlushResponseCache(NULL, NULL, 0, NULL);

    return ret;
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
ULONG WINAPI HttpDeleteServiceConfiguration( HANDLE handle, HTTP_SERVICE_CONFIG_ID type,
                 PVOID config, ULONG length, LPOVERLAPPED overlapped )
{
    FIXME( "(%p, %d, %p, %ld, %p): stub!\n", handle, type, config, length, overlapped );
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
ULONG WINAPI HttpQueryServiceConfiguration( HANDLE handle, HTTP_SERVICE_CONFIG_ID type,
                 PVOID query, ULONG query_len, PVOID buffer, ULONG buffer_len,
                 PULONG data_len, LPOVERLAPPED overlapped )
{
    FIXME( "(%p, %d, %p, %ld, %p, %ld, %p, %p): stub!\n", handle, type, query, query_len,
            buffer, buffer_len, data_len, overlapped );
    return ERROR_FILE_NOT_FOUND;
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
ULONG WINAPI HttpSetServiceConfiguration( HANDLE handle, HTTP_SERVICE_CONFIG_ID type,
                 PVOID config, ULONG length, LPOVERLAPPED overlapped )
{
    FIXME( "(%p, %d, %p, %ld, %p): stub!\n", handle, type, config, length, overlapped );
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
    int len;

    len = WideCharToMultiByte(CP_ACP, 0, urlW, -1, NULL, 0, NULL, NULL);
    if (!(params = malloc(offsetof(struct http_add_url_params, url[len]))))
        return ERROR_OUTOFMEMORY;
    WideCharToMultiByte(CP_ACP, 0, urlW, -1, params->url, len, NULL, NULL);
    params->context = context;

    ovl.hEvent = (HANDLE)((ULONG_PTR)CreateEventW(NULL, TRUE, FALSE, NULL) | 1);

    if (!DeviceIoControl(queue, IOCTL_HTTP_ADD_URL, params,
            offsetof(struct http_add_url_params, url[len]), NULL, 0, NULL, &ovl))
        ret = GetLastError();
    CloseHandle(ovl.hEvent);
    free(params);
    return ret;
}

/***********************************************************************
 *        HttpAddUrl     (HTTPAPI.@)
 */
ULONG WINAPI HttpAddUrl(HANDLE queue, const WCHAR *url, void *reserved)
{
    TRACE("queue %p, url %s, reserved %p.\n", queue, debugstr_w(url), reserved);

    return add_url(queue, url, 0);
}

static ULONG remove_url(HANDLE queue, const WCHAR *urlW)
{
    ULONG ret = ERROR_SUCCESS;
    OVERLAPPED ovl = {};
    char *url;
    int len;

    len = WideCharToMultiByte(CP_ACP, 0, urlW, -1, NULL, 0, NULL, NULL);
    if (!(url = malloc(len)))
        return ERROR_OUTOFMEMORY;
    WideCharToMultiByte(CP_ACP, 0, urlW, -1, url, len, NULL, NULL);

    ovl.hEvent = (HANDLE)((ULONG_PTR)CreateEventW(NULL, TRUE, FALSE, NULL) | 1);

    if (!DeviceIoControl(queue, IOCTL_HTTP_REMOVE_URL, url, len, NULL, 0, NULL, &ovl))
        ret = GetLastError();
    CloseHandle(ovl.hEvent);
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
        ovl = &sync_ovl;
    }

    if (!ret_size)
        ret_size = &local_ret_size;

    if (!DeviceIoControl(queue, IOCTL_HTTP_RECEIVE_BODY, &params, sizeof(params), buffer, size, ret_size, ovl))
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

/***********************************************************************
 *        HttpReceiveHttpRequest     (HTTPAPI.@)
 */
ULONG WINAPI HttpReceiveHttpRequest(HANDLE queue, HTTP_REQUEST_ID id, ULONG flags,
        HTTP_REQUEST *request, ULONG size, ULONG *ret_size, OVERLAPPED *ovl)
{
    struct http_receive_request_params params;
    ULONG ret = NO_ERROR;
    ULONG local_ret_size;
    OVERLAPPED sync_ovl;

    TRACE("queue %p, id %s, flags %#lx, request %p, size %#lx, ret_size %p, ovl %p.\n",
            queue, wine_dbgstr_longlong(id), flags, request, size, ret_size, ovl);

    if (!queue || !request)
        return ERROR_INVALID_PARAMETER;

    if (size < sizeof(HTTP_REQUEST_V1))
        return ERROR_INSUFFICIENT_BUFFER;

    if (flags & ~HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY)
        FIXME("Ignoring flags %#lx.\n", flags & ~HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY);

    if (!ovl)
    {
        sync_ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!sync_ovl.hEvent)
            return GetLastError();
        ovl = &sync_ovl;
    }

    params.addr = (ULONG_PTR)request;
    params.id = id;
    params.flags = flags;
    params.bits = sizeof(void *) * 8;

    if (!DeviceIoControl(queue, IOCTL_HTTP_RECEIVE_REQUEST,
            &params, sizeof(params), request, size, ret_size ? ret_size : &local_ret_size, ovl))
    {
        ret = GetLastError();
        if (ret != ERROR_IO_PENDING)
        {
            if (ovl == &sync_ovl)
                CloseHandle(sync_ovl.hEvent);
            return ret;
        }
    }

    if (ovl == &sync_ovl)
    {
        if (ret == ERROR_IO_PENDING)
        {
            ret = NO_ERROR;
            if (!GetOverlappedResult(queue, ovl, ret_size ? ret_size : &local_ret_size, TRUE))
                ret = GetLastError();
        }
        CloseHandle(sync_ovl.hEvent);
    }

    return ret;
}

static void format_date(char *buffer)
{
    static const char day_names[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char month_names[12][4] =
            {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    SYSTEMTIME date;
    GetSystemTime(&date);
    sprintf(buffer + strlen(buffer), "Date: %s, %02u %s %u %02u:%02u:%02u GMT\r\n",
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
    char *p, dummy[12];
    USHORT i;

    TRACE("queue %p, id %s, flags %#lx, response %p, cache_policy %p, "
            "ret_size %p, reserved1 %p, reserved2 %#lx, ovl %p, log_data %p.\n",
            queue, wine_dbgstr_longlong(id), flags, response, cache_policy,
            ret_size, reserved1, reserved2, ovl, log_data);

    if (flags & ~HTTP_SEND_RESPONSE_FLAG_MORE_DATA)
        FIXME("Unhandled flags %#lx.\n", flags & ~HTTP_SEND_RESPONSE_FLAG_MORE_DATA);
    if (response->s.Flags)
        FIXME("Unhandled response flags %#lx.\n", response->s.Flags);
    if (cache_policy)
        WARN("Ignoring cache_policy.\n");
    if (log_data)
        WARN("Ignoring log_data.\n");

    len = 12 + sprintf(dummy, "%hu", response->s.StatusCode) + response->s.ReasonLength;
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
        if (i == HttpHeaderDate)
            len += 37;
        else if (response->s.Headers.KnownHeaders[i].RawValueLength)
            len += strlen(header_names[i]) + 2 + response->s.Headers.KnownHeaders[i].RawValueLength + 2;
        else if (i == HttpHeaderContentLength && !(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
        {
            char dummy[12];
            len += strlen(header_names[i]) + 2 + sprintf(dummy, "%d", body_len) + 2;
        }
    }
    for (i = 0; i < response->s.Headers.UnknownHeaderCount; ++i)
    {
        len += response->s.Headers.pUnknownHeaders[i].NameLength + 2;
        len += response->s.Headers.pUnknownHeaders[i].RawValueLength + 2;
    }
    len += 2;

    if (!(buffer = malloc(offsetof(struct http_response, buffer[len]))))
        return ERROR_OUTOFMEMORY;
    buffer->id = id;
    buffer->response_flags = flags;
    buffer->len = len;
    sprintf(buffer->buffer, "HTTP/1.1 %u %.*s\r\n", response->s.StatusCode,
            response->s.ReasonLength, response->s.pReason);

    for (i = 0; i < HttpHeaderResponseMaximum; ++i)
    {
        const HTTP_KNOWN_HEADER *header = &response->s.Headers.KnownHeaders[i];
        if (i == HttpHeaderDate)
            format_date(buffer->buffer);
        else if (header->RawValueLength)
            sprintf(buffer->buffer + strlen(buffer->buffer), "%s: %.*s\r\n",
                    header_names[i], header->RawValueLength, header->pRawValue);
        else if (i == HttpHeaderContentLength && !(flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
            sprintf(buffer->buffer + strlen(buffer->buffer), "Content-Length: %d\r\n", body_len);
    }
    for (i = 0; i < response->s.Headers.UnknownHeaderCount; ++i)
    {
        const HTTP_UNKNOWN_HEADER *header = &response->s.Headers.pUnknownHeaders[i];
        sprintf(buffer->buffer + strlen(buffer->buffer), "%.*s: %.*s\r\n", header->NameLength,
                header->pName, header->RawValueLength, header->pRawValue);
    }
    p = buffer->buffer + strlen(buffer->buffer);
    /* Don't use strcat, because this might be the end of the buffer. */
    memcpy(p, "\r\n", 2);
    p += 2;
    for (i = 0; i < response->s.EntityChunkCount; ++i)
    {
        const HTTP_DATA_CHUNK *chunk = &response->s.pEntityChunks[i];
        memcpy(p, chunk->FromMemory.pBuffer, chunk->FromMemory.BufferLength);
        p += chunk->FromMemory.BufferLength;
    }

    if (!ovl)
        ovl = &dummy_ovl;

    if (!DeviceIoControl(queue, IOCTL_HTTP_SEND_RESPONSE, buffer,
            offsetof(struct http_response, buffer[len]), NULL, 0, NULL, ovl))
        ret = GetLastError();

    free(buffer);
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
       ULONG flags, USHORT entity_chunk_count, PHTTP_DATA_CHUNK entity_chunks,
       ULONG *ret_size, void *reserved1, ULONG reserved2, OVERLAPPED *ovl,
       HTTP_LOG_DATA *log_data)
{
    struct http_response *buffer;
    OVERLAPPED dummy_ovl = {};
    ULONG ret = NO_ERROR;
    int len = 0;
    char *p;
    USHORT i;

    TRACE("queue %p, id %s, flags %#lx, entity_chunk_count %u, entity_chunks %p, "
            "ret_size %p, reserved1 %p, reserved2 %#lx, ovl %p, log_data %p\n",
            queue, wine_dbgstr_longlong(id), flags, entity_chunk_count, entity_chunks,
            ret_size, reserved1, reserved2, ovl, log_data);

    if (!id)
        return ERROR_CONNECTION_INVALID;

    if (flags & ~HTTP_SEND_RESPONSE_FLAG_MORE_DATA)
        FIXME("Unhandled flags %#lx.\n", flags & ~HTTP_SEND_RESPONSE_FLAG_MORE_DATA);
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

    if (!(buffer = malloc(offsetof(struct http_response, buffer[len]))))
        return ERROR_OUTOFMEMORY;
    buffer->id = id;
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

    if (!DeviceIoControl(queue, IOCTL_HTTP_SEND_RESPONSE, buffer,
            offsetof(struct http_response, buffer[len]), NULL, 0, NULL, ovl))
        ret = GetLastError();

    free(buffer);
    return ret;
}

struct url_group
{
    struct list entry, session_entry;
    HANDLE queue;
    WCHAR *url;
    HTTP_URL_CONTEXT context;
};

static struct list url_groups = LIST_INIT(url_groups);

static struct url_group *get_url_group(HTTP_URL_GROUP_ID id)
{
    struct url_group *group;
    LIST_FOR_EACH_ENTRY(group, &url_groups, struct url_group, entry)
    {
        if ((HTTP_URL_GROUP_ID)(ULONG_PTR)group == id)
            return group;
    }
    return NULL;
}

struct server_session
{
    struct list entry;
    struct list groups;
};

static struct list server_sessions = LIST_INIT(server_sessions);

static struct server_session *get_server_session(HTTP_SERVER_SESSION_ID id)
{
    struct server_session *session;
    LIST_FOR_EACH_ENTRY(session, &server_sessions, struct server_session, entry)
    {
        if ((HTTP_SERVER_SESSION_ID)(ULONG_PTR)session == id)
            return session;
    }
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

    list_add_tail(&server_sessions, &session->entry);
    list_init(&session->groups);

    *id = (ULONG_PTR)session;
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpCloseServerSession     (HTTPAPI.@)
 */
ULONG WINAPI HttpCloseServerSession(HTTP_SERVER_SESSION_ID id)
{
    struct url_group *group, *group_next;
    struct server_session *session;

    TRACE("id %s.\n", wine_dbgstr_longlong(id));

    if (!(session = get_server_session(id)))
        return ERROR_INVALID_PARAMETER;

    LIST_FOR_EACH_ENTRY_SAFE(group, group_next, &session->groups, struct url_group, session_entry)
    {
        HttpCloseUrlGroup((ULONG_PTR)group);
    }
    list_remove(&session->entry);
    free(session);
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
        return ERROR_OUTOFMEMORY;
    list_add_tail(&url_groups, &group->entry);
    list_add_tail(&session->groups, &group->session_entry);

    *group_id = (ULONG_PTR)group;

    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpCloseUrlGroup     (HTTPAPI.@)
 */
ULONG WINAPI HttpCloseUrlGroup(HTTP_URL_GROUP_ID id)
{
    struct url_group *group;

    TRACE("id %s.\n", wine_dbgstr_longlong(id));

    if (!(group = get_url_group(id)))
        return ERROR_INVALID_PARAMETER;

    list_remove(&group->session_entry);
    list_remove(&group->entry);
    free(group);

    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpSetUrlGroupProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpSetUrlGroupProperty(HTTP_URL_GROUP_ID id, HTTP_SERVER_PROPERTY property, void *value, ULONG length)
{
    struct url_group *group = get_url_group(id);

    TRACE("id %s, property %u, value %p, length %lu.\n",
            wine_dbgstr_longlong(id), property, value, length);

    switch (property)
    {
        case HttpServerBindingProperty:
        {
            const HTTP_BINDING_INFO *info = value;

            TRACE("Binding to queue %p.\n", info->RequestQueueHandle);
            group->queue = info->RequestQueueHandle;
            if (group->url)
                add_url(group->queue, group->url, group->context);
            return ERROR_SUCCESS;
        }
        case HttpServerLoggingProperty:
            WARN("Ignoring logging property.\n");
            return ERROR_SUCCESS;
        default:
            FIXME("Unhandled property %u.\n", property);
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
    WCHAR *new_url;
    ULONG ret;

    TRACE("id %s, url %s, context %s, reserved %#lx.\n", wine_dbgstr_longlong(id),
            debugstr_w(url), wine_dbgstr_longlong(context), reserved);

    if (!url)
        return ERROR_INVALID_PARAMETER;

    if (reserved)
        return ERROR_INVALID_PARAMETER;

    if (!(group = get_url_group(id)))
        return ERROR_INVALID_PARAMETER;

    if (group->url)
    {
        FIXME("Multiple URLs are not handled!\n");
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    if (!(new_url = wcsdup(url)))
        return ERROR_OUTOFMEMORY;

    if (group->queue)
    {
        ret = add_url(group->queue, url, context);
        if (ret)
        {
            free(new_url);
            return ret;
        }
    }

    group->url = new_url;
    group->context = context;

    return NO_ERROR;
}

/***********************************************************************
 *        HttpRemoveUrlFromUrlGroup     (HTTPAPI.@)
 */
ULONG WINAPI HttpRemoveUrlFromUrlGroup(HTTP_URL_GROUP_ID id, const WCHAR *url, ULONG flags)
{
    struct url_group *group = get_url_group(id);

    TRACE("id %s, url %s, flags %#lx.\n", wine_dbgstr_longlong(id), debugstr_w(url), flags);

    if (!group->url)
        return ERROR_FILE_NOT_FOUND;

    if (flags)
        FIXME("Ignoring flags %#lx.\n", flags);

    free(group->url);
    group->url = NULL;

    if (group->queue)
        return remove_url(group->queue, url);

    return ERROR_SUCCESS;
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
    if (!CloseHandle(handle))
        return GetLastError();
    return ERROR_SUCCESS;
}

/***********************************************************************
 *        HttpAddFragmentToCache     (HTTPAPI.@)
 *
 * Adds a data fragment to the response cache.
 *
 * PARAMS
 *   queue       [I] Handle to the request queue.
 *   url         [I] The URL prefix to associate with the cached fragment.
 *   data_chunks [I] Pointer to the data chunks to cache.
 *   chunk_count [I] Number of data chunks.
 *   cache_policy [I] Pointer to the cache policy.
 *   reserved    [I] Reserved, must be NULL.
 *
 * RETURNS
 *   NO_ERROR on success, or an error code on failure.
 */
ULONG WINAPI HttpAddFragmentToCache(HANDLE queue, const WCHAR *url, 
        const HTTP_DATA_CHUNK *data_chunks, ULONG chunk_count,
        const HTTP_CACHE_POLICY *cache_policy, void *reserved)
{
    struct cache_entry *entry;
    ULONG total_length = 0;
    char *current_pos;
    ULONG i;

    TRACE("queue %p, url %s, data_chunks %p, chunk_count %lu, cache_policy %p, reserved %p.\n",
            queue, debugstr_w(url), data_chunks, chunk_count, cache_policy, reserved);

    if (!url || !data_chunks || !chunk_count)
        return ERROR_INVALID_PARAMETER;

    if (reserved)
        return ERROR_INVALID_PARAMETER;

    if (cache_count >= MAX_CACHE_ENTRIES)
        return ERROR_CACHE_FULL;

    /* Calculate total length and validate chunks */
    for (i = 0; i < chunk_count; i++)
    {
        if (data_chunks[i].DataChunkType != HttpDataChunkFromMemory)
        {
            FIXME("Unsupported data chunk type %d.\n", data_chunks[i].DataChunkType);
            return ERROR_NOT_SUPPORTED;
        }
        if (!data_chunks[i].FromMemory.pBuffer || !data_chunks[i].FromMemory.BufferLength)
            return ERROR_INVALID_PARAMETER;
        
        total_length += data_chunks[i].FromMemory.BufferLength;
    }

    if (!(entry = malloc(sizeof(*entry))))
        return ERROR_OUTOFMEMORY;

    if (!(entry->url = wcsdup(url)))
    {
        free(entry);
        return ERROR_OUTOFMEMORY;
    }

    if (!(entry->data = malloc(total_length)))
    {
        free(entry->url);
        free(entry);
        return ERROR_OUTOFMEMORY;
    }

    entry->data_length = total_length;
    current_pos = entry->data;

    /* Copy data chunks */
    for (i = 0; i < chunk_count; i++)
    {
        memcpy(current_pos, data_chunks[i].FromMemory.pBuffer,
                data_chunks[i].FromMemory.BufferLength);
        current_pos += data_chunks[i].FromMemory.BufferLength;
    }

    list_add_tail(&cache_list, &entry->entry);
    cache_count++;

    return NO_ERROR;
}

/***********************************************************************
 *        HttpFlushResponseCache     (HTTPAPI.@)
 *
 * Removes one or all cached responses from the HTTP Server API cache.
 *
 * PARAMS
 *   queue      [I] Handle to the request queue.
 *   url        [I] The URL prefix of the cache entries to flush. If NULL, all entries are flushed.
 *   flags      [I] Reserved, must be 0.
 *   overlapped [I] Optional pointer to an OVERLAPPED structure for asynchronous operation.
 *
 * RETURNS
 *   NO_ERROR on success, or an error code on failure.
 */
ULONG WINAPI HttpFlushResponseCache(HANDLE queue, const WCHAR *url, ULONG flags, OVERLAPPED *overlapped)
{
    struct cache_entry *entry, *next;

    TRACE("queue %p, url %s, flags %#lx, overlapped %p.\n",
          queue, debugstr_w(url), flags, overlapped);

    if (flags)
        FIXME("Ignoring flags %#lx.\n", flags);

    if (url)
    {
        LIST_FOR_EACH_ENTRY_SAFE(entry, next, &cache_list, struct cache_entry, entry)
        {
            if (!wcscmp(entry->url, url))
            {
                list_remove(&entry->entry);
                free(entry->url);
                free(entry->data);
                free(entry);
                cache_count--;
                break;
            }
        }
    }
    else
    {
        LIST_FOR_EACH_ENTRY_SAFE(entry, next, &cache_list, struct cache_entry, entry)
        {
            list_remove(&entry->entry);
            free(entry->url);
            free(entry->data);
            free(entry);
        }
        cache_count = 0;
    }

    return NO_ERROR;
}

/***********************************************************************
 *        HttpShutdownRequestQueue     (HTTPAPI.@)
 */
ULONG WINAPI HttpShutdownRequestQueue(HANDLE queue)
{
    TRACE("queue %p.\n", queue);

    /* Mark the queue as shutting down */
    if (!DeviceIoControl(queue, IOCTL_HTTP_SHUTDOWN_REQUEST_QUEUE, NULL, 0, NULL, 0, NULL, NULL))
        return GetLastError();

    return NO_ERROR;
}

/***********************************************************************
 *        HttpSetRequestQueueProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpSetRequestQueueProperty(HANDLE queue, HTTP_SERVER_PROPERTY property,
        void *value, ULONG length, ULONG reserved1, void *reserved2)
{
    TRACE("queue %p, property %u, value %p, length %lu, reserved1 %#lx, reserved2 %p.\n",
            queue, property, value, length, reserved1, reserved2);

    if (!queue || !value)
        return ERROR_INVALID_PARAMETER;

    if (reserved1 || reserved2)
        return ERROR_INVALID_PARAMETER;

    switch (property)
    {
        case HttpServerQueueLengthProperty:
            if (length != sizeof(HTTP_QOS_SETTING_INFO))
                return ERROR_INVALID_PARAMETER;
            FIXME("Ignoring queue length setting.\n");
            return NO_ERROR;

        case HttpServerStateProperty:
            if (length != sizeof(HTTP_STATE_INFO))
                return ERROR_INVALID_PARAMETER;
            FIXME("Ignoring state property.\n");
            return NO_ERROR;

        case HttpServer503VerbosityProperty:
            if (length != sizeof(HTTP_503_RESPONSE_VERBOSITY))
                return ERROR_INVALID_PARAMETER;
            FIXME("Ignoring 503 verbosity property.\n");
            return NO_ERROR;

        default:
            FIXME("Unhandled property %u.\n", property);
            return ERROR_INVALID_PARAMETER;
    }
}

/***********************************************************************
 *        HttpSetServerSessionProperty     (HTTPAPI.@)
 */
ULONG WINAPI HttpSetServerSessionProperty(HTTP_SERVER_SESSION_ID id,
        HTTP_SERVER_PROPERTY property, void *value, ULONG length)
{
    TRACE("id %s, property %u, value %p, length %lu.\n",
            wine_dbgstr_longlong(id), property, value, length);

    switch (property)
    {
        case HttpServerQosProperty:
        {
            const HTTP_QOS_SETTING_INFO *info = value;
            FIXME("Ignoring QoS setting %u.\n", info->QosType);
            return ERROR_SUCCESS;
        }
        default:
            FIXME("Unhandled property %u.\n", property);
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}
