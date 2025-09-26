/*
 * HTTP server driver
 *
 * Copyright 2019 Zebediah Figura
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

#include <assert.h>
#include <stdbool.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/http.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/debug.h"
#include <stdint.h>
#include "wine/list.h"
#include "http.h"

/* WebSocket limits and timeouts */
#define MAX_WS_FRAME_SIZE (10 * 1024 * 1024)      /* 10MB max frame */
#define MAX_WS_FRAGMENT_SIZE (100 * 1024 * 1024)  /* 100MB max message */
#define WS_TIMEOUT_MS 60000                       /* 60 second timeout */
#define AUTH_TIMEOUT_MS 30000                      /* 30 second timeout for authentication */
#define RESPONSE_TIMEOUT_MS 30000                  /* 30 second timeout for async response body */

/* RFC 6455 WebSocket opcodes */
#define WS_OPCODE_CONTINUATION  0x00
#define WS_OPCODE_TEXT          0x01
#define WS_OPCODE_BINARY        0x02
#define WS_OPCODE_CLOSE         0x08
#define WS_OPCODE_PING          0x09
#define WS_OPCODE_PONG          0x0A

/* WebSocket close codes */
#define WS_CLOSE_NORMAL         1000
#define WS_CLOSE_GOING_AWAY     1001
#define WS_CLOSE_PROTOCOL_ERROR 1002
#define WS_CLOSE_INVALID_DATA   1003
#define WS_CLOSE_INVALID_UTF8   1007
#define WS_CLOSE_POLICY_VIOLATION 1008
#define WS_CLOSE_MESSAGE_TOO_BIG 1009
#define WS_CLOSE_INTERNAL_ERROR 1011

/* Request processing states */
enum request_state {
    REQ_STATE_PENDING,     /* Request queued, waiting for processing */
    REQ_STATE_PROCESSING,  /* Request being processed by a thread */
    REQ_STATE_COMPLETED    /* Request processing completed */
};

/* Connection response states - tracks HTTP response lifecycle */
enum conn_response_state {
    CONN_RESP_IDLE,           /* No response sent yet, waiting for HttpSendHttpResponse */
    CONN_RESP_HEADERS_SENT,   /* Headers sent, may need HttpSendResponseEntityBody */
    CONN_RESP_BODY_COMPLETE   /* Response fully sent (headers + body) */
};

static HANDLE directory_obj;
static DEVICE_OBJECT *device_obj;

WINE_DEFAULT_DEBUG_CHANNEL(http);

#define DECLARE_CRITICAL_SECTION(cs) \
    static CRITICAL_SECTION cs; \
    static CRITICAL_SECTION_DEBUG cs##_debug = \
    { 0, 0, &cs, { &cs##_debug.ProcessLocksList, &cs##_debug.ProcessLocksList }, \
      0, 0, { (DWORD_PTR)(__FILE__ ": " # cs) }}; \
    static CRITICAL_SECTION cs = { &cs##_debug, -1, 0, 0, 0, 0 };

DECLARE_CRITICAL_SECTION(http_cs);

static HANDLE request_thread, request_event;
static BOOL thread_stop;

static HTTP_REQUEST_ID req_id_counter;
static HTTP_CONNECTION_ID conn_id_counter;

/* --- Minimal SHA1 implementation (for WebSocket Accept computation) --- */
typedef struct { uint32_t state[5]; uint64_t count; unsigned char buffer[64]; } sha1_ctx;

static void sha1_transform(uint32_t state[5], const unsigned char buffer[64])
{
    uint32_t a, b, c, d, e, t, W[80]; int i;
    for (i = 0; i < 16; i++)
        W[i] = (buffer[4*i]<<24) | (buffer[4*i+1]<<16) | (buffer[4*i+2]<<8) | buffer[4*i+3];
    for (; i < 80; i++) { uint32_t x = (W[i-3]^W[i-8]^W[i-14]^W[i-16]); W[i] = (x<<1) | (x>>31); }
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    for (i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        t = ((a<<5) | (a>>27)) + f + e + k + W[i];
        e = d; d = c; c = (b<<30) | (b>>2); b = a; a = t;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(sha1_ctx *ctx)
{ ctx->state[0]=0x67452301; ctx->state[1]=0xEFCDAB89; ctx->state[2]=0x98BADCFE; ctx->state[3]=0x10325476; ctx->state[4]=0xC3D2E1F0; ctx->count=0; }

static void sha1_update(sha1_ctx *ctx, const unsigned char *data, size_t len)
{
    size_t i, j = (size_t)((ctx->count >> 3) & 63);
    ctx->count += ((uint64_t)len) << 3;
    if ((j + len) > 63)
    {
        size_t part = 64 - j;
        memcpy(&ctx->buffer[j], data, part);
        sha1_transform(ctx->state, ctx->buffer);
        for (i = part; i + 63 < len; i += 64) sha1_transform(ctx->state, &data[i]);
        j = 0; len -= i; data += i;
    }
    memcpy(&ctx->buffer[j], data, len);
}

static void sha1_final(sha1_ctx *ctx, unsigned char digest[20])
{
    unsigned char finalcount[8]; unsigned char c80 = 0x80, czero = 0x00; size_t i;
    for (i = 0; i < 8; i++) finalcount[i] = (unsigned char)((ctx->count >> ((7 - i) * 8)) & 255);
    sha1_update(ctx, &c80, 1); while ((ctx->count & 504) != 448) sha1_update(ctx, &czero, 1);
    sha1_update(ctx, finalcount, 8);
    for (i = 0; i < 20; i++) digest[i] = (unsigned char)((ctx->state[i>>2] >> ((3 - (i & 3)) * 8)) & 255);
}

struct connection
{
    struct list entry; /* in "connections" below */

    SOCKET socket;

    char *buffer;
    unsigned int len, size;
    bool shutdown;
    
    /* Authentication timeout tracking */
    ULONGLONG auth_start_time;  /* Timestamp when 401 was sent */
    bool auth_in_progress;      /* TRUE if waiting for auth */

    /* If there is a request fully received and waiting to be read, the
     * "available" parameter will be TRUE. Either there is no queue matching
     * the URL of this request yet ("queue" is NULL), there is a queue but no
     * IRPs have arrived for this request yet ("queue" is non-NULL and "req_id"
     * is HTTP_NULL_ID), or an IRP has arrived but did not provide a large
     * enough buffer to read the whole request ("queue" is non-NULL and
     * "req_id" is not HTTP_NULL_ID).
     *
     * If "available" is FALSE, either we are waiting for a new request
     * ("req_id" is HTTP_NULL_ID), or we are waiting for the user to send a
     * response ("req_id" is not HTTP_NULL_ID). */
    BOOL available;
    struct request_queue *queue;
    HTTP_REQUEST_ID req_id;
    HTTP_CONNECTION_ID conn_id;  /* Unique TCP connection identifier (persists across keep-alive) */
    HTTP_URL_CONTEXT context;

    /* Response state tracking - mimics native Windows HTTP.sys behavior */
    enum conn_response_state response_state;  /* Current response lifecycle state */
    ULONGLONG response_start_time;            /* Timestamp when headers were sent */

    /* Things we already parsed out of the request header in parse_request().
     * These are valid only if "available" is TRUE. */
    unsigned int req_len;
    HTTP_VERB verb;
    HTTP_VERSION version;
    const char *url, *host;
    ULONG unk_verb_len, url_len, content_len;
    size_t host_len;  /* Length of host header value */

    /* WebSocket upgrade tracking (PoC) */
    BOOL upgrade_requested;
    char sec_ws_key[64];
    char sec_ws_protocol[64];
    
    /* Enhanced WebSocket state management */
    BOOL is_websocket;              /* TRUE after successful upgrade */
    BOOL ws_passthrough;            /* If TRUE, don't parse frames; deliver raw to app */
    unsigned char *ws_buffer;       /* Dedicated WebSocket frame buffer */
    unsigned int ws_buf_size;       /* WebSocket buffer size */
    unsigned int ws_buf_len;        /* Current data in WebSocket buffer */
    unsigned int ws_read_offset;    /* Read offset to avoid memmove */
    ULONGLONG ws_last_activity;     /* For timeout tracking */
    
    /* Fragmentation state */
    struct {
        BOOL in_fragment;            /* Currently receiving fragments */
        unsigned char fragment_opcode; /* Original opcode of fragmented message */
        unsigned char *fragment_buffer; /* Buffer for reassembly */
        size_t fragment_len;         /* Current fragment buffer length */
        size_t fragment_capacity;    /* Fragment buffer capacity */
    } ws_fragment;
    
    /* Send queue for partial writes */
    struct {
        unsigned char *data;         /* Buffer for queued data */
        size_t len;                  /* Length of queued data */
        size_t sent;                 /* Bytes already sent */
        BOOL in_progress;            /* Currently sending */
    } ws_send_queue;

    /* Application delivery buffer (parsed WS messages for app to read) */
    struct {
        unsigned char *data;
        size_t len;
        size_t read_off;
        size_t capacity;
    } ws_app_in;

    /* List of IRPs waiting for disconnect notification */
    LIST_ENTRY wait_queue;

    /* Queue of pending HTTP_RECEIVE_BODY IRPs for WS pass-through */
    
    /* O(1) request entry lookup optimization */
    struct request_entry *current_request;  /* Direct pointer to current request */
    CRITICAL_SECTION request_lock;          /* Protect request pointer */
    LIST_ENTRY ws_recv_irp_queue;
};

static struct list connections = LIST_INIT(connections);

struct listening_socket
{
    struct list entry;
    unsigned short port;
    SOCKET socket;
};

static struct list listening_sockets = LIST_INIT(listening_sockets);

struct url
{
    struct list entry;
    char *url;
    HTTP_URL_CONTEXT context;
    struct listening_socket *listening_sock;
};

/* Enhanced request tracking structure */
struct request_entry {
    LIST_ENTRY entry;              /* List linkage */
    IRP *irp;                      /* Associated IRP (may be NULL initially) */
    enum request_state state;       /* Current processing state */
    ULONGLONG timestamp;            /* Request arrival time (GetTickCount64) */
    HTTP_REQUEST_ID request_id;     /* Unique request identifier */
    struct connection *conn;        /* Associated connection */
    BOOL allocated;                /* TRUE if dynamically allocated */
    BOOL in_list;                  /* CRITICAL: Explicit list membership flag */
};

struct request_queue
{
    struct list entry;
    LIST_ENTRY irp_queue;
    struct list urls;
    /* NEW: Queue statistics - use volatile for cross-thread visibility */
    volatile LONG pending_irp_count;    /* Number of pending IRPs (worker threads waiting) */
    volatile LONG pending_request_count; /* Number of pending HTTP requests */
    volatile LONG processing_count;     /* Number of requests being processed */
    volatile LONG completed_count;      /* Total completed requests */
    LIST_ENTRY request_list;           /* NEW: List of request_entry structures */
    
    /* NEW: Request ID management - use existing http_cs lock */
    ULONGLONG next_request_id;     /* Next request ID to assign */
};

static struct list request_queues = LIST_INIT(request_queues);

static void accept_connection(SOCKET socket)
{
    struct connection *conn;
    ULONG one = 1;
    SOCKET peer;

    if ((peer = accept(socket, NULL, NULL)) == INVALID_SOCKET)
    {
        if (WSAGetLastError() != WSAEWOULDBLOCK)
            TRACE("accept() failed with error %u on socket %#Ix\n", WSAGetLastError(), (ULONG_PTR)socket);
        return;
    }

    if (!(conn = calloc(1, sizeof(*conn))))
    {
        ERR("Failed to allocate memory for connection structure.\n");
        shutdown(peer, SD_BOTH);
        closesocket(peer);
        return;
    }
    if (!(conn->buffer = malloc(8192)))
    {
        ERR("Failed to allocate buffer memory (8192 bytes) for connection.\n");
        free(conn);
        shutdown(peer, SD_BOTH);
        closesocket(peer);
        return;
    }
    
    TRACE("New connection accepted: socket=%#Ix, buffer_size=8192, conn=%p\n", (ULONG_PTR)peer, conn);
    conn->size = 8192;
    WSAEventSelect(peer, request_event, FD_READ | FD_CLOSE);
    ioctlsocket(peer, FIONBIO, &one);
    conn->socket = peer;
    conn->shutdown = FALSE;  /* Ensure connection is marked as active */
    InitializeListHead(&conn->wait_queue);
    InitializeListHead(&conn->ws_recv_irp_queue);

    /* Initialize O(1) request lookup */
    InitializeCriticalSection(&conn->request_lock);
    conn->current_request = NULL;

    /* Initialize response state tracking */
    conn->response_state = CONN_RESP_IDLE;
    conn->response_start_time = 0;

    /* Assign unique connection ID (persists across keep-alive requests) */
    conn->conn_id = ++conn_id_counter;
    TRACE("Assigned connection ID %s to conn %p\n", wine_dbgstr_longlong(conn->conn_id), conn);

    conn->upgrade_requested = FALSE;
    conn->sec_ws_key[0] = '\0';
    conn->sec_ws_protocol[0] = '\0';
    
    /* Initialize enhanced WebSocket state */
    conn->is_websocket = FALSE;
    conn->ws_passthrough = FALSE;
    conn->ws_buffer = NULL;
    conn->ws_buf_size = 0;
    conn->ws_buf_len = 0;
    conn->ws_read_offset = 0;
    conn->ws_last_activity = GetTickCount64();
    
    /* Initialize fragment state */
    conn->ws_fragment.in_fragment = FALSE;
    conn->ws_fragment.fragment_opcode = 0;
    conn->ws_fragment.fragment_buffer = NULL;
    conn->ws_fragment.fragment_len = 0;
    conn->ws_fragment.fragment_capacity = 0;
    
    /* Initialize send queue */
    conn->ws_send_queue.data = NULL;
    conn->ws_send_queue.len = 0;
    conn->ws_send_queue.sent = 0;
    conn->ws_send_queue.in_progress = FALSE;
    
    /* Initialize app delivery buffer */
    conn->ws_app_in.data = NULL;
    conn->ws_app_in.len = 0;
    conn->ws_app_in.read_off = 0;
    conn->ws_app_in.capacity = 0;
    
    list_add_head(&connections, &conn->entry);

    /* Debug: Count total connections */
    int conn_count = 0;
    struct connection *c;
    LIST_FOR_EACH_ENTRY(c, &connections, struct connection, entry)
    {
        conn_count++;
    }
    TRACE("*** NEW CONNECTION added: conn=%p, total=%d\n", conn, conn_count);
}

static void shutdown_connection(struct connection *conn)
{
    free(conn->buffer);
    shutdown(conn->socket, SD_BOTH);
    conn->shutdown = true;
}

static void close_connection(struct connection *conn)
{
    LIST_ENTRY *entry;
    
    if (!conn->shutdown)
        shutdown_connection(conn);
    
    /* Complete any pending wait-for-disconnect IRPs */
    while ((entry = RemoveHeadList(&conn->wait_queue)) != &conn->wait_queue)
    {
        IRP *irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    
    /* Clean up WebSocket resources */
    if (conn->ws_buffer)
    {
        free(conn->ws_buffer);
        conn->ws_buffer = NULL;
    }
    
    if (conn->ws_fragment.fragment_buffer)
    {
        free(conn->ws_fragment.fragment_buffer);
        conn->ws_fragment.fragment_buffer = NULL;
    }
    
    /* Clean up send queue */
    if (conn->ws_send_queue.data)
    {
        free(conn->ws_send_queue.data);
        conn->ws_send_queue.data = NULL;
    }
    
    /* Free app delivery buffer (was missing - memory leak) */
    if (conn->ws_app_in.data)
    {
        free(conn->ws_app_in.data);
        conn->ws_app_in.data = NULL;
        conn->ws_app_in.len = 0;
        conn->ws_app_in.read_off = 0;
        conn->ws_app_in.capacity = 0;
    }
    
    /* Complete any pending WS pass-through receive IRPs */
    while (!IsListEmpty(&conn->ws_recv_irp_queue))
    {
        LIST_ENTRY *entry2 = RemoveHeadList(&conn->ws_recv_irp_queue);
        IRP *irp2 = CONTAINING_RECORD(entry2, IRP, Tail.Overlay.ListEntry);
        irp2->IoStatus.Status = STATUS_CONNECTION_INVALID;
        irp2->IoStatus.Information = 0;
        IoCompleteRequest(irp2, IO_NO_INCREMENT);
    }
    
    /* Cleanup O(1) request lookup */
    DeleteCriticalSection(&conn->request_lock);
    conn->current_request = NULL;
    
    closesocket(conn->socket);
    list_remove(&conn->entry);
    free(conn);
}

static HTTP_VERB parse_verb(const char *verb, int len)
{
    static const char *const verbs[] =
    {
        "OPTIONS",
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "TRACE",
        "CONNECT",
        "TRACK",
        "MOVE",
        "COPY",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "LOCK",
        "UNLOCK",
        "SEARCH",
    };
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(verbs); ++i)
    {
        if (!strncmp(verb, verbs[i], len))
            return HttpVerbOPTIONS + i;
    }
    return HttpVerbUnknown;
}

/* Return the length of a token, as defined in RFC 2616 section 2.2. */
static int parse_token(const char *str, const char *end)
{
    const char *p;
    for (p = str; !end || p < end; ++p)
    {
        if (!isgraph(*p) || strchr("()<>@,;:\\\"/[]?={}", *p))
            break;
    }
    return p - str;
}

static HTTP_HEADER_ID parse_header_name(const char *header, int len)
{
    static const char *const headers[] =
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
        "Accept",
        "Accept-Charset",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Cookie",
        "Expect",
        "From",
        "Host",
        "If-Match",
        "If-Modified-Since",
        "If-None-Match",
        "If-Range",
        "If-Unmodified-Since",
        "Max-Forwards",
        "Proxy-Authorization",
        "Referer",
        "Range",
        "TE",
        "Translate",
        "User-Agent",
        /* Keep list indices aligned with HTTP header IDs for known headers */
    };
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(headers); ++i)
    {
        if (!strncmp(header, headers[i], len))
            return i;
    }
    return HttpHeaderRequestMaximum;
}

static void parse_header(const char *name, int *name_len, const char **value, int *value_len)
{
    const char *p = name;
    *name_len = parse_token(name, NULL);
    p += *name_len;
    while (*p == ' ' || *p == '\t') ++p;
    ++p; /* skip colon */
    while (*p == ' ' || *p == '\t') ++p;
    *value = p;
    while (isprint(*p) || *p == '\t') ++p;
    while (p > *value && isspace(p[-1])) --p; /* strip trailing LWS */
    *value_len = p - *value;
}

#define http_unknown_header http_unknown_header_64
#define http_data_chunk http_data_chunk_64
#define http_request http_request_64
#define complete_irp complete_irp_64
#define POINTER ULONGLONG
#include "request.h"
#undef http_unknown_header
#undef http_data_chunk
#undef http_request
#undef complete_irp
#undef POINTER

#define http_unknown_header http_unknown_header_32
#define http_data_chunk http_data_chunk_32
#define http_request http_request_32
#define complete_irp complete_irp_32
#define POINTER ULONG
#include "request.h"
#undef http_unknown_header
#undef http_data_chunk
#undef http_request
#undef complete_irp
#undef POINTER

static NTSTATUS complete_irp(struct connection *conn, IRP *irp)
{
    const struct http_receive_request_params params
            = *(struct http_receive_request_params *)irp->AssociatedIrp.SystemBuffer;

    TRACE("Completing IRP %p.\n", irp);

    if (!conn->req_id)
        conn->req_id = ++req_id_counter;

    if (params.bits == 32)
        return complete_irp_32(conn, irp);
    else
        return complete_irp_64(conn, irp);
}

/* Set request state and update counters - MUST be called under http_cs lock! */
static void set_request_state(struct request_queue *queue, 
                              struct request_entry *req, 
                              enum request_state new_state)
{
    enum request_state old_state;
    
    /* Safety checks */
    if (!queue || !req) {
        ERR("NULL parameter in set_request_state\n");
        return;
    }
    
    /* Use critical section for atomic state change to prevent race condition */
    EnterCriticalSection(&http_cs);
    old_state = req->state;
    req->state = new_state;
    LeaveCriticalSection(&http_cs);
    
    if (old_state == new_state)
        return;
        
    /* Update counters AFTER state change (outside critical section for performance) */
    switch (old_state) {
        case REQ_STATE_PENDING:
            InterlockedDecrement(&queue->pending_request_count);
            break;
        case REQ_STATE_PROCESSING:
            InterlockedDecrement(&queue->processing_count);
            break;
        case REQ_STATE_COMPLETED:
            /* No counter decrement for completed */
            break;
    }
    
    switch (new_state) {
        case REQ_STATE_PENDING:
            InterlockedIncrement(&queue->pending_request_count);
            break;
        case REQ_STATE_PROCESSING:
            InterlockedIncrement(&queue->processing_count);
            break;
        case REQ_STATE_COMPLETED:
            InterlockedIncrement(&queue->completed_count);
            break;
    }
    
    TRACE("Request %p state: %d -> %d (P:%ld, W:%ld, C:%ld)\n",
          req, old_state, new_state, 
          queue->pending_request_count, queue->processing_count, queue->completed_count);
}

/* Allocate and initialize a request entry */
static struct request_entry *alloc_request_entry(struct connection *conn)
{
    struct request_entry *entry;
    
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        ERR("Failed to allocate request_entry\n");
        return NULL;
    }
    
    entry->conn = conn;
    entry->timestamp = GetTickCount64();
    entry->state = REQ_STATE_PENDING;
    entry->allocated = TRUE;
    entry->in_list = FALSE;  /* Explicitly initialize list membership flag */
    /* IRP will be set later in complete_irp */
    entry->irp = NULL;
    
    return entry;
}

/* Forward declaration for O(1) optimization */
static void set_connection_request(struct connection *conn, 
                                    struct request_entry *req);

/* Free a request entry and remove from list */
static void free_request_entry(struct request_entry *entry)
{
    if (!entry) return;
    
    /* O(1) optimization: Clear connection's request pointer */
    if (entry->conn) {
        set_connection_request(entry->conn, NULL);
    }
    
    /* Use explicit membership flag instead of unreliable pointer checks */
    if (entry->in_list) {
        RemoveEntryList(&entry->entry);
        entry->in_list = FALSE;
        /* Defensive cleanup - set to safe state after removal */
        InitializeListHead(&entry->entry);
    }
    
    if (entry->allocated) {
        free(entry);
    }
}

/* Generate a unique request ID for tracking */
static ULONGLONG generate_request_id(struct request_queue *queue)
{
    ULONGLONG id;
    
    /* Caller MUST hold http_cs - no additional lock needed */
    id = queue->next_request_id++;
    
    /* Wrap around but skip 0 (HTTP_NULL_ID) */
    if (queue->next_request_id == 0)
        queue->next_request_id = 1;
    
    /* Skip 0 on first call too */
    if (id == 0)
    {
        id = queue->next_request_id++;
    }
    
    TRACE("Generated request ID: %s for queue %p\n", wine_dbgstr_longlong(id), queue);
    
    return id;
}

/* Set connection's request with proper locking */
static void set_connection_request(struct connection *conn, 
                                    struct request_entry *req)
{
    EnterCriticalSection(&conn->request_lock);
    conn->current_request = req;
    LeaveCriticalSection(&conn->request_lock);
}

/* Find request entry for a connection - O(1) optimized version */
static struct request_entry *find_request_entry(struct connection *conn)
{
    struct request_entry *entry;
    
    if (!conn)
        return NULL;
    
    EnterCriticalSection(&conn->request_lock);
    entry = conn->current_request;
    LeaveCriticalSection(&conn->request_lock);
    
    return entry;
}

/* Forward declaration */
static struct url *url_matches(const struct connection *conn, const struct request_queue *queue,
                                unsigned int *ret_slash_count);

/* Bind URL early to avoid late binding issues */
static NTSTATUS bind_url(struct connection *conn)
{
    struct request_queue *queue = conn->queue;
    unsigned int matching_length = 0;
    struct url *matched_url = NULL;
    
    TRACE("Binding connection %p with URL %.*s\n", 
          conn, (int)conn->url_len, conn->url);
    
    if (!queue)
        return STATUS_NOT_FOUND;
    
    /* Use existing url_matches() function from Wine */
    matched_url = url_matches(conn, queue, &matching_length);
    
    if (matched_url)
    {
        /* URL already matched - just trace it */
        TRACE("Bound connection %p to URL %p with matching length %u\n", 
              conn, matched_url, matching_length);
        return STATUS_SUCCESS;
    }
    else
    {
        WARN("No URL found for %.*s\n", (int)conn->url_len, conn->url);
        return STATUS_NOT_FOUND;
    }
}

/* Clean up completed requests older than 30 seconds */
static void cleanup_old_requests(struct request_queue *queue)
{
    struct request_entry *entry;
    LIST_ENTRY *cur, *next_entry;
    ULONGLONG now = GetTickCount64();
    int cleaned = 0;
    
    /* Must be called under http_cs */
    
    for (cur = queue->request_list.Flink; cur != &queue->request_list; cur = next_entry)
    {
        next_entry = cur->Flink;
        entry = CONTAINING_RECORD(cur, struct request_entry, entry);
        
        if (entry->state == REQ_STATE_COMPLETED && 
            (now - entry->timestamp) > 30000)
        {
            free_request_entry(entry);
            cleaned++;
        }
    }
    
    if (cleaned > 0)
        TRACE("Cleaned %d old completed requests\n", cleaned);
}

/* Find an available connection for a queue - called under http_cs */
/* do_mark: if TRUE, mark the connection as unavailable when found */
static struct connection *find_available_connection(struct request_queue *queue, BOOL do_mark)
{
    struct connection *conn;
    
    /* Iterate through all connections to find one that's available for this queue */
    LIST_FOR_EACH_ENTRY(conn, &connections, struct connection, entry)
    {
        if (conn->available && conn->queue == queue)
        {
            if (do_mark)
            {
                /* Mark as no longer available since we're about to use it */
                conn->available = FALSE;
            }
            return conn;
        }
    }
    
    return NULL;
}

/* Complete as many pending IRPs as we have available connections */
/* MUST be called while holding http_cs lock! */
/* Complete pending IRPs when requests are available */
static void complete_pending_irps(struct request_queue *queue)
{
    int completed = 0;
    LIST_ENTRY *irp_entry;
    struct connection *conn;
    struct connection *used_conns[100];  /* POC: Track used connections */
    int used_count = 0;
    int i;
    
    if (!queue)
        return;
        
    TRACE("complete_pending_irps: queue %p has %ld pending IRPs\n",
          queue, queue->pending_irp_count);
    
    /* Debug: Count available connections for this queue before processing */
    int available_count = 0;
    int total_conns = 0;
    LIST_FOR_EACH_ENTRY(conn, &connections, struct connection, entry)
    {
        total_conns++;
        if (conn->available && conn->queue == queue)
        {
            available_count++;
            TRACE("Available connection %p for queue %p (req_id: %I64x)\n", conn, queue, conn->req_id);
        }
    }
    TRACE("Found %d available connections (out of %d total) for queue %p, used %d so far\n", available_count, total_conns, queue, used_count);

    /* Process all available connections with parsed requests */
    /* POC FIX: Process ALL available connections, not just one */
    while (!IsListEmpty(&queue->irp_queue))
    {
        /* Find an available connection (one with a complete request) */
        conn = NULL;
        int search_count = 0;
        LIST_FOR_EACH_ENTRY(conn, &connections, struct connection, entry)
        {
            search_count++;
            /* Connection must be available and already assigned to this queue */
            if (conn->available && conn->queue == queue)
            {
                TRACE("Checking connection %p (search #%d): available=%d, queue match=%d\n", conn, search_count, conn->available, (conn->queue == queue));
                /* Check if we already used this connection in this call */
                int already_used = 0;
                for (i = 0; i < used_count; i++)
                {
                    if (used_conns[i] == conn)
                    {
                        already_used = 1;
                        TRACE("Connection %p already used in this call\n", conn);
                        break;
                    }
                }
                if (!already_used)
                {
                    TRACE("Found unused available connection %p for processing\n", conn);
                    break;  /* Found an unused available connection */
                }
            }
        }

        /* No available connections with requests? Stop */
        if (!conn || !conn->available || conn->queue != queue)
        {
            TRACE("No more available connections: conn=%p, available=%d, queue_match=%d\n", conn, conn ? conn->available : 0, conn ? (conn->queue == queue) : 0);
            break;
        }
            
        /* Track this connection as used */
        if (used_count < 100)
            used_conns[used_count++] = conn;
            
        /* Remove IRP from queue in FIFO order */
        irp_entry = RemoveHeadList(&queue->irp_queue);
        IRP *irp = CONTAINING_RECORD(irp_entry, IRP, Tail.Overlay.ListEntry);
        
        /* CRITICAL: Neutralize cancel routine BEFORE decrementing count to prevent race */
        if (!IoSetCancelRoutine(irp, NULL))
        {
            /* CRITICAL FIX: IRP is being cancelled - complete it with STATUS_CANCELLED */
            /* NEVER requeue cancelled IRPs - this causes infinite loops and hangs */
            irp->IoStatus.Status = STATUS_CANCELLED;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            InterlockedDecrement(&queue->pending_irp_count);
            TRACE("IRP %p was cancelled, completed with STATUS_CANCELLED\n", irp);
            continue;  /* Do NOT requeue! */
        }
        
        /* Decrement pending IRP count after successful cancel check */
        InterlockedDecrement(&queue->pending_irp_count);
        
        /* State transition BEFORE complete_irp (so IRP sees correct state) */
        struct request_entry *req_entry = find_request_entry(conn);
        if (req_entry)
        {
            set_request_state(queue, req_entry, REQ_STATE_PROCESSING);
            TRACE("Transitioned request on conn %p to PROCESSING state\n", conn);
        }
        
        /* Complete the IRP - this wakes the waiting thread */
        irp->IoStatus.Status = complete_irp(conn, irp);

        /* IMPORTANT: We do NOT modify conn->available or conn->req_id here!
         * The tracking array (used_conns) already prevents this connection
         * from being reused in THIS call to complete_pending_irps().
         *
         * Setting conn->available = FALSE was wrong because:
         * 1. It prevents other connections from being processed in this call
         * 2. The 'available' flag means 'has request ready', not 'is processing'
         * 3. It could cause a connection leak if never reset
         *
         * The connection tracking array is sufficient to prevent the
         * request fan-out bug where one request was assigned to all threads.
         */

        IoCompleteRequest(irp, IO_NO_INCREMENT);
        
        completed++;
        
        TRACE("Completed IRP %p on connection %p (total: %d)\n", 
              irp, conn, completed);
    }
    
    if (completed > 0)
    {
        TRACE("complete_pending_irps: completed %d IRPs for queue %p\n",
              completed, queue);
    }
}

/* Compatibility wrapper for existing single-IRP callers */
static void try_complete_irp(struct connection *conn)
{
    if (conn && conn->queue)
    {
        /* Mark this connection as available */
        conn->available = TRUE;
        
        /* Complete any pending IRPs using this and other available connections */
        complete_pending_irps(conn->queue);
    }
}

/* Debug function to dump queue state */
static void dump_queue_state(struct request_queue *queue)
{
    int irp_count = 0;
    int conn_count = 0;
    LIST_ENTRY *entry;
    struct connection *conn;
    
    /* Count pending IRPs */
    for (entry = queue->irp_queue.Flink; 
         entry != &queue->irp_queue; 
         entry = entry->Flink)
    {
        irp_count++;
    }
    
    /* Count available connections */
    LIST_FOR_EACH_ENTRY(conn, &connections, struct connection, entry)
    {
        if (conn->available && conn->queue == queue)
            conn_count++;
    }
    
    TRACE("Queue %p state: %d pending IRPs, %d available connections\n",
          queue, irp_count, conn_count);
}

/* Return 1 if str matches expect, 0 if str is incomplete, -1 if they don't match. */
static int compare_exact(const char *str, const char *expect, const char *end)
{
    while (*expect)
    {
        if (str >= end) return 0;
        if (*str++ != *expect++) return -1;
    }
    return 1;
}

static int parse_number(const char *str, const char **endptr, const char *end)
{
    int n = 0;
    while (str < end && isdigit(*str))
        n = n * 10 + (*str++ - '0');
    *endptr = str;
    return n;
}


/* 0 means not a match, 1 and higher means a match, higher means more paths matched. */
static unsigned int compare_paths(const char *queue_path, const char *conn_path, size_t conn_len)
{
    const char *question_mark;
    unsigned int i, cnt = 1;
    size_t queue_len;

    queue_len = strlen(queue_path);

    if ((question_mark = memchr(conn_path, '?', conn_len)))
        conn_len = question_mark - conn_path;

    if (queue_path[queue_len - 1] == '/')
        queue_len--;
    if (conn_path[conn_len - 1] == '/')
        conn_len--;

    if (conn_len < queue_len)
        return 0;

    for (i = 0; i < queue_len; ++i)
    {
        if (queue_path[i] != conn_path[i])
            return 0;
        if (queue_path[i] == '/')
            cnt++;
    }

    if (queue_len == conn_len || conn_path[queue_len] == '/')
        return cnt;
    else
        return 0;
}

static BOOL host_matches(const struct url *url, const char *conn_host, size_t conn_host_len)
{
    const char *conn_port = NULL;
    size_t host_len = conn_host_len;
    size_t i;

    TRACE("BC: Checking host match between URL '%s' and host '%.*s'\n", 
          url->url, (int)conn_host_len, conn_host);

    if (!url->url)
        return FALSE;

    /* Handle IPv6 addresses [host]:port */
    if (conn_host[0] == '[')
    {
        const char *close_bracket = memchr(conn_host, ']', conn_host_len);
        if (!close_bracket)
        {
            /* Malformed IPv6 address */
            WARN("Malformed IPv6 address: missing closing bracket\n");
            return FALSE;
        }
        
        host_len = close_bracket - conn_host + 1;  /* Include brackets */
        
        /* Check for port after bracket */
        if (close_bracket < conn_host + conn_host_len - 1)
        {
            if (close_bracket[1] == ':')
            {
                conn_port = close_bracket + 2;
            }
            else if (close_bracket[1] != '\0')
            {
                /* Invalid character after bracket */
                WARN("Invalid character after IPv6 address\n");
                return FALSE;
            }
        }
    }
    else
    {
        /* For IPv4/hostname, find last colon (not first) */
        const char *last_colon = NULL;
        for (i = 0; i < conn_host_len; i++)
        {
            if (conn_host[i] == ':')
            {
                last_colon = conn_host + i;
            }
        }
        if (last_colon)
        {
            conn_port = last_colon + 1;
            host_len = last_colon - conn_host;
        }
    }

    /* Handle wildcard matching */
    if (url->url[7] == '+')
    {
        const char *queue_port = strchr(url->url + 7, ':');
        
        if (queue_port && conn_port)
        {
            /* For wildcard hosts, compare only the port part */
            const char *queue_port_end = strchr(queue_port, '/');
            const char *conn_port_end = memchr(conn_port, '/',
                conn_host_len - (conn_port - conn_host));
            size_t queue_port_len, conn_port_len;
            
            if (!queue_port_end) queue_port_end = queue_port + strlen(queue_port);
            if (!conn_port_end) 
                conn_port_end = conn_host + conn_host_len;
            
            /* Skip the colon in queue_port to compare just the port number */
            queue_port++;  /* Skip ':' */
            queue_port_len = queue_port_end - queue_port;
            conn_port_len = conn_port_end - conn_port;
            
            TRACE("Comparing wildcard port '%.*s' with connection port '%.*s'\n",
                  (int)queue_port_len, queue_port, (int)conn_port_len, conn_port);
            
            if (queue_port_len == conn_port_len && !memcmp(queue_port, conn_port, queue_port_len))
                return TRUE;
        }
    }
    else
    {
        /* Normal host matching */
        const char *url_slash = strchr(url->url + 7, '/');
        size_t url_host_len;
        
        if (url_slash)
            url_host_len = url_slash - url->url - 7;
        else
            url_host_len = strlen(url->url + 7);
            
        /* Use portable case-insensitive compare */
        if (host_len == url_host_len && !memicmp(url->url + 7, conn_host, host_len))
            return TRUE;
    }

    return FALSE;
}

static struct url *url_matches(const struct connection *conn, const struct request_queue *queue,
                                unsigned int *ret_slash_count)
{
    const char *queue_path, *conn_host, *conn_path;
    unsigned int max_slash_count = 0, slash_count;
    size_t conn_path_len, conn_host_len;
    struct url *url, *ret = NULL;

    if (strstr(conn->url, "BusinessCentral"))
    {
        TRACE("BC: Checking URL '%s' against queue %p\n", conn->url, queue);
    }

    if (conn->url[0] == '/')
    {
        conn_host = conn->host;
        conn_host_len = conn->host_len;
        conn_path = conn->url;
        conn_path_len = conn->url_len;
    }
    else
    {
        conn_host = conn->url + 7;
        conn_path = strchr(conn_host, '/');
        if (conn_path)
        {
            conn_host_len = conn_path - conn_host;
            conn_path_len = (conn->url + conn->url_len) - conn_path;
        }
        else
        {
            conn_host_len = (conn->url + conn->url_len) - conn_host;
            conn_path = "/";
            conn_path_len = 1;
        }
    }

    TRACE("BC_ROUTE: Matching request: host='%.*s', path='%.*s' against queue %p\n",
          (int)conn_host_len, conn_host, (int)conn_path_len, conn_path, queue);

    LIST_FOR_EACH_ENTRY(url, &queue->urls, struct url, entry)
    {
        BOOL host_match_result;

        TRACE("BC_ROUTE:   -> Evaluating queue %p with pattern '%s'\n", queue, url->url);

        host_match_result = host_matches(url, conn_host, conn_host_len);
        if (host_match_result)
        {
            queue_path = strchr(url->url + 7, '/');
            if (!queue_path)
            {
                TRACE("BC_ROUTE:   -> HOST MATCHED, but pattern has no path. Skipping.\n");
                continue;
            }
            slash_count = compare_paths(queue_path, conn_path, conn_path_len);
            TRACE("BC_ROUTE:   -> HOST MATCHED. Path match score (slash_count) = %u\n", slash_count);

            if (slash_count > max_slash_count)
            {
                TRACE("BC_ROUTE:   -> *** NEW BEST MATCH *** Previous best score: %u. New queue: %p\n", max_slash_count, queue);
                max_slash_count = slash_count;
                ret = url;
            }
            else if (slash_count > 0)
            {
                TRACE("BC_ROUTE:   -> Match score %u is not better than current best %u\n", slash_count, max_slash_count);
            }
        }
        else
        {
            TRACE("BC_ROUTE:   -> Host did not match\n");
        }
    }

    if (ret_slash_count)
        *ret_slash_count = max_slash_count;

    return ret;
}

/* UTF-8 validation helper for text frames */
static BOOL is_valid_utf8(const unsigned char *data, size_t len)
{
    size_t i = 0;
    while (i < len)
    {
        unsigned char c = data[i];
        size_t bytes;
        
        if (c <= 0x7F)
        {
            bytes = 1;
        }
        else if ((c & 0xE0) == 0xC0)
        {
            bytes = 2;
            if ((c & 0xFE) == 0xC0) return FALSE; /* Overlong encoding */
        }
        else if ((c & 0xF0) == 0xE0)
        {
            bytes = 3;
        }
        else if ((c & 0xF8) == 0xF0)
        {
            bytes = 4;
            if ((c & 0xFF) >= 0xF5) return FALSE; /* > U+10FFFF */
        }
        else
        {
            return FALSE; /* Invalid start byte */
        }
        
        if (i + bytes > len) return FALSE; /* Truncated sequence */
        
        /* Validate continuation bytes */
        for (size_t j = 1; j < bytes; j++)
        {
            if ((data[i + j] & 0xC0) != 0x80) return FALSE;
        }
        
        /* Additional validation for surrogates */
        if (bytes == 3)
        {
            uint32_t codepoint = ((c & 0x0F) << 12) | 
                                ((data[i+1] & 0x3F) << 6) | 
                                (data[i+2] & 0x3F);
            if (codepoint >= 0xD800 && codepoint <= 0xDFFF)
            {
                return FALSE; /* UTF-16 surrogates invalid in UTF-8 */
            }
        }
        
        i += bytes;
    }
    return TRUE;
}

/* Validate WebSocket close codes per RFC 6455 */
static BOOL is_valid_close_code(UINT16 code)
{
    /* 1000-1003: Standard codes */
    if (code >= 1000 && code <= 1003) return TRUE;
    
    /* 1007-1011: Standard codes */
    if (code >= 1007 && code <= 1011) return TRUE;
    
    /* 3000-3999: Libraries/frameworks */
    if (code >= 3000 && code <= 3999) return TRUE;
    
    /* 4000-4999: Applications */
    if (code >= 4000 && code <= 4999) return TRUE;
    
    return FALSE;
}

/* Forward declarations for functions we'll implement in Phase 3 */
static int handle_websocket_opcode(struct connection *conn, unsigned char opcode,
                                   BOOL fin, unsigned char *payload, UINT64 payload_len);
static BOOL send_close_frame(struct connection *conn, UINT16 code, const char *reason);

/* Main WebSocket frame parser */
static int parse_websocket_frame(struct connection *conn)
{
    unsigned char *data = (unsigned char *)conn->ws_buffer + conn->ws_read_offset;
    unsigned int available = conn->ws_buf_len - conn->ws_read_offset;
    unsigned int pos = 0;
    
    TRACE("Parsing WebSocket frame: available=%u bytes at offset=%u\n", 
          available, conn->ws_read_offset);
    
    /* Check for timeout */
    if (GetTickCount64() - conn->ws_last_activity > WS_TIMEOUT_MS)
    {
        WARN("WebSocket timeout - closing connection\n");
        send_close_frame(conn, WS_CLOSE_GOING_AWAY, "Timeout");
        return -1;
    }
    
    /* Need at least 2 bytes for basic header */
    if (available < 2)
    {
        TRACE("Not enough data for WebSocket header (need 2, have %u)\n", available);
        return 0; /* Need more data */
    }
    
    /* Parse frame header */
    unsigned char byte1 = data[pos++];
    unsigned char byte2 = data[pos++];
    
    BOOL fin = (byte1 & 0x80) != 0;
    unsigned char rsv = (byte1 & 0x70);
    unsigned char opcode = byte1 & 0x0F;
    BOOL masked = (byte2 & 0x80) != 0;
    UINT64 payload_len = byte2 & 0x7F;
    
    TRACE("WebSocket frame: FIN=%d, RSV=0x%02X, opcode=0x%02X, masked=%d, initial_len=%llu\n",
          fin, rsv, opcode, masked, payload_len);
    
    /* ===== SECURITY VALIDATION 1: RSV bits must be 0 ===== */
    if (rsv != 0)
    {
        WARN("Non-zero RSV bits (0x%02X) without negotiated extensions\n", rsv);
        send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "RSV not 0");
        return -1;
    }
    
    /* ===== SECURITY VALIDATION 2: Client frames MUST be masked ===== */
    if (!masked)
    {
        WARN("Received unmasked client frame - protocol violation\n");
        send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Frame not masked");
        return -1;
    }
    
    /* ===== SECURITY VALIDATION 3: Control frame constraints ===== */
    if (opcode & 0x08) /* Control frame */
    {
        if (!fin)
        {
            WARN("Fragmented control frame - protocol violation\n");
            send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Control frame fragmented");
            return -1;
        }
        if (payload_len > 125)
        {
            WARN("Control frame payload too large: %llu bytes\n", payload_len);
            send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Control frame > 125 bytes");
            return -1;
        }
    }
    
    /* ===== SECURITY VALIDATION 4: Valid opcodes ===== */
    switch (opcode)
    {
    case WS_OPCODE_CONTINUATION:
    case WS_OPCODE_TEXT:
    case WS_OPCODE_BINARY:
    case WS_OPCODE_CLOSE:
    case WS_OPCODE_PING:
    case WS_OPCODE_PONG:
        break; /* Valid */
    case 0x03: case 0x04: case 0x05: case 0x06: case 0x07:
        /* Reserved data frames */
        WARN("Reserved data frame opcode 0x%02X\n", opcode);
        send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Reserved opcode");
        return -1;
    case 0x0B: case 0x0C: case 0x0D: case 0x0E: case 0x0F:
        /* Reserved control frames */
        WARN("Reserved control frame opcode 0x%02X\n", opcode);
        send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Reserved opcode");
        return -1;
    default:
        WARN("Invalid opcode 0x%02X\n", opcode);
        send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Invalid opcode");
        return -1;
    }
    
    /* Parse extended payload length */
    if (payload_len == 126)
    {
        if (available < pos + 2)
        {
            TRACE("Not enough data for 16-bit payload length\n");
            return 0; /* Need more data */
        }
        payload_len = ((UINT64)data[pos] << 8) | data[pos+1];
        pos += 2;
        TRACE("16-bit payload length: %llu\n", payload_len);
    }
    else if (payload_len == 127)
    {
        if (available < pos + 8)
        {
            TRACE("Not enough data for 64-bit payload length\n");
            return 0; /* Need more data */
        }
        payload_len = 0;
        for (int i = 0; i < 8; i++)
        {
            payload_len = (payload_len << 8) | data[pos++];
        }
        TRACE("64-bit payload length: %llu\n", payload_len);
        
        /* ===== SECURITY VALIDATION 5: Top bit must be 0 ===== */
        if (payload_len & 0x8000000000000000ULL)
        {
            WARN("Invalid 64-bit length with top bit set\n");
            send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Invalid length");
            return -1;
        }
    }
    
    /* ===== SECURITY VALIDATION 6: Enforce max frame size ===== */
    if (payload_len > MAX_WS_FRAME_SIZE)
    {
        WARN("Frame too large: %llu bytes (max %u)\n", payload_len, MAX_WS_FRAME_SIZE);
        send_close_frame(conn, WS_CLOSE_MESSAGE_TOO_BIG, "Frame too large");
        return -1;
    }
    
    /* Masking key (required for client frames) */
    if (available < pos + 4)
    {
        TRACE("Not enough data for masking key\n");
        return 0; /* Need more data */
    }
    unsigned char mask[4];
    memcpy(mask, data + pos, 4);
    pos += 4;
    
    /* Check if we have complete payload */
    if (available < pos + payload_len)
    {
        TRACE("Incomplete payload (have %u, need %llu)\n", 
              available - pos, payload_len);
        
        /* ===== SECURITY VALIDATION 7: Check for integer overflow ===== */
        if (pos + payload_len < pos)
        {
            WARN("Integer overflow in frame size calculation\n");
            send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Invalid size");
            return -1;
        }
        
        /* Check if we can even fit this in our buffer */
        if (pos + payload_len > MAX_WS_FRAME_SIZE + 14)
        {
            WARN("Frame would exceed maximum buffer size\n");
            send_close_frame(conn, WS_CLOSE_MESSAGE_TOO_BIG, "Frame too large");
            return -1;
        }
        
        return 0; /* Need more data */
    }
    
    /* Unmask payload (in-place) */
    unsigned char *payload = data + pos;
    for (UINT64 i = 0; i < payload_len; i++)
    {
        payload[i] ^= mask[i % 4];
    }
    
    TRACE("Frame complete: opcode=0x%02X, payload_len=%llu\n", opcode, payload_len);
    
    /* Update activity timestamp */
    conn->ws_last_activity = GetTickCount64();
    
    /* ===== VALIDATION 8: UTF-8 check for complete text frames ===== */
    if (opcode == WS_OPCODE_TEXT && fin)
    {
        if (!is_valid_utf8(payload, payload_len))
        {
            WARN("Invalid UTF-8 in text frame\n");
            send_close_frame(conn, WS_CLOSE_INVALID_UTF8, "Invalid UTF-8");
            return -1;
        }
    }
    /* Note: For fragmented text, we'll validate after reassembly in Phase 3 */
    
    /* Handle frame by opcode (Phase 3) */
    int result = handle_websocket_opcode(conn, opcode, fin, payload, payload_len);
    
    if (result < 0)
    {
        TRACE("Frame handler returned error\n");
        return -1; /* Error, close connection */
    }
    
    /* Return total frame size consumed */
    unsigned int frame_size = pos + payload_len;
    TRACE("Frame processed successfully, consumed %u bytes\n", frame_size);
    
    return frame_size;
}

/* Forward declarations for Phase 3 functions */
static int start_fragment(struct connection *conn, unsigned char opcode,
                         unsigned char *payload, UINT64 payload_len);
static int append_to_fragment(struct connection *conn, 
                             unsigned char *payload, UINT64 payload_len);
static int handle_fragment_continuation(struct connection *conn, BOOL fin,
                                       unsigned char *payload, UINT64 payload_len);
static int process_complete_message(struct connection *conn, unsigned char opcode,
                                   unsigned char *payload, UINT64 payload_len);
static int handle_close_frame(struct connection *conn, 
                             unsigned char *payload, UINT64 payload_len);
static BOOL send_websocket_frame(struct connection *conn, unsigned char opcode,
                                 const void *payload, UINT64 payload_len);
static BOOL send_websocket_data(struct connection *conn, 
                                unsigned char *data, size_t len);
static BOOL queue_websocket_data(struct connection *conn,
                                 unsigned char *data, size_t len);
static void process_send_queue(struct connection *conn);

/* Main opcode handler with fragmentation support */
static int handle_websocket_opcode(struct connection *conn, unsigned char opcode,
                                   BOOL fin, unsigned char *payload, UINT64 payload_len)
{
    TRACE("Handling WebSocket frame: opcode=0x%02X, fin=%d, len=%llu\n",
          opcode, fin, payload_len);
    
    switch (opcode)
    {
    case WS_OPCODE_CONTINUATION:
        /* Continuation of fragmented message */
        if (!conn->ws_fragment.in_fragment)
        {
            WARN("Unexpected continuation frame without initial fragment\n");
            send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Unexpected continuation");
            return -1;
        }
        return handle_fragment_continuation(conn, fin, payload, payload_len);
        
    case WS_OPCODE_TEXT:
        /* Text frame - validate UTF-8 */
        if (fin && !is_valid_utf8(payload, payload_len))
        {
            WARN("Invalid UTF-8 in text frame\n");
            send_close_frame(conn, WS_CLOSE_INVALID_UTF8, "Invalid UTF-8");
            return -1;
        }
        /* For fragmented text, we'll validate after reassembly */
        
        /* Check if we're already in a fragment */
        if (conn->ws_fragment.in_fragment)
        {
            WARN("New data frame while fragment in progress\n");
            send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Fragment interrupted");
            return -1;
        }
        
        if (!fin)
        {
            /* Start of fragmented message */
            return start_fragment(conn, opcode, payload, payload_len);
        }
        
        /* Complete text message */
        return process_complete_message(conn, opcode, payload, payload_len);
        
    case WS_OPCODE_BINARY:
        /* Binary frame (what BC uses for MS-NBFS) */
        if (conn->ws_fragment.in_fragment)
        {
            WARN("New data frame while fragment in progress\n");
            send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Fragment interrupted");
            return -1;
        }
        
        if (!fin)
        {
            /* Start of fragmented message */
            return start_fragment(conn, opcode, payload, payload_len);
        }
        
        /* Complete binary message */
        return process_complete_message(conn, opcode, payload, payload_len);
        
    case WS_OPCODE_CLOSE:
        /* Connection close */
        return handle_close_frame(conn, payload, payload_len);
        
    case WS_OPCODE_PING:
        /* Ping - must respond with pong containing same payload */
        TRACE("Received ping with %llu bytes payload\n", payload_len);
        if (!send_websocket_frame(conn, WS_OPCODE_PONG, payload, payload_len))
        {
            WARN("Failed to send pong response\n");
            return -1;
        }
        return 0;
        
    case WS_OPCODE_PONG:
        /* Pong - response to our ping (if we sent one) */
        TRACE("Received pong with %llu bytes payload\n", payload_len);
        /* TODO: Could track ping/pong for connection health monitoring */
        return 0;
        
    default:
        /* Should not reach here - parser validates opcodes */
        WARN("Unexpected opcode 0x%02X in handler\n", opcode);
        send_close_frame(conn, WS_CLOSE_PROTOCOL_ERROR, "Invalid opcode");
        return -1;
    }
}

/* Fragmentation support functions */
static int start_fragment(struct connection *conn, unsigned char opcode,
                         unsigned char *payload, UINT64 payload_len)
{
    TRACE("Starting fragmented message: opcode=0x%02X, first_len=%llu\n",
          opcode, payload_len);
    
    /* Check size limit */
    if (payload_len > MAX_WS_FRAGMENT_SIZE)
    {
        WARN("Fragment exceeds maximum size\n");
        send_close_frame(conn, WS_CLOSE_MESSAGE_TOO_BIG, "Message too large");
        return -1;
    }
    
    /* Set fragment state */
    conn->ws_fragment.in_fragment = TRUE;
    conn->ws_fragment.fragment_opcode = opcode;
    conn->ws_fragment.fragment_len = 0;
    
    /* Allocate or reuse fragment buffer */
    if (!conn->ws_fragment.fragment_buffer)
    {
        conn->ws_fragment.fragment_capacity = 65536; /* Start with 64KB */
        conn->ws_fragment.fragment_buffer = malloc(conn->ws_fragment.fragment_capacity);
        if (!conn->ws_fragment.fragment_buffer)
        {
            ERR("Failed to allocate fragment buffer\n");
            send_close_frame(conn, WS_CLOSE_INTERNAL_ERROR, "Out of memory");
            return -1;
        }
    }
    
    /* Append first fragment */
    return append_to_fragment(conn, payload, payload_len);
}

static int append_to_fragment(struct connection *conn, 
                             unsigned char *payload, UINT64 payload_len)
{
    /* Check total size limit */
    if (conn->ws_fragment.fragment_len + payload_len > MAX_WS_FRAGMENT_SIZE)
    {
        WARN("Fragmented message exceeds maximum size\n");
        send_close_frame(conn, WS_CLOSE_MESSAGE_TOO_BIG, "Message too large");
        conn->ws_fragment.in_fragment = FALSE;
        return -1;
    }
    
    /* Grow buffer if needed */
    size_t required = conn->ws_fragment.fragment_len + payload_len;
    if (required > conn->ws_fragment.fragment_capacity)
    {
        /* Double capacity until sufficient */
        size_t new_capacity = conn->ws_fragment.fragment_capacity * 2;
        while (new_capacity < required && new_capacity < MAX_WS_FRAGMENT_SIZE)
        {
            new_capacity *= 2;
        }
        
        if (new_capacity > MAX_WS_FRAGMENT_SIZE)
        {
            new_capacity = MAX_WS_FRAGMENT_SIZE;
        }
        
        TRACE("Growing fragment buffer from %zu to %zu bytes\n",
              conn->ws_fragment.fragment_capacity, new_capacity);
        
        unsigned char *new_buffer = realloc(conn->ws_fragment.fragment_buffer, 
                                           new_capacity);
        if (!new_buffer)
        {
            ERR("Failed to grow fragment buffer\n");
            send_close_frame(conn, WS_CLOSE_INTERNAL_ERROR, "Out of memory");
            conn->ws_fragment.in_fragment = FALSE;
            return -1;
        }
        
        conn->ws_fragment.fragment_buffer = new_buffer;
        conn->ws_fragment.fragment_capacity = new_capacity;
    }
    
    /* Append payload to fragment buffer */
    memcpy(conn->ws_fragment.fragment_buffer + conn->ws_fragment.fragment_len,
           payload, payload_len);
    conn->ws_fragment.fragment_len += payload_len;
    
    TRACE("Fragment accumulated: %zu bytes total\n", conn->ws_fragment.fragment_len);
    
    return 0;
}

static int handle_fragment_continuation(struct connection *conn, BOOL fin,
                                       unsigned char *payload, UINT64 payload_len)
{
    TRACE("Continuation frame: fin=%d, len=%llu, total=%zu\n",
          fin, payload_len, conn->ws_fragment.fragment_len);
    
    /* Append to existing fragment */
    int ret = append_to_fragment(conn, payload, payload_len);
    if (ret < 0)
    {
        conn->ws_fragment.in_fragment = FALSE;
        return ret;
    }
    
    if (fin)
    {
        /* Message complete - process it */
        unsigned char opcode = conn->ws_fragment.fragment_opcode;
        unsigned char *data = conn->ws_fragment.fragment_buffer;
        size_t len = conn->ws_fragment.fragment_len;
        
        TRACE("Fragment complete: opcode=0x%02X, total_len=%zu\n", opcode, len);
        
        /* For text messages, validate UTF-8 now */
        if (opcode == WS_OPCODE_TEXT && !is_valid_utf8(data, len))
        {
            WARN("Invalid UTF-8 in reassembled text message\n");
            send_close_frame(conn, WS_CLOSE_INVALID_UTF8, "Invalid UTF-8");
            conn->ws_fragment.in_fragment = FALSE;
            return -1;
        }
        
        /* Reset fragment state */
        conn->ws_fragment.in_fragment = FALSE;
        conn->ws_fragment.fragment_len = 0;
        
        /* Process complete message */
        return process_complete_message(conn, opcode, data, len);
    }
    
    /* More fragments expected */
    return 0;
}

/* Close frame handling */
static int handle_close_frame(struct connection *conn, 
                             unsigned char *payload, UINT64 payload_len)
{
    UINT16 code = WS_CLOSE_NORMAL;
    const char *reason = "";
    
    /* Parse close code and reason */
    if (payload_len >= 2)
    {
        code = (payload[0] << 8) | payload[1];
        
        /* Validate close code */
        if (!is_valid_close_code(code))
        {
            WARN("Invalid close code %u, using 1002\n", code);
            code = WS_CLOSE_PROTOCOL_ERROR;
        }
        
        /* Extract reason if present */
        if (payload_len > 2)
        {
            /* Validate reason is UTF-8 */
            if (!is_valid_utf8(payload + 2, payload_len - 2))
            {
                WARN("Invalid UTF-8 in close reason\n");
                code = WS_CLOSE_PROTOCOL_ERROR;
            }
            else
            {
                /* Note: We'd need to copy this to use it */
                TRACE("Close reason: %.*s\n", (int)(payload_len - 2), payload + 2);
            }
        }
    }
    else if (payload_len == 1)
    {
        /* Single byte payload is invalid */
        WARN("Close frame with 1 byte payload - protocol error\n");
        code = WS_CLOSE_PROTOCOL_ERROR;
    }
    
    TRACE("Received close frame: code=%u\n", code);
    
    /* Send close response if we didn't initiate */
    if (!conn->shutdown)
    {
        send_close_frame(conn, code, "Closing");
    }
    
    /* Signal connection should be closed */
    return -1;
}

/* Process complete messages (BC integration point) */
static int process_complete_message(struct connection *conn, unsigned char opcode,
                                   unsigned char *payload, UINT64 payload_len)
{
    TRACE("Complete WebSocket message: opcode=0x%02X, len=%llu\n", 
          opcode, payload_len);
    
    /* Log first bytes for debugging */
    if (payload_len > 0)
    {
        TRACE("Payload (first %llu bytes): ", min(32, payload_len));
        for (UINT64 i = 0; i < min(32, payload_len); i++)
        {
            TRACE("%02X ", payload[i]);
        }
        TRACE("\n");
    }
    
    /* Deliver complete message payload to application via RECEIVE_BODY */
    if (opcode == WS_OPCODE_BINARY || opcode == WS_OPCODE_TEXT)
    {
        size_t needed = conn->ws_app_in.len - conn->ws_app_in.read_off + (size_t)payload_len;
        size_t have = conn->ws_app_in.capacity;
        size_t used = conn->ws_app_in.len - conn->ws_app_in.read_off;
        if (needed > have)
        {
            size_t newcap = have ? have * 2 : 8192;
            while (newcap < needed) newcap *= 2;
            unsigned char *newbuf = realloc(conn->ws_app_in.data, newcap);
            if (!newbuf)
            {
                ERR("Failed to grow app delivery buffer\n");
                return 0;
            }
            conn->ws_app_in.data = newbuf;
            conn->ws_app_in.capacity = newcap;
        }
        /* Compact if there is read offset */
        if (conn->ws_app_in.read_off && used)
        {
            memmove(conn->ws_app_in.data, conn->ws_app_in.data + conn->ws_app_in.read_off, used);
            conn->ws_app_in.len = used;
            conn->ws_app_in.read_off = 0;
        }
        memcpy(conn->ws_app_in.data + conn->ws_app_in.len, payload, (size_t)payload_len);
        conn->ws_app_in.len += (size_t)payload_len;
        TRACE("Queued %llu bytes for app (total queued=%zu)\n", payload_len, conn->ws_app_in.len - conn->ws_app_in.read_off);
        /* Nudge app by completing a pending RECEIVE_REQUEST if any */
        try_complete_irp(conn);
    }

    /* Successfully processed */
    return 0;
}

/* Complete WebSocket frame sending implementation with queuing */
static BOOL send_websocket_frame(struct connection *conn, unsigned char opcode,
                                 const void *payload, UINT64 payload_len)
{
    unsigned char header[14];  /* Max header size */
    int header_len = 2;
    
    TRACE("Sending WebSocket frame: opcode=0x%02X, len=%llu\n", opcode, payload_len);
    
    /* Check for connection shutdown */
    if (conn->shutdown)
    {
        WARN("Attempted to send frame on shutdown connection\n");
        return FALSE;
    }
    
    /* Build frame header */
    header[0] = 0x80 | (opcode & 0x0F); /* FIN=1, RSV=0, opcode */
    
    /* Payload length encoding (server frames are never masked) */
    if (payload_len <= 125)
    {
        header[1] = (unsigned char)payload_len;
    }
    else if (payload_len <= 0xFFFF)
    {
        header[1] = 126;
        header[2] = (payload_len >> 8) & 0xFF;
        header[3] = payload_len & 0xFF;
        header_len = 4;
    }
    else
    {
        header[1] = 127;
        for (int i = 0; i < 8; i++)
        {
            header[2+i] = (payload_len >> (56 - i*8)) & 0xFF;
        }
        header_len = 10;
    }
    
    /* Total frame size */
    size_t total_size = header_len + payload_len;
    
    /* Allocate single buffer for complete frame */
    unsigned char *frame = malloc(total_size);
    if (!frame)
    {
        ERR("Failed to allocate frame buffer (%zu bytes)\n", total_size);
        return FALSE;
    }
    
    /* Copy header and payload */
    memcpy(frame, header, header_len);
    if (payload_len > 0 && payload)
    {
        memcpy(frame + header_len, payload, payload_len);
    }
    
    /* Try to send immediately */
    BOOL success = send_websocket_data(conn, frame, total_size);
    
    if (!success)
    {
        free(frame);
    }
    
    return success;
}

/* Robust send with partial write handling */
static BOOL send_websocket_data(struct connection *conn, 
                                unsigned char *data, size_t len)
{
    size_t total_sent = 0;
    
    /* If we have queued data, we must queue this too to maintain order */
    if (conn->ws_send_queue.in_progress)
    {
        return queue_websocket_data(conn, data, len);
    }
    
    /* Try to send directly */
    while (total_sent < len)
    {
        int sent = send(conn->socket, (char *)(data + total_sent), 
                       len - total_sent, 0);
        
        if (sent > 0)
        {
            total_sent += sent;
            TRACE("Sent %d bytes (%zu/%zu total)\n", sent, total_sent, len);
        }
        else if (sent == 0)
        {
            /* Connection closed */
            WARN("Connection closed during send\n");
            free(data);
            close_connection(conn);
            return FALSE;
        }
        else
        {
            /* Error or would block */
            int error = WSAGetLastError();
            
            if (error == WSAEWOULDBLOCK || error == WSAENOTCONN)
            {
                /* Socket buffer full, queue remaining data */
                TRACE("Socket would block, queuing %zu bytes\n", len - total_sent);
                
                if (total_sent > 0)
                {
                    /* Partial send, need to queue remainder */
                    size_t remaining = len - total_sent;
                    unsigned char *remainder = malloc(remaining);
                    if (!remainder)
                    {
                        ERR("Failed to allocate queue buffer\n");
                        free(data);
                        return FALSE;
                    }
                    memcpy(remainder, data + total_sent, remaining);
                    free(data);
                    return queue_websocket_data(conn, remainder, remaining);
                }
                else
                {
                    /* Nothing sent, queue entire frame */
                    return queue_websocket_data(conn, data, len);
                }
            }
            else
            {
                /* Fatal error */
                WARN("Send failed with error %d\n", error);
                free(data);
                close_connection(conn);
                return FALSE;
            }
        }
    }
    
    /* Complete send */
    free(data);
    return TRUE;
}

/* Queue management for partial writes */
static BOOL queue_websocket_data(struct connection *conn,
                                 unsigned char *data, size_t len)
{
    TRACE("Queuing %zu bytes for later transmission\n", len);
    
    if (conn->ws_send_queue.in_progress)
    {
        /* Already have queued data, append to it */
        size_t new_size = conn->ws_send_queue.len + len;
        unsigned char *new_buffer = realloc(conn->ws_send_queue.data, new_size);
        
        if (!new_buffer)
        {
            ERR("Failed to grow send queue\n");
            free(data);
            return FALSE;
        }
        
        memcpy(new_buffer + conn->ws_send_queue.len, data, len);
        conn->ws_send_queue.data = new_buffer;
        conn->ws_send_queue.len = new_size;
        free(data);
        
        TRACE("Queue now contains %zu bytes\n", conn->ws_send_queue.len);
    }
    else
    {
        /* First queued item */
        conn->ws_send_queue.data = data;
        conn->ws_send_queue.len = len;
        conn->ws_send_queue.sent = 0;
        conn->ws_send_queue.in_progress = TRUE;
        
        /* Enable FD_WRITE monitoring when data is queued */
        if (WSAEventSelect(conn->socket, request_event, FD_READ | FD_CLOSE | FD_WRITE) == SOCKET_ERROR)
        {
            ERR("WSAEventSelect failed to enable FD_WRITE: error %u\n", WSAGetLastError());
        }
        else
        {
            TRACE("Enabled FD_WRITE monitoring for queued send (%zu bytes)\n", len);
        }
    }
    
    return TRUE;
}

/* Process queued sends when socket becomes writable */
static void process_send_queue(struct connection *conn)
{
    if (!conn->ws_send_queue.in_progress)
    {
        return;
    }
    
    TRACE("Processing send queue: %zu bytes pending\n", 
          conn->ws_send_queue.len - conn->ws_send_queue.sent);
    
    while (conn->ws_send_queue.sent < conn->ws_send_queue.len)
    {
        size_t remaining = conn->ws_send_queue.len - conn->ws_send_queue.sent;
        int sent = send(conn->socket, 
                       (char *)(conn->ws_send_queue.data + conn->ws_send_queue.sent),
                       remaining, 0);
        
        if (sent > 0)
        {
            conn->ws_send_queue.sent += sent;
            TRACE("Sent %d queued bytes (%zu/%zu)\n", 
                  sent, conn->ws_send_queue.sent, conn->ws_send_queue.len);
        }
        else if (sent == 0)
        {
            /* Connection closed */
            WARN("Connection closed while sending queued data\n");
            close_connection(conn);
            return;
        }
        else
        {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK)
            {
                /* Still blocked, try again later */
                TRACE("Socket still blocking, %zu bytes remain queued\n", remaining);
                return;
            }
            else
            {
                /* Fatal error */
                WARN("Send queue failed with error %d\n", error);
                close_connection(conn);
                return;
            }
        }
    }
    
    /* Queue fully sent */
    TRACE("Send queue cleared\n");
    free(conn->ws_send_queue.data);
    conn->ws_send_queue.data = NULL;
    conn->ws_send_queue.len = 0;
    conn->ws_send_queue.sent = 0;
    conn->ws_send_queue.in_progress = FALSE;
    
    /* Disable FD_WRITE monitoring to avoid spurious wakeups */
    if (WSAEventSelect(conn->socket, request_event, FD_READ | FD_CLOSE) == SOCKET_ERROR)
    {
        ERR("WSAEventSelect failed to disable FD_WRITE: error %u\n", WSAGetLastError());
    }
    else
    {
        TRACE("Disabled FD_WRITE monitoring after queue cleared\n");
    }
}

/* Enhanced close frame sending */
static BOOL send_close_frame(struct connection *conn, UINT16 code, const char *reason)
{
    TRACE("send_close_frame: code=%u, reason=%s\n", code, reason ? reason : "(none)");
    
    /* Don't send if already shutting down */
    if (conn->shutdown)
        return TRUE;
    
    /* Mark for shutdown */
    conn->shutdown = TRUE;
    
    /* Build close frame with code */
    unsigned char frame[125];
    int frame_len = 2; /* Header */
    int payload_len = 2; /* Code */
    
    /* Add reason if provided */
    if (reason)
    {
        int reason_len = strlen(reason);
        if (reason_len > 123)
            reason_len = 123; /* Max control frame payload */
        payload_len = 2 + reason_len;
    }
    
    /* Build header */
    frame[0] = 0x88; /* FIN=1, opcode=CLOSE */
    frame[1] = payload_len;
    
    /* Add close code */
    frame[2] = (code >> 8) & 0xFF;
    frame[3] = code & 0xFF;
    
    /* Add reason */
    if (reason && payload_len > 2)
    {
        memcpy(frame + 4, reason, payload_len - 2);
    }
    
    /* Send frame */
    if (send(conn->socket, (char *)frame, 2 + payload_len, 0) < 0)
    {
        WARN("Failed to send close frame\n");
        return FALSE;
    }
    
    return TRUE;
}

/* Upon receiving a request, parse it to ensure that it is a valid HTTP request,
 * and mark down some information that we will use later. Returns 1 if we parsed
 * a complete request, 0 if incomplete, -1 if invalid. */
static int parse_request(struct connection *conn)
{
    const char *const req = conn->buffer, *const end = conn->buffer + conn->len;
    struct request_queue *queue, *best_queue = NULL;
    struct url *conn_url, *best_conn_url = NULL;
    const char *p = req, *q;
    unsigned int slash_count, best_slash_count = 0;
    int len, ret;

    if (!conn->len) return 0;

    TRACE("%s\n", wine_dbgstr_an(conn->buffer, conn->len));

    len = parse_token(p, end);
    if (p + len >= end) return 0;
    if (!len || p[len] != ' ') return -1;

    /* verb */
    if ((conn->verb = parse_verb(p, len)) == HttpVerbUnknown)
        conn->unk_verb_len = len;
    p += len + 1;

    TRACE("Got verb %u (%s).\n", conn->verb, debugstr_an(req, len));

    /* URL */
    conn->url = p;
    while (p < end && isgraph(*p)) ++p;
    conn->url_len = p - conn->url;
    if (p >= end) return 0;
    if (!conn->url_len) return -1;

    TRACE("Got URI %s.\n", debugstr_an(conn->url, conn->url_len));

    /* version */
    if ((ret = compare_exact(p, " HTTP/", end)) <= 0) return ret;
    p += 6;
    conn->version.MajorVersion = parse_number(p, &q, end);
    if (q >= end) return 0;
    if (q == p || *q != '.') return -1;
    p = q + 1;
    if (p >= end) return 0;
    conn->version.MinorVersion = parse_number(p, &q, end);
    if (q >= end) return 0;
    if (q == p) return -1;
    p = q;
    if ((ret = compare_exact(p, "\r\n", end)) <= 0) return ret;
    p += 2;

    TRACE("Got version %hu.%hu.\n", conn->version.MajorVersion, conn->version.MinorVersion);

    /* headers */
    conn->host = NULL;
    conn->host_len = 0;
    conn->content_len = 0;
    for (;;)
    {
        const char *name = p;

        if (!(ret = compare_exact(p, "\r\n", end))) return 0;
        else if (ret > 0) break;

        len = parse_token(p, end);
        if (p + len >= end) return 0;
        if (!len) return -1;
        p += len;
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        if (p >= end) return 0;
        if (*p != ':') return -1;
        ++p;
        while (p < end && (*p == ' ' || *p == '\t')) ++p;

        TRACE("Got %s header.\n", debugstr_an(name, len));

        if (!strncmp(name, "Host", len))
        {
            const char *header_start = p;
            conn->host = p;
            /* Find end of header value (before \r\n) */
            while (p < end && (isprint(*p) || *p == '\t')) ++p;
            conn->host_len = p - header_start;
            if ((ret = compare_exact(p, "\r\n", end)) <= 0) return ret;
            p += 2;
            continue;
        }
        else if (!strncmp(name, "Connection", len))
        {
            /* Detect token 'Upgrade' */
            const char *val = p; const char *v = val;
            while (v < end && (isprint(*v) || *v == '\t')) ++v;
            /* Simple case-insensitive scan */
            const char *scan = val;
            while (scan < v)
            {
                while (scan < v && (*scan == ' ' || *scan == '\t' || *scan == ',')) scan++;
                if (scan + 7 <= v && !_strnicmp(scan, "Upgrade", 7))
                {
                    conn->upgrade_requested = TRUE;
                    break;
                }
                while (scan < v && *scan != ',') scan++;
                if (scan < v && *scan == ',') scan++;
            }
        }
        else if (!strncmp(name, "Upgrade", len))
        {
            /* Look for value 'websocket' */
            const char *val = p; const char *v = val;
            while (v < end && (isprint(*v) || *v == '\t')) ++v;
            if (val < v && !_strnicmp(val, "websocket", min(9, (int)(v - val))))
                conn->upgrade_requested = TRUE;
        }
        else if (!strncmp(name, "Sec-WebSocket-Key", len))
        {
            /* Copy key value (trim trailing whitespace) */
            const char *val = p; const char *v = val;
            while (v < end && (isprint(*v) || *v == '\t')) ++v;
            /* Trim trailing spaces */
            const char *t = v;
            while (t > val && (t[-1] == ' ' || t[-1] == '\t')) --t;
            size_t copy_len = min((size_t)(t - val), sizeof(conn->sec_ws_key) - 1);
            memcpy(conn->sec_ws_key, val, copy_len);
            conn->sec_ws_key[copy_len] = '\0';
        }
        else if (!strncmp(name, "Sec-WebSocket-Protocol", len))
        {
            /* Copy protocol value (trim trailing whitespace) */
            const char *val = p; const char *v = val;
            while (v < end && (isprint(*v) || *v == '\t')) ++v;
            const char *t = v;
            while (t > val && (t[-1] == ' ' || t[-1] == '\t')) --t;
            size_t copy_len = min((size_t)(t - val), sizeof(conn->sec_ws_protocol) - 1);
            memcpy(conn->sec_ws_protocol, val, copy_len);
            conn->sec_ws_protocol[copy_len] = '\0';
        }
        else if (!strncmp(name, "Sec-WebSocket-Protocol", len))
        {
            /* Copy protocol value (trim trailing whitespace) */
            const char *val = p; const char *v = val;
            while (v < end && (isprint(*v) || *v == '\t')) ++v;
            const char *t = v;
            while (t > val && (t[-1] == ' ' || t[-1] == '\t')) --t;
            size_t copy_len = min((size_t)(t - val), sizeof(conn->sec_ws_protocol) - 1);
            memcpy(conn->sec_ws_protocol, val, copy_len);
            conn->sec_ws_protocol[copy_len] = '\0';
        }
        else if (!strncmp(name, "Content-Length", len))
        {
            conn->content_len = parse_number(p, &q, end);
            if (q >= end) return 0;
            if (q == p) return -1;
        }
        else if (!strncmp(name, "Transfer-Encoding", len))
            FIXME("Unhandled Transfer-Encoding header.\n");
        while (p < end && (isprint(*p) || *p == '\t')) ++p;
        if ((ret = compare_exact(p, "\r\n", end)) <= 0) return ret;
        p += 2;
    }
    p += 2;
    if (conn->url[0] == '/' && !conn->host) return -1;

    if (end - p < conn->content_len) return 0;

    conn->req_len = (p - req) + conn->content_len;

    TRACE("Received a full request, length %u bytes.\n", conn->req_len);

    /* If this looks like a WebSocket upgrade, log host/port and path for diagnostics */
    if (conn->upgrade_requested && conn->sec_ws_key[0])
    {
        unsigned short local_port = 0;
        SOCKADDR_STORAGE addr;
        int alen = sizeof(addr);
        if (!getsockname(conn->socket, (struct sockaddr *)&addr, &alen))
        {
            if (((struct sockaddr *)&addr)->sa_family == AF_INET)
                local_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
            else if (((struct sockaddr *)&addr)->sa_family == AF_INET6)
                local_port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
        }
        TRACE("WebSocket upgrade requested on port %u, host=%s, path=%s\n",
              local_port,
              conn->host ? debugstr_an(conn->host, conn->host_len) : debugstr_a("(none)"),
              debugstr_an(conn->url, conn->url_len));
    }

    conn->queue = NULL;
    /* Find a queue which can receive this request. */
    TRACE("Looking for queue to handle URL: %s\n", debugstr_an(conn->url, conn->url_len));
    
    LIST_FOR_EACH_ENTRY(queue, &request_queues, struct request_queue, entry)
    {
        TRACE("Checking queue %p\n", queue);
        if ((conn_url = url_matches(conn, queue, &slash_count)))
        {
            TRACE("Found matching URL with slash_count=%u\n", slash_count);
            if (slash_count > best_slash_count)
            {
                best_slash_count = slash_count;
                best_queue = queue;
                best_conn_url = conn_url;
            }
        }
    }

    if (best_conn_url)
    {
        TRACE("Assigning request to queue %p.\n", best_queue);
        conn->queue = best_queue;
        conn->context = best_conn_url->context;

        /* Use internal WebSocket parsing by default for upgraded connections. */
    }
    else
    {
        TRACE("No queue found for URL: %s\n", debugstr_an(conn->url, conn->url_len));
    }

    /* Stop selecting on incoming data until a response is queued. */
    WSAEventSelect(conn->socket, request_event, FD_CLOSE);

    conn->available = TRUE;
    TRACE("*** Connection %p marked available for queue %p (req_id will be: %I64x)\n", conn, conn->queue, conn->req_id);
    
    /* Phase 1 & 3: Track request and assign ID when complete request detected */
    {
        struct request_entry *req_entry;
        
        /* Get or create tracking entry for this request */
        req_entry = find_request_entry(conn);
        if (!req_entry)
        {
            req_entry = alloc_request_entry(conn);
            if (req_entry && conn->queue) 
            {
                /* Add to queue's request list */
                InsertTailList(&conn->queue->request_list, &req_entry->entry);
                req_entry->in_list = TRUE;  /* Set flag when adding to list */
                InterlockedIncrement(&conn->queue->pending_request_count);
                
                /* O(1) optimization: Set request in connection */
                set_connection_request(conn, req_entry);
            }
        }
        
        /* Phase 3: Assign sequential request ID */
        if (req_entry && conn->queue)
        {
            req_entry->request_id = generate_request_id(conn->queue);
            conn->req_id = req_entry->request_id;  /* Also store in connection */
            
            TRACE("Assigned request ID %s to connection %p\n",
                  wine_dbgstr_longlong(req_entry->request_id), conn);
        }
        
        /* Phase 3: Bind URL early to avoid late binding */
        bind_url(conn);
        
        /* Update state from Phase 1 */
        if (req_entry && conn->queue)
            set_request_state(conn->queue, req_entry, REQ_STATE_PENDING);
            
        TRACE("Created/updated request entry %p for connection %p with ID %s\n", 
              req_entry, conn, wine_dbgstr_longlong(conn->req_id));
    }
    
    /* REMOVED: Don't complete IRPs here - batch processing in main loop instead
     * This was causing serialized processing - only one connection's request
     * was visible at a time. Now we let all connections parse their requests
     * first, then distribute all available requests to waiting threads.
     */
    if (conn->queue)
    {
        TRACE("Connection %p now available for queue %p (will batch process later)\n", conn, conn->queue);
    }

    return 1;
}

static void format_date(char *buffer, size_t buffer_size)
{
    static const char day_names[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char month_names[12][4] =
            {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    SYSTEMTIME date;
    size_t len;
    
    GetSystemTime(&date);
    len = strlen(buffer);
    snprintf(buffer + len, buffer_size - len, "Date: %s, %02u %s %u %02u:%02u:%02u GMT\r\n",
            day_names[date.wDayOfWeek], date.wDay, month_names[date.wMonth - 1],
            date.wYear, date.wHour, date.wMinute, date.wSecond);
}

/* Send a 400 Bad Request response. */
static void send_400(struct connection *conn)
{
    static const char response_header[] = "HTTP/1.1 400 Bad Request\r\n";
    static const char response_body[] =
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Language: en\r\n"
        "Connection: close\r\n";
    char buffer[sizeof(response_header) + sizeof(response_body) + 37];

    strcpy(buffer, response_header);
    format_date(buffer, sizeof(buffer));
    strcat(buffer, response_body);
    if (send(conn->socket, buffer, strlen(buffer), 0) < 0)
        ERR("Failed to send 400 response, error %u.\n", WSAGetLastError());
    shutdown_connection(conn);
}

/* Forward declarations for Phase 5 */
static void process_websocket_frames(struct connection *conn);

/* Phase 5: Optimized WebSocket receive with circular buffer management */
static void receive_websocket_data(struct connection *conn)
{
    int len;
    
    /* Ensure WebSocket buffer is allocated */
    if (!conn->ws_buffer)
    {
        conn->ws_buf_size = 65536;  /* 64KB initial size */
        conn->ws_buffer = malloc(conn->ws_buf_size);
        if (!conn->ws_buffer)
        {
            ERR("Failed to allocate WebSocket buffer\n");
            close_connection(conn);
            return;
        }
        conn->ws_buf_len = 0;
        conn->ws_read_offset = 0;
    }
    
    /* Compact buffer if needed - raise threshold to 75% to reduce memmove frequency */
    if (conn->ws_read_offset > (conn->ws_buf_size * 3) / 4)
    {
        /* Compact only when 75% of buffer is unused */
        if (conn->ws_buf_len > conn->ws_read_offset)
        {
            size_t active_data = conn->ws_buf_len - conn->ws_read_offset;
            TRACE("Compacting WebSocket buffer: %zu bytes active, removing %u offset\n",
                  active_data, conn->ws_read_offset);
            memmove(conn->ws_buffer, conn->ws_buffer + conn->ws_read_offset, active_data);
            conn->ws_buf_len = active_data;
            conn->ws_read_offset = 0;
        }
        else
        {
            /* Buffer is empty, just reset offsets */
            conn->ws_buf_len = 0;
            conn->ws_read_offset = 0;
        }
    }
    
    /* Check if buffer needs to grow */
    if (conn->ws_buf_len >= conn->ws_buf_size - 1024)
    {
        /* Less than 1KB free, grow buffer */
        size_t new_size = conn->ws_buf_size * 2;
        if (new_size > MAX_WS_FRAME_SIZE + 14)
        {
            new_size = MAX_WS_FRAME_SIZE + 14;  /* Cap at max frame + header */
        }
        
        if (new_size > conn->ws_buf_size)
        {
            unsigned char *new_buffer;
            TRACE("Growing WebSocket buffer from %u to %zu bytes\n",
                  conn->ws_buf_size, new_size);
            
            new_buffer = realloc(conn->ws_buffer, new_size);
            if (!new_buffer)
            {
                ERR("Failed to grow WebSocket buffer\n");
                close_connection(conn);
                return;
            }
            
            conn->ws_buffer = new_buffer;
            conn->ws_buf_size = new_size;
        }
        else if (conn->ws_buf_len >= conn->ws_buf_size - 14)
        {
            /* Buffer is full and can't grow - protocol error */
            WARN("WebSocket buffer exhausted - frame too large\n");
            send_close_frame(conn, WS_CLOSE_MESSAGE_TOO_BIG, "Buffer exhausted");
            shutdown_connection(conn);
            return;
        }
    }
    
    /* Receive new data */
    len = recv(conn->socket,
              (char *)(conn->ws_buffer + conn->ws_buf_len),
              conn->ws_buf_size - conn->ws_buf_len, 0);
    
    if (len > 0)
    {
        conn->ws_buf_len += len;
        conn->ws_last_activity = GetTickCount64();
        TRACE("Received %d bytes of WebSocket data (buffer now %u bytes)\n",
              len, conn->ws_buf_len);
        
        /* In pass-through mode, do not parse frames; app will read via RECEIVE_BODY */
        if (!conn->ws_passthrough)
        {
            process_websocket_frames(conn);
            /* After parsing, if app has queued IRPs and app buffer has data, complete them */
            EnterCriticalSection(&http_cs);
            while (!IsListEmpty(&conn->ws_recv_irp_queue))
            {
                DWORD avail = (DWORD)((conn->ws_app_in.len > conn->ws_app_in.read_off) ? (conn->ws_app_in.len - conn->ws_app_in.read_off) : 0);
                if (!avail) break;
                LIST_ENTRY *entry = RemoveHeadList(&conn->ws_recv_irp_queue);
                IRP *pirp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
                IO_STACK_LOCATION *st = IoGetCurrentIrpStackLocation(pirp);
                DWORD out_len = st->Parameters.DeviceIoControl.OutputBufferLength;
                DWORD to_copy = min(avail, out_len);
                memcpy(pirp->AssociatedIrp.SystemBuffer, conn->ws_app_in.data + conn->ws_app_in.read_off, to_copy);
                conn->ws_app_in.read_off += to_copy;
                if (conn->ws_app_in.read_off >= conn->ws_app_in.len)
                {
                    conn->ws_app_in.len = 0;
                    conn->ws_app_in.read_off = 0;
                }
                pirp->IoStatus.Status = STATUS_SUCCESS;
                pirp->IoStatus.Information = to_copy;
                IoCompleteRequest(pirp, IO_NO_INCREMENT);
            }
            LeaveCriticalSection(&http_cs);
        }
        else
        {
            /* Complete any queued RECEIVE_BODY IRPs */
            EnterCriticalSection(&http_cs);
            while (!IsListEmpty(&conn->ws_recv_irp_queue))
            {
                LIST_ENTRY *entry = RemoveHeadList(&conn->ws_recv_irp_queue);
                IRP *pirp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
                IO_STACK_LOCATION *st = IoGetCurrentIrpStackLocation(pirp);
                DWORD out_len = st->Parameters.DeviceIoControl.OutputBufferLength;
                DWORD avail = (conn->ws_buf_len > conn->ws_read_offset) ? (conn->ws_buf_len - conn->ws_read_offset) : 0;
                if (!avail)
                {
                    /* Put it back and break if no data (shouldn't happen after len>0) */
                    InsertHeadList(&conn->ws_recv_irp_queue, &pirp->Tail.Overlay.ListEntry);
                    break;
                }
                DWORD to_copy = min(avail, out_len);
                memcpy(pirp->AssociatedIrp.SystemBuffer, conn->ws_buffer + conn->ws_read_offset, to_copy);
                conn->ws_read_offset += to_copy;
                if (conn->ws_read_offset >= conn->ws_buf_len)
                {
                    conn->ws_buf_len = 0;
                    conn->ws_read_offset = 0;
                }
                pirp->IoStatus.Status = STATUS_SUCCESS;
                pirp->IoStatus.Information = to_copy;
                IoCompleteRequest(pirp, IO_NO_INCREMENT);
            }
            LeaveCriticalSection(&http_cs);
        }
    }
    else if (len == 0)
    {
        /* Connection closed by peer */
        TRACE("WebSocket connection closed by peer\n");
        close_connection(conn);
    }
    else
    {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK)
        {
            WARN("WebSocket recv failed with error %d\n", error);
            close_connection(conn);
        }
    }
}

/* Process multiple WebSocket frames in buffer */
static void process_websocket_frames(struct connection *conn)
{
    /* Process all complete frames in the buffer */
    while (conn->ws_buf_len > conn->ws_read_offset && !conn->shutdown)
    {
        int frame_size = parse_websocket_frame(conn);
        
        if (frame_size < 0)
        {
            /* Error in frame parsing - close connection */
            TRACE("Frame parsing error, closing connection\n");
            shutdown_connection(conn);
            return;
        }
        else if (frame_size == 0)
        {
            /* Incomplete frame, need more data */
            TRACE("Incomplete frame, waiting for more data\n");
            break;
        }
        else
        {
            /* Frame processed successfully */
            TRACE("Processed frame of %d bytes\n", frame_size);
            conn->ws_read_offset += frame_size;
            
            /* Check if we've processed all data */
            if (conn->ws_read_offset >= conn->ws_buf_len)
            {
                /* Buffer is now empty */
                conn->ws_buf_len = 0;
                conn->ws_read_offset = 0;
            }
        }
    }
    
    /* If send queue has data and socket is writable, process it */
    if (conn->ws_send_queue.in_progress)
    {
        process_send_queue(conn);
    }
}

/* Phase 5: Periodic timeout checking for WebSocket connections */
static void check_websocket_timeouts(void)
{
    struct connection *conn, *next;
    ULONGLONG now = GetTickCount64();
    
    LIST_FOR_EACH_ENTRY_SAFE(conn, next, &connections, struct connection, entry)
    {
        if (conn->is_websocket && !conn->shutdown)
        {
            if (now - conn->ws_last_activity > WS_TIMEOUT_MS)
            {
                TRACE("WebSocket connection timed out (idle for %llu ms)\n",
                      now - conn->ws_last_activity);
                
                /* Send close frame with timeout reason */
                send_close_frame(conn, WS_CLOSE_GOING_AWAY, "Timeout");
                shutdown_connection(conn);
            }
            else if (now - conn->ws_last_activity > WS_TIMEOUT_MS / 2)
            {
                /* Send ping to keep connection alive */
                TRACE("Sending keepalive ping\n");
                send_websocket_frame(conn, WS_OPCODE_PING, NULL, 0);
                conn->ws_last_activity = now;  /* Reset timer */
            }
        }
    }
}

static void receive_data(struct connection *conn)
{
    int len, ret;

    TRACE("receive_data called for conn=%p, socket=%#Ix, shutdown=%d\n", 
          conn, (ULONG_PTR)conn->socket, conn->shutdown);

    if (conn->shutdown)
    {
        WSANETWORKEVENTS events;

        if ((ret = WSAEnumNetworkEvents(conn->socket, NULL, &events)) < 0)
            ERR("Failed to enumerate network events, error %u.\n", WSAGetLastError());
        if (events.lNetworkEvents & FD_CLOSE)
        {
            /* Handle FD_CLOSE gracefully during authentication */
            if (conn->auth_in_progress)
            {
                TRACE("FD_CLOSE received during auth (conn=%p), checking if intentional disconnect\n", conn);
                /* During auth, client may close/reopen connection - only close if timeout exceeded */
                ULONGLONG now = GetTickCount64();
                if ((now - conn->auth_start_time) > AUTH_TIMEOUT_MS)
                {
                    TRACE("Auth timeout exceeded, closing connection\n");
                    close_connection(conn);
                }
                else
                {
                    TRACE("FD_CLOSE during auth window, keeping connection for potential retry\n");
                }
            }
            else
            {
                close_connection(conn);
            }
        }
        return;
    }

    /* Check if this is a WebSocket connection */
    if (conn->is_websocket)
    {
        /* WebSocket mode - use optimized receive handler */
        receive_websocket_data(conn);
        return;
    }

    /* Original HTTP mode processing */
    /* We might be waiting for an IRP, but always call recv() anyway, since we
     * might have been woken up by the socket closing. */
    if ((len = recv(conn->socket, conn->buffer + conn->len, conn->size - conn->len, 0)) <= 0)
    {
        if (WSAGetLastError() == WSAEWOULDBLOCK)
            return; /* nothing to receive */
        else if (!len)
            TRACE("Connection was shut down by peer.\n");
        else
            ERR("Got error %u; shutting down connection.\n", WSAGetLastError());
        close_connection(conn);
        return;
    }
    conn->len += len;

    /* Clear authentication timeout tracking when data is received */
    if (conn->auth_in_progress && len > 0)
    {
        TRACE("Received data during auth, clearing auth timeout tracking.\n");
        conn->auth_in_progress = false;
        /* Step 18: Reset connection state to allow parsing the authenticated request */
        conn->available = FALSE;  /* Allow new request to be parsed */
        conn->req_id = HTTP_NULL_ID;  /* Clear old request ID */
        conn->response_state = CONN_RESP_IDLE;  /* Reset response state */
        conn->len = len;  /* Reset buffer to just the new data */
        conn->req_len = 0;  /* Clear old request length */
        TRACE("Reset connection state for auth retry: available=%d, req_id=%s, len=%u\n",
              conn->available, wine_dbgstr_longlong(conn->req_id), conn->len);
    }

    if (conn->available)
        return; /* waiting for an HttpReceiveHttpRequest() call */
    if (conn->req_id != HTTP_NULL_ID)
        return; /* waiting for an HttpSendHttpResponse() or HttpSendResponseEntityBody() call */

    TRACE("Received %u bytes of data.\n", len);

    if (!(ret = parse_request(conn)))
    {
        ULONG available;
        ioctlsocket(conn->socket, FIONREAD, &available);
        if (available)
        {
            TRACE("%lu more bytes of data available, trying with larger buffer.\n", available);
            TRACE("Reallocating buffer: current_size=%u, current_len=%u, available=%lu, new_size=%lu\n",
                  conn->size, conn->len, available, conn->len + available);
            if (!(conn->buffer = realloc(conn->buffer, conn->len + available)))
            {
                ERR("Failed to reallocate buffer from %u to %lu bytes.\n", conn->size, conn->len + available);
                close_connection(conn);
                return;
            }
            conn->size = conn->len + available;
            TRACE("Buffer reallocated successfully: new_size=%u\n", conn->size);

            if ((len = recv(conn->socket, conn->buffer + conn->len, conn->size - conn->len, 0)) < 0)
            {
                ERR("Got error %u; shutting down connection.\n", WSAGetLastError());
                close_connection(conn);
                return;
            }
            TRACE("Received %u bytes of data.\n", len);
            conn->len += len;
            ret = parse_request(conn);
        }
    }
    if (!ret)
        TRACE("Request is incomplete, waiting for more data.\n");
    else if (ret < 0)
    {
        WARN("Failed to parse request; shutting down connection.\n");
        send_400(conn);
    }
}

static void check_auth_timeouts(void)
{
    struct connection *conn, *conn_next;
    ULONGLONG now = GetTickCount64();
    int active_auth_count = 0;
    
    LIST_FOR_EACH_ENTRY_SAFE(conn, conn_next, &connections, struct connection, entry)
    {
        if (conn->auth_in_progress)
        {
            ULONGLONG elapsed;
            active_auth_count++;
            elapsed = now - conn->auth_start_time;
            if (elapsed > AUTH_TIMEOUT_MS)
            {
                WARN("401 auth timeout for connection %p after %llu ms (limit: %u ms)\n", 
                     conn, elapsed, AUTH_TIMEOUT_MS);
                        TRACE("Closing timed-out auth connection: socket=%#Ix, req_id=%s\n",
                              (ULONG_PTR)conn->socket, wine_dbgstr_longlong(conn->req_id));
                close_connection(conn);
            }
            else
            {
                TRACE("Auth connection %p still active: %llu ms elapsed of %u ms timeout\n",
                      conn, elapsed, AUTH_TIMEOUT_MS);
            }
        }
    }
    
    if (active_auth_count > 0)
        TRACE("Active auth connections: %d\n", active_auth_count);
}

static void check_response_timeouts(void)
{
    struct connection *conn, *conn_next;
    ULONGLONG now = GetTickCount64();
    int pending_response_count = 0;

    LIST_FOR_EACH_ENTRY_SAFE(conn, conn_next, &connections, struct connection, entry)
    {
        /* Check for connections stuck in HEADERS_SENT state */
        if (conn->response_state == CONN_RESP_HEADERS_SENT && conn->response_start_time > 0)
        {
            ULONGLONG elapsed = now - conn->response_start_time;
            pending_response_count++;

            if (elapsed > RESPONSE_TIMEOUT_MS)
            {
                WARN("Response timeout for connection %p after %llu ms (limit: %u ms) - headers sent but body never received\n",
                     conn, elapsed, RESPONSE_TIMEOUT_MS);
                TRACE("Closing timed-out response connection: socket=%#Ix, req_id=%s, state=%d\n",
                      (ULONG_PTR)conn->socket, wine_dbgstr_longlong(conn->req_id), conn->response_state);
                /* Reset state before closing */
                conn->response_state = CONN_RESP_IDLE;
                conn->req_id = HTTP_NULL_ID;
                conn->queue = NULL;
                close_connection(conn);
            }
            else
            {
                TRACE("Response connection %p still waiting for body: %llu ms elapsed of %u ms timeout\n",
                      conn, elapsed, RESPONSE_TIMEOUT_MS);
            }
        }
    }

    if (pending_response_count > 0)
        TRACE("Connections waiting for response body: %d\n", pending_response_count);
}

static DWORD WINAPI request_thread_proc(void *arg)
{
    struct connection *conn, *cursor;
    struct request_queue *queue;
    struct url *url;
    WSANETWORKEVENTS events;

    TRACE("Starting request thread.\n");

    while (!WaitForSingleObject(request_event, INFINITE))
    {
        EnterCriticalSection(&http_cs);

        LIST_FOR_EACH_ENTRY(queue, &request_queues, struct request_queue, entry)
        {
            LIST_FOR_EACH_ENTRY(url, &queue->urls, struct url, entry)
            {
                if (url->listening_sock && url->listening_sock->socket != -1)
                {
                    /* Check if FD_ACCEPT event is actually pending before calling accept */
                    if (WSAEnumNetworkEvents(url->listening_sock->socket, request_event, &events) == 0)
                    {
                        if (events.lNetworkEvents & FD_ACCEPT)
                        {
                            accept_connection(url->listening_sock->socket);
                        }
                    }
                }
            }
        }

        LIST_FOR_EACH_ENTRY_SAFE(conn, cursor, &connections, struct connection, entry)
        {
            receive_data(conn);
        }

        /* BATCH PROCESSING FIX: After processing all socket events, distribute all available requests.
         * This fixes the BC 429 error by allowing multiple connections to be marked available
         * before we try to complete pending IRPs. Previously, each connection would immediately
         * trigger IRP completion, causing only 1 request to be visible at a time.
         */
        struct request_queue *queue;
        LIST_FOR_EACH_ENTRY(queue, &request_queues, struct request_queue, entry)
        {
            /* Only run completion logic if there are threads waiting for requests */
            if (queue->pending_irp_count > 0 && !IsListEmpty(&queue->irp_queue))
            {
                TRACE("Batch processing: queue %p has %ld pending IRPs, checking all connections\n",
                      queue, queue->pending_irp_count);
                complete_pending_irps(queue);
            }
        }

        /* Check for authentication timeouts */
        check_auth_timeouts();

        /* Check for response body timeouts (async responses) */
        check_response_timeouts();

        /* Check for WebSocket timeouts - send pings and check idle connections */
        check_websocket_timeouts();

        LeaveCriticalSection(&http_cs);
    }

    TRACE("Stopping request thread.\n");

    return 0;
}

static struct listening_socket *get_listening_socket(unsigned short port)
{
    struct listening_socket *listening_sock;

    LIST_FOR_EACH_ENTRY(listening_sock, &listening_sockets, struct listening_socket, entry)
    {
        if (listening_sock->port == port)
            return listening_sock;
    }

    return NULL;
}

static NTSTATUS http_add_url(struct request_queue *queue, IRP *irp)
{
    const struct http_add_url_params *params = irp->AssociatedIrp.SystemBuffer;
    struct request_queue *queue_entry;
    struct sockaddr_in addr;
    struct connection *conn;
    struct url *url_entry, *new_entry;
    struct listening_socket *listening_sock;
    char *url, *endptr;
    size_t queue_url_len, new_url_len;
    ULONG one = 1, value;
    SOCKET s = INVALID_SOCKET;

    TRACE("host %s, context %s.\n", debugstr_a(params->url), wine_dbgstr_longlong(params->context));

    if (!strncmp(params->url, "https://", 8))
    {
        FIXME("HTTPS is not implemented.\n");
        return STATUS_NOT_IMPLEMENTED;
    }
    else if (strncmp(params->url, "http://", 7) || !strchr(params->url + 7, ':'))
        return STATUS_INVALID_PARAMETER;
    if (!(addr.sin_port = htons(strtol(strchr(params->url + 7, ':') + 1, &endptr, 10))) || *endptr != '/')
        return STATUS_INVALID_PARAMETER;
    if (strchr(params->url, '?'))
        return STATUS_INVALID_PARAMETER;

    if (!(url = strdup(params->url)))
        return STATUS_NO_MEMORY;

    if (!(new_entry = malloc(sizeof(struct url))))
    {
        free(url);
        return STATUS_NO_MEMORY;
    }

    new_url_len = strlen(url);
    if (url[new_url_len - 1] == '/')
        new_url_len--;
    
    TRACE("Adding URL: %s to queue %p\n", url, queue);
    TRACE("BC_ROUTE: Registered URL '%s' to queue %p\n", url, queue);

    EnterCriticalSection(&http_cs);

    LIST_FOR_EACH_ENTRY(queue_entry, &request_queues, struct request_queue, entry)
    {
        LIST_FOR_EACH_ENTRY(url_entry, &queue_entry->urls, struct url, entry)
        {
            queue_url_len = strlen(url_entry->url);
            if (url_entry->url[queue_url_len - 1] == '/')
                queue_url_len--;

            if (url_entry->url && queue_url_len == new_url_len && !memcmp(url_entry->url, url, queue_url_len))
            {
                LeaveCriticalSection(&http_cs);
                free(url);
                free(new_entry);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    listening_sock = get_listening_socket(addr.sin_port);

    if (!listening_sock)
    {
        if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
            ERR("Failed to create socket, error %u.\n", WSAGetLastError());
            LeaveCriticalSection(&http_cs);
            free(url);
            free(new_entry);
            return STATUS_UNSUCCESSFUL;
        }

        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = INADDR_ANY;
        value = 1;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&value, sizeof(value));
        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            LeaveCriticalSection(&http_cs);
            closesocket(s);
            free(url);
            free(new_entry);
            if (WSAGetLastError() == WSAEADDRINUSE)
            {
                WARN("Address %s is already in use.\n", debugstr_a(params->url));
                return STATUS_SHARING_VIOLATION;
            }
            else if (WSAGetLastError() == WSAEACCES)
            {
                WARN("Not enough permissions to bind to address %s.\n", debugstr_a(params->url));
                return STATUS_ACCESS_DENIED;
            }
            ERR("Failed to bind socket, error %u.\n", WSAGetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        if (listen(s, SOMAXCONN) == -1)
        {
            ERR("Failed to listen to port %u, error %u.\n", addr.sin_port, WSAGetLastError());
            LeaveCriticalSection(&http_cs);
            closesocket(s);
            free(url);
            free(new_entry);
            return STATUS_OBJECT_NAME_COLLISION;
        }

        if (!(listening_sock = malloc(sizeof(struct listening_socket))))
        {
            LeaveCriticalSection(&http_cs);
            closesocket(s);
            free(url);
            free(new_entry);
            return STATUS_NO_MEMORY;
        }
        listening_sock->port = addr.sin_port;
        listening_sock->socket = s;
        list_add_head(&listening_sockets, &listening_sock->entry);

        ioctlsocket(s, FIONBIO, &one);
        WSAEventSelect(s, request_event, FD_ACCEPT);
    }

    new_entry->url = url;
    new_entry->context = params->context;
    new_entry->listening_sock = listening_sock;
    list_add_head(&queue->urls, &new_entry->entry);
    
    /* Log all URLs in this queue for debugging */
    {
        struct url *existing;
        int count = 0;
        LIST_FOR_EACH_ENTRY(existing, &queue->urls, struct url, entry)
        {
            TRACE("Queue %p now has URL[%d]: %s\n", queue, count++, existing->url);
        }
    }

    /* See if any pending requests now match this queue. */
    LIST_FOR_EACH_ENTRY(conn, &connections, struct connection, entry)
    {
        if (conn->available && !conn->queue && url_matches(conn, queue, NULL))
        {
            conn->queue = queue;
            conn->context = params->context;
            try_complete_irp(conn);
        }
    }

    LeaveCriticalSection(&http_cs);

    return STATUS_SUCCESS;
}

static BOOL is_listening_socket_used(const struct listening_socket *listening_sock)
{
    struct request_queue *queue_entry;
    struct url *url_entry;

    LIST_FOR_EACH_ENTRY(queue_entry, &request_queues, struct request_queue, entry)
    {
        LIST_FOR_EACH_ENTRY(url_entry, &queue_entry->urls, struct url, entry)
        {
            if (listening_sock == url_entry->listening_sock)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static NTSTATUS http_remove_url(struct request_queue *queue, IRP *irp)
{
    const char *url = irp->AssociatedIrp.SystemBuffer;
    struct url *url_entry;

    TRACE("host %s.\n", debugstr_a(url));

    EnterCriticalSection(&http_cs);

    LIST_FOR_EACH_ENTRY(url_entry, &queue->urls, struct url, entry)
    {
        if (url_entry->url && !strcmp(url, url_entry->url))
        {
            free(url_entry->url);
            url_entry->url = NULL;

            if (!is_listening_socket_used(url_entry->listening_sock))
            {
                shutdown(url_entry->listening_sock->socket, SD_BOTH);
                closesocket(url_entry->listening_sock->socket);
                list_remove(&url_entry->listening_sock->entry);
                free(url_entry->listening_sock);
            }
            url_entry->listening_sock = NULL;

            list_remove(&url_entry->entry);
            free(url_entry);

            LeaveCriticalSection(&http_cs);
            return STATUS_SUCCESS;
        }
    }

    LeaveCriticalSection(&http_cs);
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static struct connection *get_connection(HTTP_REQUEST_ID req_id)
{
    struct connection *conn;

    LIST_FOR_EACH_ENTRY(conn, &connections, struct connection, entry)
    {
        if (conn->req_id == req_id)
            return conn;
    }
    TRACE("Failed to find connection for req_id %s\n", wine_dbgstr_longlong(req_id));
    return NULL;
}

static struct connection *get_connection_by_id(HTTP_CONNECTION_ID conn_id)
{
    struct connection *conn;

    LIST_FOR_EACH_ENTRY(conn, &connections, struct connection, entry)
    {
        if (conn->conn_id == conn_id)
            return conn;
    }
    TRACE("Failed to find connection for conn_id %s\n", wine_dbgstr_longlong(conn_id));
    return NULL;
}

static void WINAPI http_receive_request_cancel(DEVICE_OBJECT *device, IRP *irp)
{
    IO_STACK_LOCATION *stack;
    struct request_queue *queue = NULL;

    TRACE("device %p, irp %p.\n", device, irp);

    /* Release the cancel spin lock first per IRP cancel contract */
    IoReleaseCancelSpinLock(irp->CancelIrql);

    /* Best-effort: derive the queue to keep the pending_irp_count accurate */
    stack = IoGetCurrentIrpStackLocation(irp);
    if (stack && stack->FileObject)
        queue = stack->FileObject->FsContext;

    EnterCriticalSection(&http_cs);
    /* Remove from the queue's IRP list if present */
    RemoveEntryList(&irp->Tail.Overlay.ListEntry);
    /* Decrement the pending IRP counter to mirror the increment at queue time */
    if (queue)
    {
        LONG v = InterlockedDecrement(&queue->pending_irp_count);
        if (v < 0)
        {
            /* Should never happen; log and avoid underflowing */
            WARN("pending_irp_count underflow for queue %p (value=%ld)\n", queue, v);
        }
    }
    LeaveCriticalSection(&http_cs);

    irp->IoStatus.Status = STATUS_CANCELLED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static void WINAPI http_wait_for_disconnect_cancel(DEVICE_OBJECT *device, IRP *irp)
{
    TRACE("device %p, irp %p.\n", device, irp);

    IoReleaseCancelSpinLock(irp->CancelIrql);

    EnterCriticalSection(&http_cs);
    RemoveEntryList(&irp->Tail.Overlay.ListEntry);
    LeaveCriticalSection(&http_cs);

    irp->IoStatus.Status = STATUS_CANCELLED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static NTSTATUS http_receive_request(struct request_queue *queue, IRP *irp)
{
    const struct http_receive_request_params *params = irp->AssociatedIrp.SystemBuffer;
    struct connection *conn;
    NTSTATUS ret;

    TRACE("addr %s, id %s, flags %#lx, bits %lu.\n", wine_dbgstr_longlong(params->addr),
            wine_dbgstr_longlong(params->id), params->flags, params->bits);

    EnterCriticalSection(&http_cs);
    
    /* NEW: Add queue status trace */
    TRACE("Queue %p status: pending_requests=%ld, pending_irps=%ld, processing=%ld, completed=%ld\n",
          queue, queue->pending_request_count, queue->pending_irp_count, queue->processing_count, queue->completed_count);

    /* Check if a specific request is already available */
    if (params->id != HTTP_NULL_ID)
    {
        conn = get_connection(params->id);
        if (conn && conn->available && conn->queue == queue)
        {
            ret = complete_irp(conn, irp);
            LeaveCriticalSection(&http_cs);
            return ret;
        }
        else
        {
            ret = STATUS_CONNECTION_INVALID;
            LeaveCriticalSection(&http_cs);
            return ret;
        }
    }

    /* HTTP_NULL_ID means accept any request */
    
    /* First check if any connection is immediately available */
    conn = find_available_connection(queue, TRUE);  /* Mark as unavailable when found */
    if (conn)
    {
        TRACE("Found immediately available connection %p\n", conn);
        ret = complete_irp(conn, irp);
        LeaveCriticalSection(&http_cs);
        return ret;
    }
    
    /* No request available, queue the IRP for later completion */
    TRACE("No requests available, queuing IRP %p\n", irp);
    
    IoSetCancelRoutine(irp, http_receive_request_cancel);
    if (irp->Cancel && !IoSetCancelRoutine(irp, NULL))
    {
        /* The IRP was canceled before we set the cancel routine. */
        ret = STATUS_CANCELLED;
    }
    else
    {
        /* Add IRP to queue - it will be completed when a request arrives */
        IoMarkIrpPending(irp);
        InsertTailList(&queue->irp_queue, &irp->Tail.Overlay.ListEntry);
        
        /* Update statistics if Phase 1 is implemented */
        InterlockedIncrement(&queue->pending_irp_count);
        
        TRACE("IRP %p queued, queue now has %ld pending receive IRPs\n",
              irp, queue->pending_irp_count);
        
        ret = STATUS_PENDING;
    }

    LeaveCriticalSection(&http_cs);

    return ret;
}

static NTSTATUS http_send_response(struct request_queue *queue, IRP *irp)
{
    const struct http_response *response = irp->AssociatedIrp.SystemBuffer;
    struct connection *conn;
    const char *auth_header = "WWW-Authenticate:";
    const size_t auth_header_len = 17;
    const char *found, *p, *end, *headers_end;
    size_t headers_len;
    bool is_401_auth = false;

    TRACE("id %s, len %d, flags 0x%08x (DISCONNECT=%d, MORE_DATA=%d).\n", wine_dbgstr_longlong(response->id), response->len, response->response_flags, !!(response->response_flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT), !!(response->response_flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA));

    EnterCriticalSection(&http_cs);

    if ((conn = get_connection(response->id)))
    {
        const char *buf = response->buffer;
        int len = response->len;
        char *patched = NULL;
        int patched_len = 0;

        /* For upgraded WebSocket connections, treat subsequent sends as WebSocket data */
        if (conn->is_websocket)
        {
            DWORD sent_len = 0;
            if (len > 0)
            {
                TRACE("WS pass-through: sending %d bytes as WebSocket binary frame\n", len);
                if (send_websocket_frame(conn, WS_OPCODE_BINARY, (const unsigned char *)buf, len))
                {
                    sent_len = len;
                    irp->IoStatus.Information = sent_len;
                    LeaveCriticalSection(&http_cs);
                    return STATUS_SUCCESS;
                }
                else
                {
                    WARN("Failed to send WS frame; closing connection\n");
                    close_connection(conn);
                    LeaveCriticalSection(&http_cs);
                    return STATUS_CONNECTION_RESET;
                }
            }
            /* No body payload; honor DISCONNECT by sending a close */
            if (response->response_flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT)
            {
                TRACE("WS pass-through: DISCONNECT flag set, sending close frame\n");
                send_close_frame(conn, WS_CLOSE_NORMAL, NULL);
                close_connection(conn);
            }
            LeaveCriticalSection(&http_cs);
            return STATUS_SUCCESS;
        }

        /* Inject missing WebSocket headers for 101 responses (server-side fix) */
        if (len >= 12 && !memcmp(buf, "HTTP/1.", 7) && !memcmp(buf + 8, " 101", 4))
        {
            /* Find end of headers */
            const char *headers_end = NULL;
            if (len >= 4)
            {
                const char *scan = buf;
                const char *scan_end = buf + len - 3;
                while (scan < scan_end)
                {
                    if (!memcmp(scan, "\r\n\r\n", 4)) { headers_end = scan; break; }
                    scan++;
                }
            }
            
            {
            size_t hdr_len = headers_end ? (size_t)(headers_end - buf) : (size_t)len;
            /* Check if critical WebSocket headers already present */
            BOOL have_accept = FALSE, have_upgrade = FALSE, have_connection = FALSE, have_protocol = FALSE;
            if (hdr_len > 0)
            {
                const char *p = buf;
                const char *end_scan = buf + hdr_len;
                while (p + 1 < end_scan)
                {
                    if (!_strnicmp(p, "Sec-WebSocket-Accept:", 21)) have_accept = TRUE;
                    else if (!_strnicmp(p, "Upgrade:", 8)) have_upgrade = TRUE;
                    else if (!_strnicmp(p, "Connection:", 11)) have_connection = TRUE;
                    else if (!_strnicmp(p, "Sec-WebSocket-Protocol:", 23)) have_protocol = TRUE;
                    /* advance to next line */
                    while (p < end_scan && *p != '\n') p++;
                    if (p < end_scan) p++;
                }
            }

            if ((!have_accept || !have_upgrade || !have_connection || (!have_protocol && conn->sec_ws_protocol[0])) && conn->sec_ws_key[0])
            {
                /* Compute Sec-WebSocket-Accept = base64( SHA1(key + GUID) ) */
                static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                unsigned char hash[20];
                /* Minimal SHA1 implementation */
                {
                    sha1_ctx c; sha1_init(&c);
                    sha1_update(&c, (const unsigned char *)conn->sec_ws_key, strlen(conn->sec_ws_key));
                    sha1_update(&c, (const unsigned char *)guid, sizeof(guid) - 1);
                    sha1_final(&c, hash);
                }
                /* Base64 encode (no CRLF) */
                {
                    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    char accept[64]; size_t j = 0; size_t i;
                    for (i = 0; i < sizeof(hash) && j + 4 < sizeof(accept); i += 3)
                    {
                        unsigned int v = hash[i] << 16;
                        if (i + 1 < sizeof(hash)) v |= hash[i+1] << 8;
                        if (i + 2 < sizeof(hash)) v |= hash[i+2];
                        accept[j++] = b64[(v >> 18) & 0x3f];
                        accept[j++] = b64[(v >> 12) & 0x3f];
                        accept[j++] = (i + 1 < sizeof(hash)) ? b64[(v >> 6) & 0x3f] : '=';
                        accept[j++] = (i + 2 < sizeof(hash)) ? b64[v & 0x3f] : '=';
                    }
                    accept[j] = '\0';
                    if (!headers_end) headers_end = buf + len; /* fallback */
                    {
                        const char *insertion = headers_end;
                        char extra[512];
                        int extra_len = 0;
                        BOOL add_u = FALSE, add_c = FALSE, add_a = FALSE, add_p = FALSE;
                        if (!have_upgrade) { extra_len += snprintf(extra + extra_len, sizeof(extra) - extra_len, "Upgrade: websocket\r\n"); add_u = TRUE; }
                        if (!have_connection) { extra_len += snprintf(extra + extra_len, sizeof(extra) - extra_len, "Connection: Upgrade\r\n"); add_c = TRUE; }
                        if (!have_accept) { extra_len += snprintf(extra + extra_len, sizeof(extra) - extra_len, "Sec-WebSocket-Accept: %s\r\n", accept); add_a = TRUE; }
                        if (!have_protocol && conn->sec_ws_protocol[0])
                        { extra_len += snprintf(extra + extra_len, sizeof(extra) - extra_len, "Sec-WebSocket-Protocol: %s\r\n", conn->sec_ws_protocol); add_p = TRUE; }
                        if (!have_upgrade || !have_connection || !have_accept)
                        {
                            /* Build canonical 101 response */
                            char header[1024];
                            int hdr_len = 0;
                            hdr_len += snprintf(header + hdr_len, sizeof(header) - hdr_len, "HTTP/1.1 101 Switching Protocols\r\n");
                            hdr_len += snprintf(header + hdr_len, sizeof(header) - hdr_len, "Upgrade: websocket\r\n");
                            hdr_len += snprintf(header + hdr_len, sizeof(header) - hdr_len, "Connection: Upgrade\r\n");
                            hdr_len += snprintf(header + hdr_len, sizeof(header) - hdr_len, "Sec-WebSocket-Accept: %s\r\n", accept);
                            if (conn->sec_ws_protocol[0])
                                hdr_len += snprintf(header + hdr_len, sizeof(header) - hdr_len, "Sec-WebSocket-Protocol: %s\r\n", conn->sec_ws_protocol);
                            hdr_len += snprintf(header + hdr_len, sizeof(header) - hdr_len, "\r\n");

                            patched_len = hdr_len;
                            patched = malloc(patched_len);
                            if (patched)
                                memcpy(patched, header, hdr_len);
                        }
                        else if (extra_len > 0)
                        {
                            patched_len = len + extra_len;
                            patched = malloc(patched_len);
                            if (patched)
                            {
                                size_t pre = (size_t)(insertion - buf);
                                memcpy(patched, buf, pre);
                                memcpy(patched + pre, extra, extra_len);
                                memcpy(patched + pre + extra_len, insertion, len - pre);
                            }
                        }
                        if (patched)
                        {
                            /* Log port and path to pinpoint endpoint */
                            {
                                unsigned short local_port = 0;
                                SOCKADDR_STORAGE addr;
                                int alen = sizeof(addr);
                                if (!getsockname(conn->socket, (struct sockaddr *)&addr, &alen))
                                {
                                    if (((struct sockaddr *)&addr)->sa_family == AF_INET)
                                        local_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
                                    else if (((struct sockaddr *)&addr)->sa_family == AF_INET6)
                                        local_port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
                                }
                                TRACE("Injected Sec-WebSocket-Accept into 101 (server-side), port=%u, path=%s, key=%s, accept=%s\n",
                                      local_port,
                                      debugstr_an(conn->url, conn->url_len),
                                      debugstr_a(conn->sec_ws_key),
                                      debugstr_a(accept));
                                /* Also log final 101 header block for diagnostics */
                                {
                                    const char *ph_end = NULL;
                                    for (const char *sp = patched; sp + 3 < patched + patched_len; ++sp)
                                    {
                                        if (!memcmp(sp, "\r\n\r\n", 4)) { ph_end = sp; break; }
                                    }
                                    if (ph_end)
                                    {
                                        int hlen = (int)(ph_end - patched);
                                        TRACE("Final 101 headers (first block):\n%.*s\n", hlen, patched);
                                    }
                                }
                            }
                            
                                /* Upgrade connection to WebSocket mode */
                                conn->is_websocket = TRUE;
                                conn->ws_passthrough = FALSE; /* Use internal frame parsing for server-side */
                                /* Signal availability so pending RECEIVE_REQUEST can complete */
                                conn->available = TRUE;
                                /* Keep req_id mapping for upgraded connection so app can read body */
                                try_complete_irp(conn);
                            conn->ws_last_activity = GetTickCount64();
                            
                            /* Allocate WebSocket buffer */
                            conn->ws_buf_size = 65536; /* Start with 64KB */
                            conn->ws_buffer = malloc(conn->ws_buf_size);
                            if (!conn->ws_buffer)
                            {
                                ERR("Failed to allocate WebSocket buffer\n");
                                /* Note: Connection will be closed later due to allocation failure */
                            }
                            else
                            {
                                {
                                    unsigned short local_port2 = 0;
                                    SOCKADDR_STORAGE addr2;
                                    int alen2 = sizeof(addr2);
                                    if (!getsockname(conn->socket, (struct sockaddr *)&addr2, &alen2))
                                    {
                                        if (((struct sockaddr *)&addr2)->sa_family == AF_INET)
                                            local_port2 = ntohs(((struct sockaddr_in *)&addr2)->sin_port);
                                        else if (((struct sockaddr *)&addr2)->sa_family == AF_INET6)
                                            local_port2 = ntohs(((struct sockaddr_in6 *)&addr2)->sin6_port);
                                    }
                                    TRACE("Connection upgraded to WebSocket mode (port=%u, path=%s)\n",
                                          local_port2, debugstr_an(conn->url, conn->url_len));
                                }
                                
                                /* Check for remaining data in HTTP buffer and move to WebSocket buffer */
                                if (conn->len > 0)
                                {
                                    TRACE("Buffer has %u bytes after upgrade, moving to WebSocket buffer\n", conn->len);
                                    if (conn->len <= conn->ws_buf_size)
                                    {
                                        memcpy(conn->ws_buffer, conn->buffer, conn->len);
                                        conn->ws_buf_len = conn->len;
                                        conn->len = 0;  /* Clear HTTP buffer */
                                        
                                        /* Try to process as WebSocket frames */
                                        process_websocket_frames(conn);
                                    }
                                    else
                                    {
                                        WARN("Leftover data too large for WebSocket buffer\n");
                                        close_connection(conn);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            }  /* Close the C90 block */
        }

        if (patched)
        {
            if (send(conn->socket, patched, patched_len, 0) >= 0)
            {
                free(patched);
                goto post_send;
            }
            free(patched);
            /* fallback to original on failure */
        }

        if (send(conn->socket, buf, len, 0) >= 0)
        {
post_send:
            /* In http_send_response(), after successfully sending response */
            {
                /* Find and complete the request entry */
                LIST_ENTRY *cur;
                struct request_entry *entry;
                
                for (cur = queue->request_list.Flink; cur != &queue->request_list; cur = cur->Flink)
                {
                    entry = CONTAINING_RECORD(cur, struct request_entry, entry);
                    if (entry->conn == conn && entry->state == REQ_STATE_PROCESSING)
                    {
                        set_request_state(queue, entry, REQ_STATE_COMPLETED);
                        /* Could free immediately or leave for cleanup */
                        break;
                    }
                }
                
                /* Periodically clean old entries */
                if (queue->completed_count % 100 == 0)
                    cleanup_old_requests(queue);
            }
            
            /* Handle connection based on response flags and state */
            if (response->response_flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT)
            {
                /* Client requested to close the connection */
                TRACE("Closing connection due to DISCONNECT flag.\n");
                conn->response_state = CONN_RESP_BODY_COMPLETE;
                conn->req_id = HTTP_NULL_ID;
                conn->queue = NULL;
                close_connection(conn);
            }
            else if (!(response->response_flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
            {
                TRACE("MORE_DATA flag NOT set, response_state=%d\n", conn->response_state);

                /* State-based handling: mimics native Windows HTTP.sys behavior */
                if (conn->response_state == CONN_RESP_IDLE)
                {
                    /* First call (headers sent) - keep req_id valid for HttpSendResponseEntityBody */
                    TRACE("Response headers sent, setting state to HEADERS_SENT, keeping req_id=%s valid\n",
                          wine_dbgstr_longlong(conn->req_id));
                    conn->response_state = CONN_RESP_HEADERS_SENT;
                    conn->response_start_time = GetTickCount64();
                }
                else if (conn->response_state == CONN_RESP_HEADERS_SENT)
                {
                    /* Subsequent call (body sent) - now we can clear req_id */
                    TRACE("Response body sent, setting state to BODY_COMPLETE, clearing req_id=%s\n",
                          wine_dbgstr_longlong(conn->req_id));
                    conn->response_state = CONN_RESP_BODY_COMPLETE;
                }
                else
                {
                    /* Already complete or unexpected state */
                    TRACE("Response in state %d, no state change needed\n", conn->response_state);
                }

                /* Check if this is a 401 Unauthorized response for NTLM authentication */
                is_401_auth = false;
                /* Accept both HTTP/1.0 and HTTP/1.1 401 responses */
                if (response->len >= 12 && !memcmp(response->buffer, "HTTP/1.", 7) && 
                    !memcmp(response->buffer + 8, " 401", 4))
                {
                    TRACE("401 Unauthorized response detected, checking for auth headers (response_len=%d)\n", response->len);
                    /* Search for WWW-Authenticate header in headers only (before \r\n\r\n) */
                    /* Find end of headers manually since memmem is not available */
                    headers_end = NULL;
                    if (response->len >= 4)
                    {
                        const char *scan = response->buffer;
                        const char *scan_end = response->buffer + response->len - 3;
                        while (scan < scan_end)
                        {
                            if (!memcmp(scan, "\r\n\r\n", 4))
                            {
                                headers_end = scan;
                                break;
                            }
                            scan++;
                        }
                    }
                    headers_len = headers_end ? (size_t)(headers_end - response->buffer) : response->len;
                    
                    found = NULL;
                    if (headers_len >= auth_header_len)
                    {
                        /* Case-insensitive search for WWW-Authenticate header */
                        p = response->buffer;
                        end = response->buffer + headers_len - auth_header_len + 1;
                        while (p < end)
                        {
                            if (!_strnicmp(p, auth_header, auth_header_len))
                            {
                                found = p;
                                TRACE("Found WWW-Authenticate header at offset %ld\n", (long)(p - response->buffer));
                                break;
                            }
                            p++;
                        }
                    }
                    if (found)
                    {
                        is_401_auth = true;
                        TRACE("401 auth detected: Keeping connection state for authentication challenge (conn=%p, socket=%#Ix)\n",
                              conn, (ULONG_PTR)conn->socket);
                    }
                    else
                    {
                        TRACE("401 response without WWW-Authenticate header, treating as normal response\n");
                    }
                }
                else
                {
                    TRACE("Non-401 response or too short to be 401 (len=%d)\n", response->len);
                }
                
                /* No more data for this response, but keep connection alive for potential pipelining */
                if (conn->content_len)
                {
                    /* Discard whatever entity body is left. */
                    memmove(conn->buffer, conn->buffer + conn->content_len, conn->len - conn->content_len);
                    conn->len -= conn->content_len;
                }

                /* For 401 auth challenges, keep the queue and request association */
                if (!is_401_auth)
                {
                    /* For upgraded WebSocket connections, keep mapping for subsequent reads. */
                    if (!conn->is_websocket)
                    {
                        /* Only clear req_id when response is fully complete (body sent) */
                        if (conn->response_state == CONN_RESP_BODY_COMPLETE)
                        {
                            TRACE("Response complete, clearing req_id=%s and queue\n", wine_dbgstr_longlong(conn->req_id));
                            conn->queue = NULL;
                            conn->req_id = HTTP_NULL_ID;
                        }
                        else if (conn->response_state == CONN_RESP_HEADERS_SENT)
                        {
                            /* Headers sent but body pending - keep req_id for HttpSendResponseEntityBody */
                            TRACE("Headers sent, keeping req_id=%s valid for entity body (state=HEADERS_SENT)\n",
                                  wine_dbgstr_longlong(conn->req_id));
                        }
                    }
                    WSAEventSelect(conn->socket, request_event, FD_READ | FD_CLOSE);
                }
                else
                {
                    /* Keep FD_CLOSE enabled but handle auth gracefully */
                    /* This allows detection of client disconnects while still supporting auth retries */
                    if (WSAEventSelect(conn->socket, request_event, FD_READ | FD_CLOSE) == SOCKET_ERROR)
                    {
                        ERR("WSAEventSelect failed with error %u for 401 auth; closing connection.\n", WSAGetLastError());
                        TRACE("Failed to set socket events for auth: socket=%#Ix, conn=%p\n", (ULONG_PTR)conn->socket, conn);
                        close_connection(conn);
                    }
                    else
                    {
                        TRACE("401 response: Monitoring FD_READ and FD_CLOSE events (balanced approach)\n");
                        /* Set authentication timeout tracking */
                        conn->auth_in_progress = true;
                        conn->auth_start_time = GetTickCount64();
                        TRACE("Started auth timeout tracking: conn=%p, start_time=%llu, timeout=%u ms\n",
                              conn, conn->auth_start_time, AUTH_TIMEOUT_MS);
                        /* Note: FD_CLOSE during auth will be handled gracefully in receive_data() */
                    }
                }

                /* For 401 auth responses during WebSocket upgrades, don't immediately parse */
                /* Let the client send its retry with Authorization header first */
                if (!is_401_auth)
                {
                    /* Only mark available and parse next request when response is fully complete */
                    if (conn->response_state == CONN_RESP_BODY_COMPLETE)
                    {
                        TRACE("Response complete, checking buffer for pipelined requests\n");

                        /* Mark connection as available again for request processing */
                        conn->available = TRUE;

                        /* We might have another request already in the buffer (HTTP pipelining). */
                        if (parse_request(conn) < 0)
                        {
                            WARN("Failed to parse request; shutting down connection.\n");
                            send_400(conn);
                        }
                        else if (conn->available)
                        {
                            TRACE("Successfully parsed next request from buffer (available=%d)\n", conn->available);
                        }
                    }
                    else if (conn->response_state == CONN_RESP_HEADERS_SENT)
                    {
                        TRACE("Headers sent but body pending, NOT marking available yet\n");
                        /* Don't mark available - waiting for HttpSendResponseEntityBody */
                    }
                }
                else
                {
                    TRACE("401 auth response sent, waiting for client retry with credentials\n");
                    /* Don't call parse_request() here - wait for FD_READ event when client sends retry */
                }
                
                /* After sending response, check if we already have a pipelined request.
                   If not, wait for next request but don't call complete_pending_irps */
            }
            else
            {
                TRACE("MORE_DATA flag IS set, keeping connection state: conn=%p, req_id=%s, queue=%p (expecting HttpSendResponseEntityBody call)\n", conn, wine_dbgstr_longlong(conn->req_id), conn->queue);
            }
            irp->IoStatus.Information = response->len;

            /* Don't complete the IRP here - let caller handle it */
            /* This function is called synchronously, so just return status */

            LeaveCriticalSection(&http_cs);
            return STATUS_SUCCESS;
        }
        else
        {
            ERR("Got error %u; shutting down connection.\n", WSAGetLastError());
            close_connection(conn);

            /* Set error status but don't complete - let caller handle it */
            irp->IoStatus.Status = STATUS_CONNECTION_RESET;
            irp->IoStatus.Information = 0;

            LeaveCriticalSection(&http_cs);
            return STATUS_CONNECTION_RESET;
        }
    }

    /* Connection not found - set error but don't complete */
    irp->IoStatus.Status = STATUS_CONNECTION_INVALID;
    irp->IoStatus.Information = 0;

    LeaveCriticalSection(&http_cs);
    return STATUS_CONNECTION_INVALID;
}

/* Cancel routine for queued WS pass-through RECEIVE_BODY IRPs */
static void WINAPI http_receive_body_ws_cancel(DEVICE_OBJECT *device, IRP *irp);

static NTSTATUS http_receive_body(struct request_queue *queue, IRP *irp)
{
    const struct http_receive_body_params *params = irp->AssociatedIrp.SystemBuffer;
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(irp);
    const DWORD output_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
    struct connection *conn;
    NTSTATUS ret;

    TRACE("id %s, bits %lu.\n", wine_dbgstr_longlong(params->id), params->bits);

    EnterCriticalSection(&http_cs);

    if ((conn = get_connection(params->id)))
    {
        /* For WebSocket connections, deliver bytes to app */
        if (conn->is_websocket)
        {
            /* Prefer parsed application buffer if available */
            DWORD available = (DWORD)((conn->ws_app_in.len > conn->ws_app_in.read_off) ? (conn->ws_app_in.len - conn->ws_app_in.read_off) : 0);
            if (available)
            {
                DWORD to_copy = min(available, output_len);
                memcpy(irp->AssociatedIrp.SystemBuffer, conn->ws_app_in.data + conn->ws_app_in.read_off, to_copy);
                conn->ws_app_in.read_off += to_copy;
                if (conn->ws_app_in.read_off >= conn->ws_app_in.len)
                {
                    conn->ws_app_in.len = 0;
                    conn->ws_app_in.read_off = 0;
                }
                TRACE("WS deliver: delivering %lu bytes to app (queued before=%lu)\n", to_copy, available);
                irp->IoStatus.Information = to_copy;
                LeaveCriticalSection(&http_cs);
                return STATUS_SUCCESS;
            }
            /* No bytes available yet; queue IRP for completion when data arrives */
            TRACE("WS deliver: queueing RECEIVE_BODY IRP (no data yet)\n");
            IoSetCancelRoutine(irp, http_receive_body_ws_cancel);
            if (irp->Cancel && !IoSetCancelRoutine(irp, NULL)) ret = STATUS_CANCELLED;
            else {
                irp->Tail.Overlay.DriverContext[0] = conn;
                IoMarkIrpPending(irp);
                InsertTailList(&conn->ws_recv_irp_queue, &irp->Tail.Overlay.ListEntry);
                LeaveCriticalSection(&http_cs);
                return STATUS_PENDING;
            }
            LeaveCriticalSection(&http_cs);
            return ret;
        }

        TRACE("%lu bits remaining.\n", conn->content_len);

        if (conn->content_len)
        {
            ULONG len = min(conn->content_len, output_len);
            memcpy(irp->AssociatedIrp.SystemBuffer, conn->buffer, len);
            memmove(conn->buffer, conn->buffer + len, conn->len - len);
            conn->content_len -= len;
            conn->len -= len;

            irp->IoStatus.Information = len;
            ret = STATUS_SUCCESS;
        }
        else
            ret = STATUS_END_OF_FILE;
    }
    else
        ret = STATUS_CONNECTION_INVALID;

    LeaveCriticalSection(&http_cs);

    return ret;
}

static NTSTATUS WINAPI dispatch_ioctl(DEVICE_OBJECT *device, IRP *irp)
{
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(irp);
    struct request_queue *queue = stack->FileObject->FsContext;
    NTSTATUS ret;

    TRACE("IOCTL code=0x%lx, in_len=%lu, out_len=%lu\n",
          stack->Parameters.DeviceIoControl.IoControlCode,
          stack->Parameters.DeviceIoControl.InputBufferLength,
          stack->Parameters.DeviceIoControl.OutputBufferLength);

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_HTTP_ADD_URL:
        TRACE("IOCTL_HTTP_ADD_URL\n");
        ret = http_add_url(queue, irp);
        break;
    case IOCTL_HTTP_REMOVE_URL:
        TRACE("IOCTL_HTTP_REMOVE_URL\n");
        ret = http_remove_url(queue, irp);
        break;
    case IOCTL_HTTP_RECEIVE_REQUEST:
        TRACE("IOCTL_HTTP_RECEIVE_REQUEST\n");
        ret = http_receive_request(queue, irp);
        break;
    case IOCTL_HTTP_SEND_RESPONSE:
        TRACE("IOCTL_HTTP_SEND_RESPONSE\n");
        ret = http_send_response(queue, irp);
        break;
    case IOCTL_HTTP_SEND_RESPONSE_ENTITY_BODY:
        TRACE("IOCTL_HTTP_SEND_RESPONSE_ENTITY_BODY\n");
        /* Reuse http_send_response handler since our buffer format matches */
        ret = http_send_response(queue, irp);
        break;
    case IOCTL_HTTP_RECEIVE_BODY:
        TRACE("IOCTL_HTTP_RECEIVE_BODY\n");
        ret = http_receive_body(queue, irp);
        break;
    case IOCTL_HTTP_WAIT_FOR_DISCONNECT:
        TRACE("IOCTL_HTTP_WAIT_FOR_DISCONNECT\n");
        {
            const struct http_wait_for_disconnect_params *params = irp->AssociatedIrp.SystemBuffer;
            struct connection *conn;
            
            TRACE("IOCTL_HTTP_WAIT_FOR_DISCONNECT: connection_id %s.\n", wine_dbgstr_longlong(params->id));

            EnterCriticalSection(&http_cs);

            if ((conn = get_connection_by_id(params->id)))
            {
                TRACE("Found connection %p with conn_id=%s, req_id=%s\n",
                      conn, wine_dbgstr_longlong(conn->conn_id), wine_dbgstr_longlong(conn->req_id));
                /* If connection is already shutting down, complete immediately */
                if (conn->shutdown)
                {
                    LeaveCriticalSection(&http_cs);
                    ret = STATUS_SUCCESS;
                }
                else
                {
                    /* Queue this IRP to be completed on disconnect */
                    IoSetCancelRoutine(irp, http_wait_for_disconnect_cancel);
                    if (irp->Cancel && !IoSetCancelRoutine(irp, NULL))
                    {
                        /* The IRP was canceled before we set the cancel routine. */
                        LeaveCriticalSection(&http_cs);
                        ret = STATUS_CANCELLED;
                    }
                    else
                    {
                        IoMarkIrpPending(irp);
                        InsertTailList(&conn->wait_queue, &irp->Tail.Overlay.ListEntry);
                        LeaveCriticalSection(&http_cs);
                        ret = STATUS_PENDING;
                    }
                }
            }
            else
            {
                LeaveCriticalSection(&http_cs);
                ret = STATUS_CONNECTION_INVALID;
            }
        }
        break;
    case IOCTL_HTTP_CANCEL_REQUEST:
        {
            const struct http_cancel_request_params *params = irp->AssociatedIrp.SystemBuffer;
            struct connection *conn;
            BOOL found = FALSE;
            
            TRACE("IOCTL_HTTP_CANCEL_REQUEST: id %s.\n", wine_dbgstr_longlong(params->id));
            
            EnterCriticalSection(&http_cs);
            
            /* Find the connection with this request ID */
            if ((conn = get_connection(params->id)))
            {
                /* Check if there's a pending receive request IRP in the queue */
                struct request_queue *queue = conn->queue;
                if (queue)
                {
                    LIST_ENTRY *entry = queue->irp_queue.Flink;
                    while (entry != &queue->irp_queue)
                    {
                        LIST_ENTRY *next = entry->Flink;
                        IRP *pending_irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
                        struct http_receive_request_params *pending_params = pending_irp->AssociatedIrp.SystemBuffer;
                        
                        if (pending_params->id == params->id)
                        {
                            /* Found the IRP to cancel */
                            RemoveEntryList(&pending_irp->Tail.Overlay.ListEntry);
                            if (IoSetCancelRoutine(pending_irp, NULL))
                            {
                                pending_irp->IoStatus.Status = STATUS_CANCELLED;
                                pending_irp->IoStatus.Information = 0;
                                IoCompleteRequest(pending_irp, IO_NO_INCREMENT);
                            }
                            found = TRUE;
                            break;
                        }
                        entry = next;
                    }
                }
                
                /* Also mark the connection as no longer having a pending request */
                if (found || conn->req_id == params->id)
                {
                    conn->available = FALSE;
                    conn->req_id = HTTP_NULL_ID;
                    conn->response_state = CONN_RESP_IDLE;
                    ret = STATUS_SUCCESS;
                }
                else
                {
                    ret = STATUS_NOT_FOUND;
                }
            }
            else
            {
                ret = STATUS_CONNECTION_INVALID;
            }
            
            LeaveCriticalSection(&http_cs);
        }
        break;
    default:
        FIXME("Unhandled ioctl %#lx.\n", stack->Parameters.DeviceIoControl.IoControlCode);
        ret = STATUS_NOT_IMPLEMENTED;
    }

    if (ret != STATUS_PENDING)
    {
        irp->IoStatus.Status = ret;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    return ret;
}

static NTSTATUS WINAPI dispatch_create(DEVICE_OBJECT *device, IRP *irp)
{
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(irp);
    struct request_queue *queue;

    if (!(queue = calloc(1, sizeof(*queue))))
        return STATUS_NO_MEMORY;
    list_init(&queue->urls);
    stack->FileObject->FsContext = queue;
    InitializeListHead(&queue->irp_queue);
    
    /* NEW: Initialize statistics and request list */
    queue->pending_irp_count = 0;
    queue->pending_request_count = 0;
    queue->processing_count = 0;
    queue->completed_count = 0;
    InitializeListHead(&queue->request_list);

    EnterCriticalSection(&http_cs);
    list_add_head(&request_queues, &queue->entry);
    LeaveCriticalSection(&http_cs);

    TRACE("Created queue %p with state tracking.\n", queue);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static void close_queue(struct request_queue *queue)
{
    struct url *url, *url_next;
    struct listening_socket *listening_sock, *listening_sock_next;
    LIST_ENTRY *cur, *next;

    EnterCriticalSection(&http_cs);
    list_remove(&queue->entry);

    LIST_FOR_EACH_ENTRY_SAFE(url, url_next, &queue->urls, struct url, entry)
    {
        free(url->url);
        free(url);
    }

    LIST_FOR_EACH_ENTRY_SAFE(listening_sock, listening_sock_next, &listening_sockets, struct listening_socket, entry)
    {
        shutdown(listening_sock->socket, SD_BOTH);
        closesocket(listening_sock->socket);
        list_remove(&listening_sock->entry);
        free(listening_sock);
    }

    /* Free all request entries to prevent memory leak */
    for (cur = queue->request_list.Flink; 
         cur != &queue->request_list; 
         cur = next)
    {
        struct request_entry *e;
        next = cur->Flink;
        e = CONTAINING_RECORD(cur, struct request_entry, entry);
        RemoveEntryList(&e->entry);
        e->in_list = FALSE;  /* Clear list membership flag */
        if (e->allocated) free(e);
    }
    
    /* Cancel any pending IRPs to prevent hanging threads */
    while (!IsListEmpty(&queue->irp_queue))
    {
        LIST_ENTRY *entry = RemoveHeadList(&queue->irp_queue);
        IRP *irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        irp->IoStatus.Status = STATUS_CANCELLED;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    free(queue);

    LeaveCriticalSection(&http_cs);
}

static NTSTATUS WINAPI dispatch_close(DEVICE_OBJECT *device, IRP *irp)
{
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(irp);
    struct request_queue *queue = stack->FileObject->FsContext;
    LIST_ENTRY *entry;

    TRACE("Closing queue %p.\n", queue);

    EnterCriticalSection(&http_cs);

    while ((entry = queue->irp_queue.Flink) != &queue->irp_queue)
    {
        IRP *queued_irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        IoCancelIrp(queued_irp);
    }

    LeaveCriticalSection(&http_cs);

    close_queue(queue);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static void WINAPI unload(DRIVER_OBJECT *driver)
{
    struct request_queue *queue, *queue_next;
    struct connection *conn, *conn_next;

    thread_stop = TRUE;
    SetEvent(request_event);
    WaitForSingleObject(request_thread, INFINITE);
    CloseHandle(request_thread);
    CloseHandle(request_event);

    LIST_FOR_EACH_ENTRY_SAFE(conn, conn_next, &connections, struct connection, entry)
    {
        close_connection(conn);
    }

    LIST_FOR_EACH_ENTRY_SAFE(queue, queue_next, &request_queues, struct request_queue, entry)
    {
        close_queue(queue);
    }

    WSACleanup();

    IoDeleteDevice(device_obj);
    NtClose(directory_obj);
}

NTSTATUS WINAPI DriverEntry(DRIVER_OBJECT *driver, UNICODE_STRING *path)
{
    OBJECT_ATTRIBUTES attr = {sizeof(attr)};
    UNICODE_STRING device_http = RTL_CONSTANT_STRING(L"\\Device\\Http");
    UNICODE_STRING device_http_req_queue = RTL_CONSTANT_STRING(L"\\Device\\Http\\ReqQueue");
    WSADATA wsadata;
    NTSTATUS ret;

    TRACE("driver %p, path %s.\n", driver, debugstr_w(path->Buffer));

    attr.ObjectName = &device_http;
    if ((ret = NtCreateDirectoryObject(&directory_obj, 0, &attr)) && ret != STATUS_OBJECT_NAME_COLLISION)
        ERR("Failed to create \\Device\\Http directory, status %#lx.\n", ret);

    if ((ret = IoCreateDevice(driver, 0, &device_http_req_queue, FILE_DEVICE_UNKNOWN, 0, FALSE, &device_obj)))
    {
        ERR("Failed to create request queue device, status %#lx.\n", ret);
        NtClose(directory_obj);
        return ret;
    }

    driver->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
    driver->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ioctl;
    driver->DriverUnload = unload;

    WSAStartup(MAKEWORD(1,1), &wsadata);

    request_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    request_thread = CreateThread(NULL, 0, request_thread_proc, NULL, 0, NULL);

    return STATUS_SUCCESS;
}
static void WINAPI http_receive_body_ws_cancel(DEVICE_OBJECT *device, IRP *irp)
{
    struct connection *conn;
    
    TRACE("cancel WS receive body irp %p.\n", irp);
    IoReleaseCancelSpinLock(irp->CancelIrql);
    EnterCriticalSection(&http_cs);
    /* Find connection from DriverContext */
    conn = irp->Tail.Overlay.DriverContext[0];
    if (conn)
    {
        RemoveEntryList(&irp->Tail.Overlay.ListEntry);
    }
    LeaveCriticalSection(&http_cs);
    irp->IoStatus.Status = STATUS_CANCELLED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}
