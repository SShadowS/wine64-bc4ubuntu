/*
 * Tests for HTTP API improvements
 * Testing modified procedures: HttpSendResponseEntityBody, HttpWaitForDisconnect, HttpCancelHttpRequest
 *
 * Copyright 2025 Wine Contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "http.h"

#include "wine/test.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

static ULONG (WINAPI *pHttpSendResponseEntityBody)(HANDLE queue, HTTP_REQUEST_ID id, ULONG flags, 
    USHORT count, HTTP_DATA_CHUNK *chunks, ULONG *ret_size, void *reserved1, ULONG reserved2, 
    OVERLAPPED *ovl, HTTP_LOG_DATA *log_data);
static ULONG (WINAPI *pHttpWaitForDisconnect)(HANDLE queue, HTTP_CONNECTION_ID connection_id, OVERLAPPED *ovl);
static ULONG (WINAPI *pHttpWaitForDisconnectEx)(HANDLE queue, HTTP_CONNECTION_ID connection_id, ULONG reserved, OVERLAPPED *ovl);
static ULONG (WINAPI *pHttpCancelHttpRequest)(HANDLE queue, HTTP_REQUEST_ID id, OVERLAPPED *ovl);

static void init_functions(void)
{
    HMODULE mod = GetModuleHandleA("httpapi.dll");

#define X(f) p##f = (void *)GetProcAddress(mod, #f)
    X(HttpSendResponseEntityBody);
    X(HttpWaitForDisconnect);
    X(HttpWaitForDisconnectEx);
    X(HttpCancelHttpRequest);
#undef X
}

static const char test_req[] =
    "GET /test HTTP/1.1\r\n"
    "Host: localhost:%u\r\n"
    "Connection: keep-alive\r\n"
    "User-Agent: Wine-Test\r\n"
    "\r\n";

static SOCKET create_test_socket(unsigned short port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.S_un.S_addr = inet_addr("127.0.0.1"),
    };
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    int ret;
    
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;
        
    ret = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (ret)
    {
        closesocket(s);
        return INVALID_SOCKET;
    }
    
    return s;
}

static unsigned short find_free_port(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.S_un.S_addr = inet_addr("127.0.0.1"),
    };
    unsigned short port;
    int ret;
    
    for (port = 50000; port < 51000; port++)
    {
        addr.sin_port = htons(port);
        ret = bind(s, (struct sockaddr *)&addr, sizeof(addr));
        if (!ret)
        {
            closesocket(s);
            return port;
        }
    }
    
    closesocket(s);
    return 0;
}

static void test_HttpSendResponseEntityBody(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HANDLE queue = NULL;
    HTTP_DATA_CHUNK chunks[2];
    ULONG ret, ret_size;
    OVERLAPPED ovl = {};
    char buffer[1024];
    unsigned short port;
    WCHAR url[256];
    SOCKET client;
    HTTP_REQUEST *request;
    char req_buffer[4096];
    
    if (!pHttpSendResponseEntityBody)
    {
        win_skip("HttpSendResponseEntityBody not available\n");
        return;
    }
    
    trace("Testing HttpSendResponseEntityBody...\n");
    
    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(!ret, "HttpInitialize failed: %lu\n", ret);
    
    ret = HttpCreateRequestQueue(version, NULL, NULL, 0, &queue);
    ok(!ret, "HttpCreateRequestQueue failed: %lu\n", ret);
    
    port = find_free_port();
    ok(port != 0, "Failed to find free port\n");
    
    swprintf(url, ARRAY_SIZE(url), L"http://localhost:%u/", port);
    ret = HttpAddUrl(queue, url, NULL);
    ok(!ret || ret == ERROR_ACCESS_DENIED, "HttpAddUrl failed: %lu\n", ret);
    
    if (ret == ERROR_ACCESS_DENIED)
    {
        skip("Need admin rights to add URL\n");
        goto cleanup;
    }
    
    /* Test 1: Send entity body without MORE_DATA flag */
    trace("Test 1: Entity body without MORE_DATA flag\n");
    
    client = create_test_socket(port);
    ok(client != INVALID_SOCKET, "Failed to create client socket\n");
    
    sprintf(buffer, test_req, port);
    send(client, buffer, strlen(buffer), 0);
    
    request = (HTTP_REQUEST *)req_buffer;
    ret = HttpReceiveHttpRequest(queue, HTTP_NULL_ID, 0, request, sizeof(req_buffer), NULL, NULL);
    ok(!ret, "HttpReceiveHttpRequest failed: %lu\n", ret);
    
    /* Send response headers first */
    HTTP_RESPONSE response;
    memset(&response, 0, sizeof(response));
    response.s.StatusCode = 200;
    response.s.pReason = "OK";
    response.s.ReasonLength = 2;
    response.s.Headers.KnownHeaders[HttpHeaderContentLength].pRawValue = "10";
    response.s.Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength = 2;
    
    ret = HttpSendHttpResponse(queue, request->s.RequestId, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 
                               &response, NULL, NULL, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendHttpResponse failed: %lu\n", ret);
    
    /* Now send entity body */
    chunks[0].DataChunkType = HttpDataChunkFromMemory;
    chunks[0].FromMemory.pBuffer = (void *)"Test body1";
    chunks[0].FromMemory.BufferLength = 10;
    
    ret = pHttpSendResponseEntityBody(queue, request->s.RequestId, 0, 1, chunks, &ret_size, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendResponseEntityBody failed: %lu\n", ret);
    ok(ret_size == 10, "Expected ret_size 10, got %lu\n", ret_size);
    
    /* Receive response on client */
    ret = recv(client, buffer, sizeof(buffer), 0);
    ok(ret > 0, "recv failed\n");
    ok(strstr(buffer, "200 OK") != NULL, "Response header not found\n");
    ok(strstr(buffer, "Test body1") != NULL, "Response body not found\n");
    
    closesocket(client);
    
    /* Test 2: Send entity body with MORE_DATA flag (chunked response) */
    trace("Test 2: Entity body with MORE_DATA flag (chunked)\n");
    
    client = create_test_socket(port);
    ok(client != INVALID_SOCKET, "Failed to create client socket\n");
    
    sprintf(buffer, test_req, port);
    send(client, buffer, strlen(buffer), 0);
    
    ret = HttpReceiveHttpRequest(queue, HTTP_NULL_ID, 0, request, sizeof(req_buffer), NULL, NULL);
    ok(!ret, "HttpReceiveHttpRequest failed: %lu\n", ret);
    
    /* Send response headers with MORE_DATA */
    response.s.StatusCode = 200;
    response.s.Headers.KnownHeaders[HttpHeaderContentLength].pRawValue = NULL;
    response.s.Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength = 0;
    
    ret = HttpSendHttpResponse(queue, request->s.RequestId, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 
                               &response, NULL, NULL, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendHttpResponse failed: %lu\n", ret);
    
    /* Send first chunk with MORE_DATA */
    chunks[0].DataChunkType = HttpDataChunkFromMemory;
    chunks[0].FromMemory.pBuffer = (void *)"Chunk1";
    chunks[0].FromMemory.BufferLength = 6;
    
    ret = pHttpSendResponseEntityBody(queue, request->s.RequestId, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 
                                     1, chunks, &ret_size, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendResponseEntityBody with MORE_DATA failed: %lu\n", ret);
    
    /* Send final chunk without MORE_DATA */
    chunks[0].FromMemory.pBuffer = (void *)"Chunk2";
    chunks[0].FromMemory.BufferLength = 6;
    
    ret = pHttpSendResponseEntityBody(queue, request->s.RequestId, 0, 1, chunks, &ret_size, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendResponseEntityBody final chunk failed: %lu\n", ret);
    
    closesocket(client);
    
    /* Test 3: Test with multiple chunks */
    trace("Test 3: Multiple chunks in single call\n");
    
    client = create_test_socket(port);
    ok(client != INVALID_SOCKET, "Failed to create client socket\n");
    
    sprintf(buffer, test_req, port);
    send(client, buffer, strlen(buffer), 0);
    
    ret = HttpReceiveHttpRequest(queue, HTTP_NULL_ID, 0, request, sizeof(req_buffer), NULL, NULL);
    ok(!ret, "HttpReceiveHttpRequest failed: %lu\n", ret);
    
    /* Send response headers */
    ret = HttpSendHttpResponse(queue, request->s.RequestId, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 
                               &response, NULL, NULL, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendHttpResponse failed: %lu\n", ret);
    
    /* Send multiple chunks */
    chunks[0].DataChunkType = HttpDataChunkFromMemory;
    chunks[0].FromMemory.pBuffer = (void *)"Part1-";
    chunks[0].FromMemory.BufferLength = 6;
    
    chunks[1].DataChunkType = HttpDataChunkFromMemory;
    chunks[1].FromMemory.pBuffer = (void *)"Part2";
    chunks[1].FromMemory.BufferLength = 5;
    
    ret = pHttpSendResponseEntityBody(queue, request->s.RequestId, 0, 2, chunks, &ret_size, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendResponseEntityBody multiple chunks failed: %lu\n", ret);
    ok(ret_size == 11, "Expected ret_size 11, got %lu\n", ret_size);
    
    closesocket(client);
    
    /* Test 4: Test with overlapped I/O */
    trace("Test 4: Overlapped I/O\n");
    
    client = create_test_socket(port);
    ok(client != INVALID_SOCKET, "Failed to create client socket\n");
    
    sprintf(buffer, test_req, port);
    send(client, buffer, strlen(buffer), 0);
    
    ret = HttpReceiveHttpRequest(queue, HTTP_NULL_ID, 0, request, sizeof(req_buffer), NULL, NULL);
    ok(!ret, "HttpReceiveHttpRequest failed: %lu\n", ret);
    
    /* Send response headers */
    ret = HttpSendHttpResponse(queue, request->s.RequestId, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 
                               &response, NULL, NULL, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendHttpResponse failed: %lu\n", ret);
    
    /* Send entity body with overlapped */
    ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    chunks[0].DataChunkType = HttpDataChunkFromMemory;
    chunks[0].FromMemory.pBuffer = (void *)"Async body";
    chunks[0].FromMemory.BufferLength = 10;
    
    ret = pHttpSendResponseEntityBody(queue, request->s.RequestId, 0, 1, chunks, NULL, NULL, 0, &ovl, NULL);
    ok(ret == ERROR_IO_PENDING || !ret, "HttpSendResponseEntityBody overlapped returned %lu\n", ret);
    
    if (ret == ERROR_IO_PENDING)
    {
        DWORD wait_result = WaitForSingleObject(ovl.hEvent, 1000);
        ok(wait_result == WAIT_OBJECT_0, "Wait failed: %lu\n", wait_result);
    }
    
    CloseHandle(ovl.hEvent);
    closesocket(client);
    
    HttpRemoveUrl(queue, url);
    
cleanup:
    if (queue)
        HttpCloseRequestQueue(queue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
}

static void test_HttpWaitForDisconnect(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HANDLE queue = NULL;
    HTTP_CONNECTION_ID conn_id = 12345; /* Test connection ID */
    OVERLAPPED ovl = {};
    ULONG ret;
    
    if (!pHttpWaitForDisconnect)
    {
        win_skip("HttpWaitForDisconnect not available\n");
        return;
    }
    
    trace("Testing HttpWaitForDisconnect...\n");
    
    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(!ret, "HttpInitialize failed: %lu\n", ret);
    
    ret = HttpCreateRequestQueue(version, NULL, NULL, 0, &queue);
    ok(!ret, "HttpCreateRequestQueue failed: %lu\n", ret);
    
    /* Test 1: Test with invalid parameters */
    trace("Test 1: Invalid parameters\n");
    
    ret = pHttpWaitForDisconnect(NULL, conn_id, NULL);
    ok(ret == ERROR_INVALID_PARAMETER, "Expected ERROR_INVALID_PARAMETER, got %lu\n", ret);
    
    ret = pHttpWaitForDisconnect(queue, 0, NULL);
    ok(ret == ERROR_INVALID_PARAMETER, "Expected ERROR_INVALID_PARAMETER, got %lu\n", ret);
    
    /* Test 2: Test with non-existent connection (should return NO_ERROR) */
    trace("Test 2: Non-existent connection\n");
    
    ret = pHttpWaitForDisconnect(queue, conn_id, NULL);
    ok(ret == NO_ERROR || ret == ERROR_INVALID_FUNCTION, 
       "Expected NO_ERROR or ERROR_INVALID_FUNCTION, got %lu\n", ret);
    
    /* Test 3: Test with overlapped I/O */
    trace("Test 3: Overlapped I/O\n");
    
    ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ret = pHttpWaitForDisconnect(queue, conn_id, &ovl);
    ok(ret == ERROR_IO_PENDING || ret == NO_ERROR || ret == ERROR_INVALID_FUNCTION, 
       "Expected ERROR_IO_PENDING, NO_ERROR, or ERROR_INVALID_FUNCTION, got %lu\n", ret);
    
    if (ret == ERROR_IO_PENDING)
    {
        /* Cancel the pending operation */
        CancelIo(queue);
        WaitForSingleObject(ovl.hEvent, 100);
    }
    
    CloseHandle(ovl.hEvent);
    
    /* Test 4: Test HttpWaitForDisconnectEx if available */
    if (pHttpWaitForDisconnectEx)
    {
        trace("Test 4: HttpWaitForDisconnectEx\n");
        
        /* Test with reserved parameter */
        ret = pHttpWaitForDisconnectEx(queue, conn_id, 12345, NULL);
        ok(ret == NO_ERROR || ret == ERROR_INVALID_FUNCTION, 
       "HttpWaitForDisconnectEx failed: %lu\n", ret);
        
        /* Test with overlapped */
        ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        ret = pHttpWaitForDisconnectEx(queue, conn_id, 0, &ovl);
        ok(ret == ERROR_IO_PENDING || ret == NO_ERROR || ret == ERROR_INVALID_FUNCTION, 
           "Expected ERROR_IO_PENDING, NO_ERROR, or ERROR_INVALID_FUNCTION, got %lu\n", ret);
        
        if (ret == ERROR_IO_PENDING)
        {
            CancelIo(queue);
            WaitForSingleObject(ovl.hEvent, 100);
        }
        
        CloseHandle(ovl.hEvent);
    }
    
    HttpCloseRequestQueue(queue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
}

static void test_HttpCancelHttpRequest(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HANDLE queue = NULL;
    HTTP_REQUEST_ID req_id = 12345; /* Test request ID */
    OVERLAPPED ovl = {};
    ULONG ret;
    
    if (!pHttpCancelHttpRequest)
    {
        win_skip("HttpCancelHttpRequest not available\n");
        return;
    }
    
    trace("Testing HttpCancelHttpRequest...\n");
    
    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(!ret, "HttpInitialize failed: %lu\n", ret);
    
    ret = HttpCreateRequestQueue(version, NULL, NULL, 0, &queue);
    ok(!ret, "HttpCreateRequestQueue failed: %lu\n", ret);
    
    /* Test 1: Test with invalid parameters */
    trace("Test 1: Invalid parameters\n");
    
    ret = pHttpCancelHttpRequest(NULL, req_id, NULL);
    ok(ret == ERROR_INVALID_PARAMETER, "Expected ERROR_INVALID_PARAMETER, got %lu\n", ret);
    
    ret = pHttpCancelHttpRequest(queue, 0, NULL);
    ok(ret == ERROR_INVALID_PARAMETER, "Expected ERROR_INVALID_PARAMETER, got %lu\n", ret);
    
    /* Test 2: Cancel non-existent request */
    trace("Test 2: Non-existent request\n");
    
    ret = pHttpCancelHttpRequest(queue, req_id, NULL);
    ok(ret == ERROR_CONNECTION_INVALID || ret == NO_ERROR || ret == ERROR_INVALID_FUNCTION, 
       "Expected ERROR_CONNECTION_INVALID, NO_ERROR, or ERROR_INVALID_FUNCTION, got %lu\n", ret);
    
    /* Test 3: Test with overlapped I/O */
    trace("Test 3: Overlapped I/O\n");
    
    ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ret = pHttpCancelHttpRequest(queue, req_id, &ovl);
    ok(ret == ERROR_IO_PENDING || ret == ERROR_CONNECTION_INVALID || ret == NO_ERROR || ret == ERROR_INVALID_FUNCTION,
       "Expected ERROR_IO_PENDING, ERROR_CONNECTION_INVALID, NO_ERROR, or ERROR_INVALID_FUNCTION, got %lu\n", ret);
    
    if (ret == ERROR_IO_PENDING)
    {
        WaitForSingleObject(ovl.hEvent, 100);
    }
    
    CloseHandle(ovl.hEvent);
    
    /* Test 4: Cancel with actual pending request */
    trace("Test 4: Cancel actual pending request\n");
    {
        /* Start an async receive that we'll cancel */
        char req_buffer[4096];
        HTTP_REQUEST *request = (HTTP_REQUEST *)req_buffer;
        DWORD wait_result;
        DWORD bytes;
        BOOL result;
        
        ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    
        ret = HttpReceiveHttpRequest(queue, HTTP_NULL_ID, 0, request, sizeof(req_buffer), NULL, &ovl);
        ok(ret == ERROR_IO_PENDING, "Expected ERROR_IO_PENDING, got %lu\n", ret);
        
        /* Now cancel it using the queue handle (cancels all pending on this queue) */
        CancelIo(queue);
        
        wait_result = WaitForSingleObject(ovl.hEvent, 1000);
        ok(wait_result == WAIT_OBJECT_0, "Wait failed: %lu\n", wait_result);
        
        result = GetOverlappedResult(queue, &ovl, &bytes, FALSE);
        ok(!result, "Expected GetOverlappedResult to fail\n");
        ok(GetLastError() == ERROR_OPERATION_ABORTED, "Expected ERROR_OPERATION_ABORTED, got %lu\n", GetLastError());
        
        CloseHandle(ovl.hEvent);
    }
    
    HttpCloseRequestQueue(queue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
}

static void test_response_flags(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HANDLE queue = NULL;
    ULONG ret;
    unsigned short port;
    WCHAR url[256];
    SOCKET client;
    char buffer[4096];
    HTTP_REQUEST *request = (HTTP_REQUEST *)buffer;
    HTTP_RESPONSE response;
    char req_text[256];
    memset(&response, 0, sizeof(response));
    
    trace("Testing HTTP_SEND_RESPONSE_FLAG_MORE_DATA handling...\n");
    
    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(!ret, "HttpInitialize failed: %lu\n", ret);
    
    ret = HttpCreateRequestQueue(version, NULL, NULL, 0, &queue);
    ok(!ret, "HttpCreateRequestQueue failed: %lu\n", ret);
    
    port = find_free_port();
    ok(port != 0, "Failed to find free port\n");
    
    swprintf(url, ARRAY_SIZE(url), L"http://localhost:%u/", port);
    ret = HttpAddUrl(queue, url, NULL);
    
    if (ret == ERROR_ACCESS_DENIED)
    {
        skip("Need admin rights to test response flags\n");
        goto cleanup;
    }
    ok(!ret, "HttpAddUrl failed: %lu\n", ret);
    
    /* Test 1: Response without MORE_DATA should include Content-Length */
    trace("Test 1: Response without MORE_DATA\n");
    
    client = create_test_socket(port);
    ok(client != INVALID_SOCKET, "Failed to create client socket\n");
    
    sprintf(req_text, test_req, port);
    send(client, req_text, strlen(req_text), 0);
    
    ret = HttpReceiveHttpRequest(queue, HTTP_NULL_ID, 0, request, sizeof(buffer), NULL, NULL);
    ok(!ret, "HttpReceiveHttpRequest failed: %lu\n", ret);
    
    response.s.StatusCode = 200;
    response.s.pReason = "OK";
    response.s.ReasonLength = 2;
    
    /* Send response without body and without MORE_DATA - should auto-add Content-Length: 0 */
    ret = HttpSendHttpResponse(queue, request->s.RequestId, 0, &response, NULL, NULL, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendHttpResponse failed: %lu\n", ret);
    
    ret = recv(client, buffer, sizeof(buffer), 0);
    ok(ret > 0, "recv failed\n");
    ok(strstr(buffer, "Content-Length: 0") != NULL, "Content-Length header not found\n");
    
    closesocket(client);
    
    /* Test 2: Response with MORE_DATA should not include Content-Length */
    trace("Test 2: Response with MORE_DATA\n");
    
    client = create_test_socket(port);
    ok(client != INVALID_SOCKET, "Failed to create client socket\n");
    
    sprintf(req_text, test_req, port);
    send(client, req_text, strlen(req_text), 0);
    
    ret = HttpReceiveHttpRequest(queue, HTTP_NULL_ID, 0, request, sizeof(buffer), NULL, NULL);
    ok(!ret, "HttpReceiveHttpRequest failed: %lu\n", ret);
    
    /* Send response with MORE_DATA - should not add Content-Length */
    ret = HttpSendHttpResponse(queue, request->s.RequestId, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 
                               &response, NULL, NULL, NULL, 0, NULL, NULL);
    ok(!ret, "HttpSendHttpResponse with MORE_DATA failed: %lu\n", ret);
    
    ret = recv(client, buffer, sizeof(buffer), 0);
    if (ret > 0)
    {
        ok(strstr(buffer, "Content-Length") == NULL, "Content-Length header found with MORE_DATA\n");
    }
    
    closesocket(client);
    
    HttpRemoveUrl(queue, url);
    
cleanup:
    if (queue)
        HttpCloseRequestQueue(queue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
}

START_TEST(httpapi_improvements)
{
    WSADATA wsadata;
    
    init_functions();
    
    if (WSAStartup(MAKEWORD(2, 2), &wsadata))
    {
        skip("Failed to initialize Winsock\n");
        return;
    }
    
    test_HttpSendResponseEntityBody();
    test_HttpWaitForDisconnect();
    test_HttpCancelHttpRequest();
    test_response_flags();
    
    WSACleanup();
}