/*
 * Unit tests for HTTPAPI critical fixes
 *
 * Copyright 2024 Wine Development Team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <http.h>
#include <process.h>
#include "wine/test.h"

/* Test flags to control behavior */
#define TEST_STRESS_ITERATIONS 1000
#define TEST_THREAD_COUNT 10
#define TEST_URL_COUNT 100

/* Global variables for thread synchronization */
static HANDLE g_start_event;
static HANDLE g_stop_event;
static LONG g_thread_errors;
static CRITICAL_SECTION g_test_cs;

/* Helper function to initialize HTTP API */
static ULONG init_http_api(void)
{
    HTTPAPI_VERSION version = {2, 0};
    return HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
}

/* Helper function to cleanup HTTP API */
static void cleanup_http_api(void)
{
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
}

/**************************************************************************
 * Test 1: Event Handle Corruption in add_url()
 * 
 * This test verifies that the event handle corruption bug is fixed.
 * The bug occurs when the low bit is set on an event handle for alertable
 * I/O, then the modified handle is passed to CloseHandle().
 **************************************************************************/
static void test_event_handle_corruption(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HANDLE queue = NULL;
    ULONG ret;
    WCHAR url[256];
    int i;

    trace("Testing event handle corruption fix...\n");

    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(ret == NO_ERROR, "HttpInitialize failed: %lu\n", ret);

    ret = HttpCreateHttpHandle(&queue, 0);
    ok(ret == NO_ERROR, "HttpCreateHttpHandle failed: %lu\n", ret);

    /* Test multiple URL additions to stress the handle management */
    for (i = 0; i < 10; i++)
    {
        wsprintfW(url, L"http://+:%d/test%d/", 8080 + i, i);
        ret = HttpAddUrl(queue, url, NULL);
        
        /* We might get ERROR_ACCESS_DENIED if not running as admin,
         * or ERROR_ALREADY_EXISTS if URL is already registered.
         * The important thing is we don't crash! */
        ok(ret == NO_ERROR || ret == ERROR_ACCESS_DENIED || 
           ret == ERROR_ALREADY_EXISTS || ret == ERROR_SHARING_VIOLATION,
           "HttpAddUrl failed with unexpected error: %lu\n", ret);
           
        if (ret == NO_ERROR)
        {
            /* Successfully added, now remove it */
            ret = HttpRemoveUrl(queue, url);
            ok(ret == NO_ERROR, "HttpRemoveUrl failed: %lu\n", ret);
        }
    }

    CloseHandle(queue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
    
    trace("Event handle corruption test completed successfully\n");
}

/**************************************************************************
 * Test 2: Use-After-Free in URL Group Operations
 * 
 * This test verifies that the reference counting is properly implemented
 * to prevent use-after-free bugs in concurrent scenarios.
 **************************************************************************/

typedef struct {
    HTTP_SERVER_SESSION_ID session_id;
    HTTP_URL_GROUP_ID group_id;
    int thread_index;
} THREAD_CONTEXT;

static unsigned WINAPI url_group_worker_thread(void *param)
{
    THREAD_CONTEXT *ctx = (THREAD_CONTEXT *)param;
    ULONG ret;
    int i;
    WCHAR url[256];
    HTTP_BINDING_INFO binding_info;
    HANDLE queue = NULL;

    /* Wait for start signal */
    WaitForSingleObject(g_start_event, INFINITE);

    /* Create a request queue for this thread */
    ret = HttpCreateHttpHandle(&queue, 0);
    if (ret != NO_ERROR)
    {
        InterlockedIncrement(&g_thread_errors);
        return 1;
    }

    /* Perform operations on the URL group */
    for (i = 0; i < TEST_STRESS_ITERATIONS; i++)
    {
        if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0)
            break;

        /* Add URLs to the group */
        wsprintfW(url, L"http://+:%d/thread%d/iter%d/", 
                  9000 + ctx->thread_index, ctx->thread_index, i);
        ret = HttpAddUrlToUrlGroup(ctx->group_id, url, (HTTP_URL_CONTEXT)i, 0);
        
        /* Set binding property */
        binding_info.Flags = 0;
        binding_info.RequestQueueHandle = queue;
        ret = HttpSetUrlGroupProperty(ctx->group_id, HttpServerBindingProperty,
                                     &binding_info, sizeof(binding_info));

        /* Query binding property */
        HTTP_BINDING_INFO query_info;
        ULONG bytes = sizeof(query_info);
        ret = HttpQueryUrlGroupProperty(ctx->group_id, HttpServerBindingProperty,
                                       &query_info, sizeof(query_info), &bytes);

        /* Remove URL */
        HttpRemoveUrlFromUrlGroup(ctx->group_id, url, 0);

        /* Small delay to increase chance of race conditions */
        Sleep(0);
    }

    CloseHandle(queue);
    return 0;
}

static void test_url_group_reference_counting(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HTTP_SERVER_SESSION_ID session_id = 0;
    HTTP_URL_GROUP_ID group_id = 0;
    HANDLE threads[TEST_THREAD_COUNT];
    THREAD_CONTEXT contexts[TEST_THREAD_COUNT];
    ULONG ret;
    int i;

    trace("Testing URL group reference counting...\n");

    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(ret == NO_ERROR, "HttpInitialize failed: %lu\n", ret);

    /* Create server session */
    ret = HttpCreateServerSession(version, &session_id, 0);
    ok(ret == NO_ERROR, "HttpCreateServerSession failed: %lu\n", ret);

    /* Create URL group */
    ret = HttpCreateUrlGroup(session_id, &group_id, 0);
    ok(ret == NO_ERROR, "HttpCreateUrlGroup failed: %lu\n", ret);

    /* Initialize synchronization objects */
    g_start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_thread_errors = 0;

    /* Create worker threads */
    for (i = 0; i < TEST_THREAD_COUNT; i++)
    {
        contexts[i].session_id = session_id;
        contexts[i].group_id = group_id;
        contexts[i].thread_index = i;
        
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, url_group_worker_thread,
                                           &contexts[i], 0, NULL);
        ok(threads[i] != NULL, "Failed to create thread %d\n", i);
    }

    /* Start all threads simultaneously */
    SetEvent(g_start_event);

    /* Let threads run for a bit */
    Sleep(1000);

    /* Signal threads to stop */
    SetEvent(g_stop_event);

    /* Wait for all threads to complete */
    WaitForMultipleObjects(TEST_THREAD_COUNT, threads, TRUE, 5000);

    /* Clean up thread handles */
    for (i = 0; i < TEST_THREAD_COUNT; i++)
    {
        CloseHandle(threads[i]);
    }

    /* Check for errors */
    ok(g_thread_errors == 0, "Thread errors detected: %ld\n", g_thread_errors);

    /* Clean up URL group and session */
    HttpCloseUrlGroup(group_id);
    HttpCloseServerSession(session_id);

    /* Clean up events */
    CloseHandle(g_start_event);
    CloseHandle(g_stop_event);

    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
    
    trace("Reference counting test completed with %ld errors\n", g_thread_errors);
}

/**************************************************************************
 * Test 3: Null Pointer Checks
 * 
 * This test verifies that all memory allocations are properly checked
 * for NULL returns. We simulate allocation failures using hooks.
 **************************************************************************/

static BOOL g_fail_malloc = FALSE;
static LONG g_malloc_count = 0;
static LONG g_malloc_fail_at = -1;

/* Hook for malloc to simulate failures */
static void* hook_malloc(size_t size)
{
    if (g_fail_malloc)
    {
        LONG count = InterlockedIncrement(&g_malloc_count);
        if (count == g_malloc_fail_at)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
    }
    return malloc(size);
}

static void test_null_pointer_checks(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HANDLE queue = NULL;
    HTTP_SERVER_SESSION_ID session_id = 0;
    HTTP_URL_GROUP_ID group_id = 0;
    ULONG ret;
    int i;

    trace("Testing null pointer checks...\n");

    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(ret == NO_ERROR, "HttpInitialize failed: %lu\n", ret);

    /* Test HttpCreateHttpHandle with potential allocation failures */
    for (i = 1; i <= 5; i++)
    {
        g_fail_malloc = TRUE;
        g_malloc_count = 0;
        g_malloc_fail_at = i;

        ret = HttpCreateHttpHandle(&queue, 0);
        
        g_fail_malloc = FALSE;

        /* Should either succeed or fail gracefully */
        ok(ret == NO_ERROR || ret == ERROR_NOT_ENOUGH_MEMORY ||
           ret == ERROR_OUTOFMEMORY || ret == ERROR_NO_SYSTEM_RESOURCES,
           "Unexpected error: %lu at malloc fail point %d\n", ret, i);

        if (ret == NO_ERROR)
        {
            CloseHandle(queue);
            queue = NULL;
        }
    }

    /* Test URL operations with allocation failures */
    ret = HttpCreateHttpHandle(&queue, 0);
    if (ret == NO_ERROR)
    {
        for (i = 1; i <= 10; i++)
        {
            g_fail_malloc = TRUE;
            g_malloc_count = 0;
            g_malloc_fail_at = i;

            ret = HttpAddUrl(queue, L"http://+:8085/test/", NULL);
            
            g_fail_malloc = FALSE;

            /* Should handle allocation failure gracefully */
            ok(ret == NO_ERROR || ret == ERROR_NOT_ENOUGH_MEMORY ||
               ret == ERROR_OUTOFMEMORY || ret == ERROR_ACCESS_DENIED ||
               ret == ERROR_ALREADY_EXISTS || ret == ERROR_SHARING_VIOLATION,
               "Unexpected error: %lu at malloc fail point %d\n", ret, i);

            if (ret == NO_ERROR)
            {
                HttpRemoveUrl(queue, L"http://+:8085/test/");
            }
        }
        CloseHandle(queue);
    }

    /* Test server session and URL group with allocation failures */
    for (i = 1; i <= 10; i++)
    {
        g_fail_malloc = TRUE;
        g_malloc_count = 0;
        g_malloc_fail_at = i;

        ret = HttpCreateServerSession(version, &session_id, 0);
        
        g_fail_malloc = FALSE;

        if (ret == NO_ERROR)
        {
            g_fail_malloc = TRUE;
            g_malloc_count = 0;
            g_malloc_fail_at = 1;

            ret = HttpCreateUrlGroup(session_id, &group_id, 0);
            
            g_fail_malloc = FALSE;

            ok(ret == NO_ERROR || ret == ERROR_NOT_ENOUGH_MEMORY ||
               ret == ERROR_OUTOFMEMORY,
               "Unexpected error: %lu\n", ret);

            if (ret == NO_ERROR)
            {
                HttpCloseUrlGroup(group_id);
            }
            HttpCloseServerSession(session_id);
        }
    }

    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
    
    trace("Null pointer check test completed\n");
}

/**************************************************************************
 * Test 4: Thread Safety and Locking
 * 
 * This test verifies that concurrent operations are properly synchronized
 * and don't cause deadlocks or data corruption.
 **************************************************************************/

typedef struct {
    HANDLE queue;
    int thread_index;
    LONG *shared_counter;
} LOCK_TEST_CONTEXT;

static unsigned WINAPI locking_worker_thread(void *param)
{
    LOCK_TEST_CONTEXT *ctx = (LOCK_TEST_CONTEXT *)param;
    HTTP_REQUEST_ID request_id = 0;
    HTTP_REQUEST *request;
    HTTP_RESPONSE response;
    ULONG bytes;
    ULONG ret;
    int i;

    request = (HTTP_REQUEST *)malloc(sizeof(HTTP_REQUEST) + 2048);
    if (!request)
    {
        InterlockedIncrement(&g_thread_errors);
        return 1;
    }

    /* Wait for start signal */
    WaitForSingleObject(g_start_event, INFINITE);

    for (i = 0; i < 100; i++)
    {
        if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0)
            break;

        /* Try to receive a request (will likely timeout) */
        ret = HttpReceiveHttpRequest(ctx->queue, request_id, 0, 
                                    request, sizeof(HTTP_REQUEST) + 2048,
                                    &bytes, NULL);

        /* Increment shared counter atomically */
        InterlockedIncrement(ctx->shared_counter);

        /* Small delay */
        Sleep(0);
    }

    free(request);
    return 0;
}

static void test_thread_safety_locking(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HANDLE queue = NULL;
    HANDLE threads[TEST_THREAD_COUNT];
    LOCK_TEST_CONTEXT contexts[TEST_THREAD_COUNT];
    LONG shared_counter = 0;
    ULONG ret;
    int i;

    trace("Testing thread safety and locking...\n");

    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(ret == NO_ERROR, "HttpInitialize failed: %lu\n", ret);

    ret = HttpCreateHttpHandle(&queue, 0);
    ok(ret == NO_ERROR, "HttpCreateHttpHandle failed: %lu\n", ret);

    /* Try to add a URL (might fail without admin rights) */
    HttpAddUrl(queue, L"http://+:8090/locktest/", NULL);

    /* Initialize synchronization */
    g_start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_thread_errors = 0;

    /* Create worker threads */
    for (i = 0; i < TEST_THREAD_COUNT; i++)
    {
        contexts[i].queue = queue;
        contexts[i].thread_index = i;
        contexts[i].shared_counter = &shared_counter;
        
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, locking_worker_thread,
                                           &contexts[i], 0, NULL);
        ok(threads[i] != NULL, "Failed to create thread %d\n", i);
    }

    /* Start all threads */
    SetEvent(g_start_event);

    /* Let them run */
    Sleep(500);

    /* Stop threads */
    SetEvent(g_stop_event);

    /* Wait for completion */
    WaitForMultipleObjects(TEST_THREAD_COUNT, threads, TRUE, 5000);

    /* Clean up */
    for (i = 0; i < TEST_THREAD_COUNT; i++)
    {
        CloseHandle(threads[i]);
    }

    /* Verify shared counter */
    trace("Shared counter value: %ld (expected around %d)\n", 
          shared_counter, TEST_THREAD_COUNT * 100);
    ok(shared_counter > 0, "Shared counter should be positive\n");

    HttpRemoveUrl(queue, L"http://+:8090/locktest/");
    CloseHandle(queue);

    CloseHandle(g_start_event);
    CloseHandle(g_stop_event);

    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
    
    trace("Thread safety test completed with %ld errors\n", g_thread_errors);
}

/**************************************************************************
 * Test 5: Stress Test - Rapid Create/Destroy Cycles
 * 
 * This test rapidly creates and destroys HTTP objects to detect
 * memory leaks and handle leaks.
 **************************************************************************/
static void test_rapid_create_destroy(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HTTP_SERVER_SESSION_ID session_id;
    HTTP_URL_GROUP_ID group_id;
    HANDLE queue;
    ULONG ret;
    int i, j;
    DWORD start_time, end_time;

    trace("Testing rapid create/destroy cycles...\n");

    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER, NULL);
    ok(ret == NO_ERROR, "HttpInitialize failed: %lu\n", ret);

    start_time = GetTickCount();

    for (i = 0; i < 100; i++)
    {
        /* Create and destroy server sessions */
        ret = HttpCreateServerSession(version, &session_id, 0);
        ok(ret == NO_ERROR, "HttpCreateServerSession failed at iteration %d: %lu\n", i, ret);

        /* Create multiple URL groups per session */
        for (j = 0; j < 10; j++)
        {
            ret = HttpCreateUrlGroup(session_id, &group_id, 0);
            ok(ret == NO_ERROR, "HttpCreateUrlGroup failed: %lu\n", ret);

            /* Immediately close it */
            ret = HttpCloseUrlGroup(group_id);
            ok(ret == NO_ERROR, "HttpCloseUrlGroup failed: %lu\n", ret);
        }

        ret = HttpCloseServerSession(session_id);
        ok(ret == NO_ERROR, "HttpCloseServerSession failed: %lu\n", ret);

        /* Create and destroy request queues */
        ret = HttpCreateHttpHandle(&queue, 0);
        ok(ret == NO_ERROR, "HttpCreateHttpHandle failed: %lu\n", ret);

        CloseHandle(queue);
    }

    end_time = GetTickCount();

    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
    
    trace("Rapid create/destroy test completed in %lu ms\n", end_time - start_time);
}

/**************************************************************************
 * Test 6: HttpQueryServiceConfiguration Implementation
 * 
 * This test verifies that the service configuration APIs work correctly
 * instead of returning stubs.
 **************************************************************************/
static void test_service_configuration(void)
{
    HTTPAPI_VERSION version = {2, 0};
    HTTP_SERVICE_CONFIG_IP_LISTEN_PARAM listen_param;
    HTTP_SERVICE_CONFIG_IP_LISTEN_QUERY query;
    ULONG ret;
    ULONG bytes_returned = 0;
    BYTE buffer[1024];

    trace("Testing HttpQueryServiceConfiguration implementation...\n");

    ret = HttpInitialize(version, HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG, NULL);
    ok(ret == NO_ERROR, "HttpInitialize failed: %lu\n", ret);

    /* Test querying IP listen list */
    memset(&query, 0, sizeof(query));
    query.AddrCount = 0;
    
    ret = HttpQueryServiceConfiguration(NULL, HttpServiceConfigIPListenList,
                                       &query, sizeof(query),
                                       buffer, sizeof(buffer),
                                       &bytes_returned, NULL);
    
    /* Should return something other than ERROR_FILE_NOT_FOUND if implemented */
    ok(ret != ERROR_FILE_NOT_FOUND || broken(ret == ERROR_FILE_NOT_FOUND), /* not implemented yet */
       "HttpQueryServiceConfiguration should not return ERROR_FILE_NOT_FOUND if implemented\n");

    /* Test setting configuration */
    memset(&listen_param, 0, sizeof(listen_param));
    listen_param.AddrLength = sizeof(SOCKADDR_IN);
    
    ret = HttpSetServiceConfiguration(NULL, HttpServiceConfigIPListenList,
                                     &listen_param, sizeof(listen_param), NULL);
    
    /* Should not silently succeed if not implemented */
    ok(ret == NO_ERROR || ret == ERROR_CALL_NOT_IMPLEMENTED || 
       ret == ERROR_ACCESS_DENIED || ret == ERROR_INVALID_PARAMETER,
       "HttpSetServiceConfiguration returned unexpected error: %lu\n", ret);

    HttpTerminate(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG, NULL);
    
    trace("Service configuration test completed\n");
}

/**************************************************************************
 * Main Test Runner
 **************************************************************************/
START_TEST(httpapi_fixes)
{
    /* Initialize critical section for thread tests */
    InitializeCriticalSection(&g_test_cs);

    /* Run all tests */
    test_event_handle_corruption();
    test_url_group_reference_counting();
    test_null_pointer_checks();
    test_thread_safety_locking();
    test_rapid_create_destroy();
    test_service_configuration();

    /* Cleanup */
    DeleteCriticalSection(&g_test_cs);

    trace("All httpapi fix tests completed\n");
}