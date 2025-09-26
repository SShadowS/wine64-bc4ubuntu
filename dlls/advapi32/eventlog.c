/*
 * Win32 advapi functions
 *
 * Copyright 1995 Sven Verdoolaege
 * Copyright 1998 Juergen Schmied
 * Copyright 2003 Mike Hearn
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

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winternl.h"
#include "wmistr.h"
#define _WMI_SOURCE_
#include "evntrace.h"
#include "evntprov.h"

#include "wine/debug.h"

#include "advapi32_misc.h"

WINE_DEFAULT_DEBUG_CHANNEL(advapi);
WINE_DECLARE_DEBUG_CHANNEL(eventlog);

/* Simple in-memory event log buffer for Wine */
#define MAX_EVENTS 10000
#define EVENT_BUFFER_SIZE 512
#define WRITE_QUEUE_SIZE 1000

struct wine_event_entry
{
    DWORD event_id;
    WORD event_type;
    WORD category;
    DWORD process_id;
    DWORD thread_id;
    ULONGLONG timestamp;
    WCHAR source[64];
    WCHAR strings[384];  /* Concatenated strings */
};

/* Write queue entry for async file writes */
struct write_queue_entry
{
    char log_entry[1024];
    WCHAR log_file[MAX_PATH];
};

/* Process-local event buffer */
static struct wine_event_entry *event_buffer = NULL;
static LONG event_index = 0;

/* Async write queue */
static struct write_queue_entry *write_queue = NULL;
static LONG write_head = 0;
static LONG write_tail = 0;
static HANDLE write_thread = NULL;
static HANDLE write_event = NULL;
static volatile BOOL write_thread_running = FALSE;

static CRITICAL_SECTION event_cs;
static CRITICAL_SECTION_DEBUG event_cs_debug =
{
    0, 0, &event_cs,
    { &event_cs_debug.ProcessLocksList, &event_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": event_cs") }
};
static CRITICAL_SECTION event_cs = { &event_cs_debug, -1, 0, 0, 0, 0 };

/* Background writer thread */
static DWORD WINAPI eventlog_writer_thread(LPVOID param)
{
    TRACE_(eventlog)("Writer thread started\n");
    
    while (write_thread_running)
    {
        LONG tail, head;
        DWORD wait_result;
        
        /* Wait for events or timeout every second */
        wait_result = WaitForSingleObject(write_event, 1000);
        
        /* Process all pending writes */
        tail = write_tail;
        head = write_head;
        
        if (tail != head)
        {
            TRACE_(eventlog)("Processing writes: tail=%ld, head=%ld\n", tail, head);
        }
        
        while (tail != head)
        {
            struct write_queue_entry *entry = &write_queue[tail % WRITE_QUEUE_SIZE];
            HANDLE hFile;
            DWORD written;
            
            TRACE_(eventlog)("Writing to file: %s\n", debugstr_w(entry->log_file));
            
            /* Open file and append */
            hFile = CreateFileW(entry->log_file, FILE_APPEND_DATA, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            
            if (hFile != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(hFile, 0, NULL, FILE_END);
                WriteFile(hFile, entry->log_entry, lstrlenA(entry->log_entry), &written, NULL);
                CloseHandle(hFile);
                TRACE_(eventlog)("Wrote %lu bytes to file\n", written);
            }
            else
            {
                TRACE_(eventlog)("Failed to open file: error %lu\n", GetLastError());
            }
            
            /* Advance tail */
            tail = InterlockedIncrement(&write_tail);
            head = write_head;
        }
    }
    
    TRACE_(eventlog)("Writer thread exiting\n");
    return 0;
}

static void init_event_buffer(void)
{
    static BOOL checked_env = FALSE;
    static BOOL eventlog_enabled = FALSE;
    
    if (!checked_env)
    {
        WCHAR env_var[32];
        DWORD len;
        
        checked_env = TRUE;
        
        /* Check WINE_EVENTLOG environment variable */
        len = GetEnvironmentVariableW(L"WINE_EVENTLOG", env_var, sizeof(env_var)/sizeof(WCHAR));
        if (len > 0)
        {
            /* Enable if set to "1", "true", "yes", or "on" (case insensitive) */
            if (!lstrcmpiW(env_var, L"1") || 
                !lstrcmpiW(env_var, L"true") || 
                !lstrcmpiW(env_var, L"yes") ||
                !lstrcmpiW(env_var, L"on"))
            {
                eventlog_enabled = TRUE;
                TRACE_(eventlog)("Event log enabled via WINE_EVENTLOG environment variable\n");
            }
        }
    }
    
    /* Only initialize if enabled via environment variable */
    if (eventlog_enabled && !event_buffer)
    {
        event_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
                                sizeof(struct wine_event_entry) * MAX_EVENTS);
        write_queue = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                               sizeof(struct write_queue_entry) * WRITE_QUEUE_SIZE);
        
        /* Create write event and thread */
        write_event = CreateEventW(NULL, FALSE, FALSE, NULL);
        write_thread_running = TRUE;
        write_thread = CreateThread(NULL, 0, eventlog_writer_thread, NULL, 0, NULL);
        
        TRACE_(eventlog)("Event log buffer initialized (buffer=%p, queue=%p)\n", 
                         event_buffer, write_queue);
    }
}

/******************************************************************************
 * BackupEventLogA [ADVAPI32.@]
 *
 * Saves the event log to a backup file.
 *
 * PARAMS
 *  hEventLog        [I] Handle to event log to backup.
 *  lpBackupFileName [I] Name of the backup file.
 *
 * RETURNS
 *  Success: nonzero. File lpBackupFileName will contain the contents of
 *           hEvenLog.
 *  Failure: zero.
 */
BOOL WINAPI BackupEventLogA( HANDLE hEventLog, LPCSTR lpBackupFileName )
{
    LPWSTR backupW;
    BOOL ret;

    backupW = strdupAW(lpBackupFileName);
    ret = BackupEventLogW(hEventLog, backupW);
    free(backupW);

    return ret;
}

/******************************************************************************
 * BackupEventLogW [ADVAPI32.@]
 *
 * See BackupEventLogA.
 */
BOOL WINAPI BackupEventLogW( HANDLE hEventLog, LPCWSTR lpBackupFileName )
{
    FIXME("(%p,%s) stub\n", hEventLog, debugstr_w(lpBackupFileName));

    if (!lpBackupFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!hEventLog)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (GetFileAttributesW(lpBackupFileName) != INVALID_FILE_ATTRIBUTES)
    {
        SetLastError(ERROR_ALREADY_EXISTS);
        return FALSE;
    }

    return TRUE;
}

/******************************************************************************
 * ClearEventLogA [ADVAPI32.@]
 *
 * Clears the event log and optionally saves the log to a backup file.
 *
 * PARAMS
 *  hEvenLog         [I] Handle to event log to clear.
 *  lpBackupFileName [I] Name of the backup file.
 *
 * RETURNS
 *  Success: nonzero. if lpBackupFileName != NULL, lpBackupFileName will 
 *           contain the contents of hEvenLog and the log will be cleared.
 *  Failure: zero. Fails if the event log is empty or if lpBackupFileName
 *           exists.
 */
BOOL WINAPI ClearEventLogA( HANDLE hEventLog, LPCSTR lpBackupFileName )
{
    LPWSTR backupW;
    BOOL ret;

    backupW = strdupAW(lpBackupFileName);
    ret = ClearEventLogW(hEventLog, backupW);
    free(backupW);

    return ret;
}

/******************************************************************************
 * ClearEventLogW [ADVAPI32.@]
 *
 * See ClearEventLogA.
 */
BOOL WINAPI ClearEventLogW( HANDLE hEventLog, LPCWSTR lpBackupFileName )
{
    FIXME("(%p,%s) stub\n", hEventLog, debugstr_w(lpBackupFileName));

    if (!hEventLog)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    return TRUE;
}

/******************************************************************************
 * CloseEventLog [ADVAPI32.@]
 *
 * Closes a read handle to the event log.
 *
 * PARAMS
 *  hEventLog [I/O] Handle of the event log to close.
 *
 * RETURNS
 *  Success: nonzero
 *  Failure: zero
 */
BOOL WINAPI CloseEventLog( HANDLE hEventLog )
{
    FIXME("(%p) stub\n", hEventLog);

    if (!hEventLog)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    return TRUE;
}

/******************************************************************************
 * FlushTraceA [ADVAPI32.@]
 */
ULONG WINAPI FlushTraceA ( TRACEHANDLE hSession, LPCSTR SessionName, PEVENT_TRACE_PROPERTIES Properties )
{
    return ControlTraceA( hSession, SessionName, Properties, EVENT_TRACE_CONTROL_FLUSH );
}

/******************************************************************************
 * FlushTraceW [ADVAPI32.@]
 */
ULONG WINAPI FlushTraceW ( TRACEHANDLE hSession, LPCWSTR SessionName, PEVENT_TRACE_PROPERTIES Properties )
{
    return ControlTraceW( hSession, SessionName, Properties, EVENT_TRACE_CONTROL_FLUSH );
}


/******************************************************************************
 * DeregisterEventSource [ADVAPI32.@]
 * 
 * Closes a write handle to an event log
 *
 * PARAMS
 *  hEventLog [I/O] Handle of the event log.
 *
 * RETURNS
 *  Success: nonzero
 *  Failure: zero
 */
BOOL WINAPI DeregisterEventSource( HANDLE hEventLog )
{
    FIXME("(%p) stub\n", hEventLog);
    return TRUE;
}

/******************************************************************************
 * EnableTraceEx [ADVAPI32.@]
 */
ULONG WINAPI EnableTraceEx( LPCGUID provider, LPCGUID source, TRACEHANDLE hSession, ULONG enable,
                            UCHAR level, ULONGLONG anykeyword, ULONGLONG allkeyword, ULONG enableprop,
                            PEVENT_FILTER_DESCRIPTOR filterdesc )
{
    FIXME("(%s, %s, %s, %lu, %u, %s, %s, %lu, %p): stub\n", debugstr_guid(provider),
            debugstr_guid(source), wine_dbgstr_longlong(hSession), enable, level,
            wine_dbgstr_longlong(anykeyword), wine_dbgstr_longlong(allkeyword),
            enableprop, filterdesc);

    return ERROR_SUCCESS;
}

/******************************************************************************
 * EnableTrace [ADVAPI32.@]
 */
ULONG WINAPI EnableTrace( ULONG enable, ULONG flag, ULONG level, LPCGUID guid, TRACEHANDLE hSession )
{
    FIXME("(%ld, 0x%lx, %ld, %s, %s): stub\n", enable, flag, level,
            debugstr_guid(guid), wine_dbgstr_longlong(hSession));

    return ERROR_SUCCESS;
}

/******************************************************************************
 * GetEventLogInformation [ADVAPI32.@]
 *
 * Retrieve some information about an event log.
 *
 * PARAMS
 *  hEventLog      [I]   Handle to an open event log.
 *  dwInfoLevel    [I]   Level of information (only EVENTLOG_FULL_INFO)
 *  lpBuffer       [I/O] The buffer for the returned information
 *  cbBufSize      [I]   The size of the buffer
 *  pcbBytesNeeded [O]   The needed bytes to hold the information
 *
 * RETURNS
 *  Success: TRUE. lpBuffer will hold the information and pcbBytesNeeded shows
 *           the needed buffer size.
 *  Failure: FALSE.
 */
BOOL WINAPI GetEventLogInformation( HANDLE hEventLog, DWORD dwInfoLevel, LPVOID lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    EVENTLOG_FULL_INFORMATION *efi;

    FIXME("(%p, %ld, %p, %ld, %p) stub\n", hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);

    if (dwInfoLevel != EVENTLOG_FULL_INFO)
    {
        SetLastError(ERROR_INVALID_LEVEL);
        return FALSE;
    }

    if (!hEventLog)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (!lpBuffer || !pcbBytesNeeded)
    {
        /* FIXME: This will be handled properly when eventlog is moved
         * to a higher level
         */
        SetLastError(RPC_X_NULL_REF_POINTER);
        return FALSE;
    }

    *pcbBytesNeeded = sizeof(EVENTLOG_FULL_INFORMATION);
    if (cbBufSize < sizeof(EVENTLOG_FULL_INFORMATION))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    /* Pretend the log is not full */
    efi = (EVENTLOG_FULL_INFORMATION *)lpBuffer;
    efi->dwFull = 0;

    return TRUE;
}

/******************************************************************************
 * GetNumberOfEventLogRecords [ADVAPI32.@]
 *
 * Retrieves the number of records in an event log.
 *
 * PARAMS
 *  hEventLog       [I] Handle to an open event log.
 *  NumberOfRecords [O] Number of records in the log.
 *
 * RETURNS
 *  Success: nonzero. NumberOfRecords will contain the number of records in
 *           the log.
 *  Failure: zero
 */
BOOL WINAPI GetNumberOfEventLogRecords( HANDLE hEventLog, PDWORD NumberOfRecords )
{
    FIXME("(%p,%p) stub\n", hEventLog, NumberOfRecords);

    if (!NumberOfRecords)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!hEventLog)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    *NumberOfRecords = 0;

    return TRUE;
}

/******************************************************************************
 * GetOldestEventLogRecord [ADVAPI32.@]
 *
 * Retrieves the absolute record number of the oldest record in an even log.
 *
 * PARAMS
 *  hEventLog    [I] Handle to an open event log.
 *  OldestRecord [O] Absolute record number of the oldest record.
 *
 * RETURNS
 *  Success: nonzero. OldestRecord contains the record number of the oldest
 *           record in the log.
 *  Failure: zero 
 */
BOOL WINAPI GetOldestEventLogRecord( HANDLE hEventLog, PDWORD OldestRecord )
{
    FIXME("(%p,%p) stub\n", hEventLog, OldestRecord);

    if (!OldestRecord)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!hEventLog)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    *OldestRecord = 0;

    return TRUE;
}

/******************************************************************************
 * NotifyChangeEventLog [ADVAPI32.@]
 *
 * Enables an application to receive notification when an event is written
 * to an event log.
 *
 * PARAMS
 *  hEventLog [I] Handle to an event log.
 *  hEvent    [I] Handle to a manual-reset event object.
 *
 * RETURNS
 *  Success: nonzero
 *  Failure: zero
 */
BOOL WINAPI NotifyChangeEventLog( HANDLE hEventLog, HANDLE hEvent )
{
	FIXME("(%p,%p) stub\n", hEventLog, hEvent);
	return TRUE;
}

/******************************************************************************
 * OpenBackupEventLogA [ADVAPI32.@]
 *
 * Opens a handle to a backup event log.
 *
 * PARAMS
 *  lpUNCServerName [I] Universal Naming Convention name of the server on which
 *                      this will be performed.
 *  lpFileName      [I] Specifies the name of the backup file.
 *
 * RETURNS
 *  Success: Handle to the backup event log.
 *  Failure: NULL
 */
HANDLE WINAPI OpenBackupEventLogA( LPCSTR lpUNCServerName, LPCSTR lpFileName )
{
    LPWSTR uncnameW, filenameW;
    HANDLE handle;

    uncnameW = strdupAW(lpUNCServerName);
    filenameW = strdupAW(lpFileName);
    handle = OpenBackupEventLogW(uncnameW, filenameW);
    free(uncnameW);
    free(filenameW);

    return handle;
}

/******************************************************************************
 * OpenBackupEventLogW [ADVAPI32.@]
 *
 * See OpenBackupEventLogA.
 */
HANDLE WINAPI OpenBackupEventLogW( LPCWSTR lpUNCServerName, LPCWSTR lpFileName )
{
    FIXME("(%s,%s) stub\n", debugstr_w(lpUNCServerName), debugstr_w(lpFileName));
    
    init_event_buffer();

    if (!lpFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (lpUNCServerName && lpUNCServerName[0])
    {
        FIXME("Remote server not supported\n");
        SetLastError(RPC_S_SERVER_UNAVAILABLE);
        return NULL;
    }

    if (GetFileAttributesW(lpFileName) == INVALID_FILE_ATTRIBUTES)
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return NULL;
    }

    return (HANDLE)0xcafe0000;  /* Default to Application log */
}

/******************************************************************************
 * OpenEventLogA [ADVAPI32.@]
 *
 * Opens a handle to the specified event log.
 *
 * PARAMS
 *  lpUNCServerName [I] UNC name of the server on which the event log is
 *                      opened.
 *  lpSourceName    [I] Name of the log.
 *
 * RETURNS
 *  Success: Handle to an event log.
 *  Failure: NULL
 */
HANDLE WINAPI OpenEventLogA( LPCSTR uncname, LPCSTR source )
{
    LPWSTR uncnameW, sourceW;
    HANDLE handle;

    uncnameW = strdupAW(uncname);
    sourceW = strdupAW(source);
    handle = OpenEventLogW(uncnameW, sourceW);
    free(uncnameW);
    free(sourceW);

    return handle;
}

/******************************************************************************
 * OpenEventLogW [ADVAPI32.@]
 *
 * See OpenEventLogA.
 */
HANDLE WINAPI OpenEventLogW( LPCWSTR uncname, LPCWSTR source )
{
    FIXME("(%s,%s) stub\n", debugstr_w(uncname), debugstr_w(source));
    
    init_event_buffer();

    if (!source)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (uncname && uncname[0])
    {
        FIXME("Remote server not supported\n");
        SetLastError(RPC_S_SERVER_UNAVAILABLE);
        return NULL;
    }

    /* Return handle based on source */
    if (!wcscmp(source, L"System"))
        return (HANDLE)0xcafe0001;
    else if (!wcscmp(source, L"Security"))
        return (HANDLE)0xcafe0002;
    else
        return (HANDLE)0xcafe0000;  /* Application */
}

/******************************************************************************
 * ReadEventLogA [ADVAPI32.@]
 *
 * Reads a whole number of entries from an event log.
 *
 * PARAMS
 *  hEventLog                [I] Handle of the event log to read.
 *  dwReadFlags              [I] see MSDN doc.
 *  dwRecordOffset           [I] Log-entry record number to start at.
 *  lpBuffer                 [O] Buffer for the data read.
 *  nNumberOfBytesToRead     [I] Size of lpBuffer.
 *  pnBytesRead              [O] Receives number of bytes read.
 *  pnMinNumberOfBytesNeeded [O] Receives number of bytes required for the
 *                               next log entry.
 *
 * RETURNS
 *  Success: nonzero
 *  Failure: zero
 */
BOOL WINAPI ReadEventLogA( HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset,
    LPVOID lpBuffer, DWORD nNumberOfBytesToRead, DWORD *pnBytesRead, DWORD *pnMinNumberOfBytesNeeded )
{
    FIXME("(%p,0x%08lx,0x%08lx,%p,0x%08lx,%p,%p) stub\n", hEventLog, dwReadFlags,
          dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded);

    SetLastError(ERROR_HANDLE_EOF);
    return FALSE;
}

/******************************************************************************
 * ReadEventLogW [ADVAPI32.@]
 *
 * See ReadEventLogA.
 */
BOOL WINAPI ReadEventLogW( HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset,
    LPVOID lpBuffer, DWORD nNumberOfBytesToRead, DWORD *pnBytesRead, DWORD *pnMinNumberOfBytesNeeded )
{
    FIXME("(%p,0x%08lx,0x%08lx,%p,0x%08lx,%p,%p) stub\n", hEventLog, dwReadFlags,
          dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded);

    SetLastError(ERROR_HANDLE_EOF);
    return FALSE;
}

/******************************************************************************
 * RegisterEventSourceA [ADVAPI32.@]
 *
 * Returns a registered handle to an event log.
 *
 * PARAMS
 *  lpUNCServerName [I] UNC name of the source server.
 *  lpSourceName    [I] Specifies the name of the event source to retrieve.
 *
 * RETURNS
 *  Success: Handle to the event log.
 *  Failure: NULL. Returns ERROR_INVALID_HANDLE if lpSourceName specifies the
 *           Security event log.
 */
HANDLE WINAPI RegisterEventSourceA( LPCSTR lpUNCServerName, LPCSTR lpSourceName )
{
    UNICODE_STRING lpUNCServerNameW;
    UNICODE_STRING lpSourceNameW;
    HANDLE ret;

    FIXME("(%s,%s): stub\n", debugstr_a(lpUNCServerName), debugstr_a(lpSourceName));

    RtlCreateUnicodeStringFromAsciiz(&lpUNCServerNameW, lpUNCServerName);
    RtlCreateUnicodeStringFromAsciiz(&lpSourceNameW, lpSourceName);
    ret = RegisterEventSourceW(lpUNCServerNameW.Buffer,lpSourceNameW.Buffer);
    RtlFreeUnicodeString (&lpUNCServerNameW);
    RtlFreeUnicodeString (&lpSourceNameW);
    return ret;
}

/******************************************************************************
 * RegisterEventSourceW [ADVAPI32.@]
 *
 * See RegisterEventSourceA.
 */
HANDLE WINAPI RegisterEventSourceW( LPCWSTR lpUNCServerName, LPCWSTR lpSourceName )
{
    TRACE("(%s,%s)\n", debugstr_w(lpUNCServerName), debugstr_w(lpSourceName));
    
    init_event_buffer();
    
    /* Simple implementation - return handle based on source */
    if (lpSourceName && !wcscmp(lpSourceName, L"System"))
        return (HANDLE)0xcafe0001;
    else if (lpSourceName && !wcscmp(lpSourceName, L"Security"))
        return (HANDLE)0xcafe0002;
    else
        return (HANDLE)0xcafe0000;  /* Application */
}

/******************************************************************************
 * ReportEventA [ADVAPI32.@]
 *
 * Writes an entry at the end of an event log.
 *
 * PARAMS
 *  hEventLog   [I] Handle of an event log.
 *  wType       [I] See MSDN doc.
 *  wCategory   [I] Event category.
 *  dwEventID   [I] Event identifier.
 *  lpUserSid   [I] Current user's security identifier.
 *  wNumStrings [I] Number of insert strings in lpStrings.
 *  dwDataSize  [I] Size of event-specific raw data to write.
 *  lpStrings   [I] Buffer containing an array of string to be merged.
 *  lpRawData   [I] Buffer containing the binary data.
 *
 * RETURNS
 *  Success: nonzero. Entry was written to the log.
 *  Failure: zero.
 *
 * NOTES
 *  The ReportEvent function adds the time, the entry's length, and the
 *  offsets before storing the entry in the log. If lpUserSid != NULL, the
 *  username is also logged.
 */
BOOL WINAPI ReportEventA ( HANDLE hEventLog, WORD wType, WORD wCategory, DWORD dwEventID,
    PSID lpUserSid, WORD wNumStrings, DWORD dwDataSize, LPCSTR *lpStrings, LPVOID lpRawData)
{
    LPWSTR *wideStrArray;
    UNICODE_STRING str;
    UINT i;
    BOOL ret;

    TRACE("(%p,0x%04x,0x%04x,0x%08lx,%p,0x%04x,0x%08lx,%p,%p)\n", hEventLog,
          wType, wCategory, dwEventID, lpUserSid, wNumStrings, dwDataSize, lpStrings, lpRawData);

    if (wNumStrings == 0) return TRUE;
    if (!lpStrings) return TRUE;

    wideStrArray = malloc(sizeof(WCHAR *) * wNumStrings);
    for (i = 0; i < wNumStrings; i++)
    {
        RtlCreateUnicodeStringFromAsciiz(&str, lpStrings[i]);
        wideStrArray[i] = str.Buffer;
    }
    ret = ReportEventW(hEventLog, wType, wCategory, dwEventID, lpUserSid,
                       wNumStrings, dwDataSize, (LPCWSTR *)wideStrArray, lpRawData);
    for (i = 0; i < wNumStrings; i++)
        free(wideStrArray[i]);
    free(wideStrArray);
    return ret;
}

/******************************************************************************
 * ReportEventW [ADVAPI32.@]
 *
 * See ReportEventA.
 */
BOOL WINAPI ReportEventW( HANDLE hEventLog, WORD wType, WORD wCategory, DWORD dwEventID,
    PSID lpUserSid, WORD wNumStrings, DWORD dwDataSize, LPCWSTR *lpStrings, LPVOID lpRawData )
{
    struct wine_event_entry *event;
    LONG idx;
    UINT i;
    WCHAR *p;
    
    TRACE("(%p,0x%04x,0x%04x,0x%08lx,%p,0x%04x,0x%08lx,%p,%p)\n", hEventLog,
          wType, wCategory, dwEventID, lpUserSid, wNumStrings, dwDataSize, lpStrings, lpRawData);
    
    /* Initialize buffer if needed */
    init_event_buffer();
    
    /* Store event in local buffer for fast access */
    if (event_buffer)
    {
        EnterCriticalSection(&event_cs);
        
        idx = InterlockedIncrement(&event_index) - 1;
        if (idx >= MAX_EVENTS) 
        {
            /* Wrap around */
            idx = 0;
            InterlockedExchange(&event_index, 1);
        }
        
        event = &event_buffer[idx];
        event->event_id = dwEventID;
        event->event_type = wType;
        event->category = wCategory;
        event->timestamp = GetTickCount64();
        event->process_id = GetCurrentProcessId();
        event->thread_id = GetCurrentThreadId();
        
        /* Store source name */
        lstrcpynW(event->source, L"Wine", 64);
        
        /* Concatenate strings */
        p = event->strings;
        if (wNumStrings > 0 && lpStrings)
        {
            for (i = 0; i < wNumStrings && p < event->strings + 380; i++)
            {
                if (lpStrings[i])
                {
                    int len = lstrlenW(lpStrings[i]);
                    if (p + len < event->strings + 380)
                    {
                        lstrcpyW(p, lpStrings[i]);
                        p += len + 1;  /* Include null separator */
                    }
                }
            }
        }
        *p = 0;  /* Double null terminator */
        
        LeaveCriticalSection(&event_cs);
        
        TRACE_(eventlog)("Event %lu stored in buffer at index %ld\n", dwEventID, idx);
    }
    
    /* Queue for async file write */
    if (write_queue)
    {
        LONG head = InterlockedIncrement(&write_head) - 1;
        struct write_queue_entry *entry = &write_queue[head % WRITE_QUEUE_SIZE];
        WCHAR log_path[MAX_PATH] = {0};
        DWORD ret;
        int len;
        
        TRACE_(eventlog)("Queueing event %lu for async write (head=%ld)\n", dwEventID, head);
        
        /* Get Wine prefix path */
        ret = GetEnvironmentVariableW(L"WINEPREFIX", log_path, MAX_PATH);
        if (ret == 0 || ret >= MAX_PATH)
        {
            /* Try HOME/.wine as fallback */
            ret = GetEnvironmentVariableW(L"HOME", log_path, MAX_PATH);
            if (ret > 0 && ret < MAX_PATH)
            {
                lstrcatW(log_path, L"/.wine");
            }
            else
            {
                /* Use a hardcoded default */
                lstrcpyW(log_path, L"C:\\windows\\temp");
            }
        }
        
        /* Build log file path - use simpler path for Wine */
        if (log_path[0] == L'C' && log_path[1] == L':')
        {
            /* Windows-style path */
            lstrcpyW(entry->log_file, log_path);
            lstrcatW(entry->log_file, L"\\eventlog_");
        }
        else
        {
            /* Unix-style Wine prefix path */
            lstrcpyW(entry->log_file, log_path);
            lstrcatW(entry->log_file, L"/drive_c/windows/temp/eventlog_");
        }
        
        lstrcatW(entry->log_file, ((ULONG_PTR)hEventLog == 0xcafe0001) ? L"System" :
                                 ((ULONG_PTR)hEventLog == 0xcafe0002) ? L"Security" : L"Application");
        lstrcatW(entry->log_file, L".txt");
        
        TRACE_(eventlog)("Log file path: %s\n", debugstr_w(entry->log_file));
        
        /* Format log entry */
        len = snprintf(entry->log_entry, sizeof(entry->log_entry),
                      "[%llu] EventID=%lu Type=%d Category=%d PID=%lu TID=%lu: ",
                      (unsigned long long)GetTickCount64(), dwEventID, wType,
                      wCategory, (unsigned long)GetCurrentProcessId(), 
                      (unsigned long)GetCurrentThreadId());
        
        /* Append string data */
        if (wNumStrings > 0 && lpStrings)
        {
            for (i = 0; i < wNumStrings && i < 3; i++)
            {
                if (lpStrings[i])
                {
                    CHAR temp[256];
                    WideCharToMultiByte(CP_UTF8, 0, lpStrings[i], -1, temp, sizeof(temp), NULL, NULL);
                    len += snprintf(entry->log_entry + len, sizeof(entry->log_entry) - len, "%s ", temp);
                }
            }
        }
        lstrcatA(entry->log_entry, "\r\n");
        
        /* Signal writer thread */
        SetEvent(write_event);
    }
    
    /* Also output to debug channel for immediate visibility */
    /* Check if this is a Business Central multilingual string */
    if (wNumStrings > 0 && lpStrings && lpStrings[0])
    {
        /* Detect Business Central multilingual format: "LANG=text;LANG=text;..." */
        const WCHAR *first_str = lpStrings[0];
        BOOL is_multilingual = FALSE;
        
        /* Check if string matches pattern like "DAN=...;DEA=...;ENU=..." */
        if (wcslen(first_str) > 7)
        {
            const WCHAR *p = first_str;
            int equals_count = 0;
            int semicolon_count = 0;
            BOOL has_lang_pattern = FALSE;
            
            /* Check first 50 chars for language code pattern */
            for (int i = 0; i < 50 && p[i]; i++)
            {
                if (p[i] == L'=') equals_count++;
                if (p[i] == L';') semicolon_count++;
                
                /* Check for 3-letter lang code pattern like "ENU=" or "DEA=" */
                if (i >= 3 && p[i] == L'=' && 
                    ((p[i-3] >= L'A' && p[i-3] <= L'Z') || (p[i-3] == L';' && i > 3)) &&
                    (p[i-2] >= L'A' && p[i-2] <= L'Z') &&
                    (p[i-1] >= L'A' && p[i-1] <= L'Z'))
                {
                    has_lang_pattern = TRUE;
                }
            }
            
            /* If we have multiple lang=value pairs, it's multilingual */
            if (has_lang_pattern && equals_count >= 2 && semicolon_count >= 1)
            {
                is_multilingual = TRUE;
                TRACE_(eventlog)("Detected multilingual string (eq=%d, semi=%d, pattern=%d)\n", 
                                 equals_count, semicolon_count, has_lang_pattern);
            }
        }
        
        if (is_multilingual)
        {
            /* Extract and display only the English (ENU) version if available */
            const WCHAR *enu_start = wcsstr(first_str, L"ENU=");
            if (!enu_start)
                enu_start = wcsstr(first_str, L"ENA=");  /* Try ENA if ENU not found */
            if (!enu_start)
                enu_start = wcsstr(first_str, L"ENG=");  /* Try ENG as fallback */
                
            if (enu_start)
            {
                enu_start += 4;  /* Skip past "ENU=" */
                const WCHAR *enu_end = wcschr(enu_start, L';');
                int len = enu_end ? (enu_end - enu_start) : wcslen(enu_start);
                
                /* Log based on event type, but use TRACE for multilingual strings */
                if (wType == EVENTLOG_ERROR_TYPE || wType == EVENTLOG_WARNING_TYPE)
                {
                    /* BC uses ERROR/WARNING for normal multilingual strings, downgrade to TRACE */
                    TRACE_(eventlog)("Multilingual string (ENU): %s\n", debugstr_wn(enu_start, len));
                }
                else
                {
                    TRACE_(eventlog)("Multilingual string (ENU): %s\n", debugstr_wn(enu_start, len));
                }
            }
            else
            {
                /* No English found, show first language */
                const WCHAR *first_equals = wcschr(first_str, L'=');
                if (first_equals)
                {
                    first_equals++;
                    const WCHAR *first_semi = wcschr(first_equals, L';');
                    int len = first_semi ? (first_semi - first_equals) : wcslen(first_equals);
                    TRACE_(eventlog)("Multilingual string (first): %s\n", debugstr_wn(first_equals, len));
                }
                else
                {
                    /* Shouldn't happen, but show whole string */
                    TRACE_(eventlog)("Multilingual string: %s\n", debugstr_w(first_str));
                }
            }
            
            /* Process remaining strings if any */
            for (i = 1; i < wNumStrings; i++)
            {
                if (lpStrings[i])
                    TRACE_(eventlog)("Additional data: %s\n", debugstr_w(lpStrings[i]));
            }
            
            return TRUE;
        }
    }
    
    /* Fallback to original handling for non-multilingual strings */
    if (wNumStrings == 0) return TRUE;
    if (!lpStrings) return TRUE;

    for (i = 0; i < wNumStrings; i++)
    {
        const WCHAR *line = lpStrings[i];
        BOOL is_bc_format_error = FALSE;
        
        /* Check for Business Central error message pattern */
        if (line && wcsstr(line, L"The specified string is not formatted correctly"))
        {
            /* This is BC complaining about its own strings, downgrade to trace */
            is_bc_format_error = TRUE;
        }
        
        while (*line)
        {
            const WCHAR *next = wcschr( line, '\n' );
            if (next)
                ++next;
            else
                next = line + wcslen( line );

            switch (wType)
            {
            case EVENTLOG_SUCCESS:
                TRACE_(eventlog)("%s\n", debugstr_wn(line, next - line));
                break;
            case EVENTLOG_ERROR_TYPE:
                /* Check if this is a BC format error or multilingual string */
                if (is_bc_format_error ||
                    ((line[0] >= L'A' && line[0] <= L'Z') &&
                     (line[1] >= L'A' && line[1] <= L'Z') &&
                     ((line[2] >= L'A' && line[2] <= L'Z') || (line[2] >= L'0' && line[2] <= L'9')) &&
                     (line[3] == L'=' || (line[3] >= L'A' && line[3] <= L'Z' && line[4] == L'='))))
                {
                    /* This is either BC format error or multilingual string, downgrade to TRACE */
                    TRACE_(eventlog)("Multilingual: %s\n", debugstr_wn(line, next - line));
                }
                else
                {
                    ERR_(eventlog)("%s\n", debugstr_wn(line, next - line));
                }
                break;
            case EVENTLOG_WARNING_TYPE:
                /* Same check for warnings */
                if (is_bc_format_error ||
                    ((line[0] >= L'A' && line[0] <= L'Z') &&
                     (line[1] >= L'A' && line[1] <= L'Z') &&
                     ((line[2] >= L'A' && line[2] <= L'Z') || (line[2] >= L'0' && line[2] <= L'9')) &&
                     (line[3] == L'=' || (line[3] >= L'A' && line[3] <= L'Z' && line[4] == L'='))))
                {
                    TRACE_(eventlog)("Multilingual: %s\n", debugstr_wn(line, next - line));
                }
                else
                {
                    WARN_(eventlog)("%s\n", debugstr_wn(line, next - line));
                }
                break;
            default:
                TRACE_(eventlog)("%s\n", debugstr_wn(line, next - line));
                break;
            }
            line = next;
        }
    }
    return TRUE;
}

/******************************************************************************
 * StopTraceA [ADVAPI32.@]
 *
 * See StopTraceW.
 *
 */
ULONG WINAPI StopTraceA( TRACEHANDLE session, LPCSTR session_name, PEVENT_TRACE_PROPERTIES properties )
{
    FIXME("(%s, %s, %p) stub\n", wine_dbgstr_longlong(session), debugstr_a(session_name), properties);
    return ERROR_SUCCESS;
}

/******************************************************************************
 * QueryTraceA [ADVAPI32.@]
 */
ULONG WINAPI QueryTraceA( TRACEHANDLE handle, LPCSTR sessionname, PEVENT_TRACE_PROPERTIES properties )
{
    FIXME("%s %s %p: stub\n", wine_dbgstr_longlong(handle), debugstr_a(sessionname), properties);
    return ERROR_WMI_INSTANCE_NOT_FOUND;
}

/******************************************************************************
 * QueryTraceW [ADVAPI32.@]
 */
ULONG WINAPI QueryTraceW( TRACEHANDLE handle, LPCWSTR sessionname, PEVENT_TRACE_PROPERTIES properties )
{
    FIXME("%s %s %p: stub\n", wine_dbgstr_longlong(handle), debugstr_w(sessionname), properties);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/******************************************************************************
 * OpenTraceA [ADVAPI32.@]
 */
TRACEHANDLE WINAPI OpenTraceA( PEVENT_TRACE_LOGFILEA logfile )
{
    static int once;

    if (!once++) FIXME("%p: stub\n", logfile);
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_PROCESSTRACE_HANDLE;
}

/******************************************************************************
 * EnumerateTraceGuids [ADVAPI32.@]
 */
ULONG WINAPI EnumerateTraceGuids(PTRACE_GUID_PROPERTIES *propertiesarray,
                                 ULONG arraycount, PULONG guidcount)
{
    FIXME("%p %ld %p: stub\n", propertiesarray, arraycount, guidcount);
    return ERROR_INVALID_PARAMETER;
}
