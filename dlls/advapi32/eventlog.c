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

/* BC event context for tracking Business Central service events */
struct bc_event_ctx {
    LONG  refcount;  /* Thread-safe reference counting */
    BOOL  is_bc;     /* BC service flag */
    DWORD magic;     /* Validation magic (0x42434556 = 'BCEV') */
};

#define BC_EVENT_MAGIC 0x42434556

/* Shared singleton context for non-BC services (zero overhead fast path) */
static struct bc_event_ctx non_bc_dummy_ctx = { 1, FALSE, BC_EVENT_MAGIC };
static HANDLE non_bc_dummy_handle = &non_bc_dummy_ctx;

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
    struct bc_event_ctx *ctx = (struct bc_event_ctx *)hEventLog;

    TRACE("(%p)\n", hEventLog);

    if (!ctx)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Fast path: shared dummy handle for non-BC services */
    if (ctx == &non_bc_dummy_ctx)
    {
        FIXME("(%p) stub\n", hEventLog);
        return TRUE;
    }

    /* Validate magic and handle BC context */
    if (ctx->magic != BC_EVENT_MAGIC)
    {
        WARN("Invalid handle magic: %p\n", hEventLog);
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Decrement refcount and free if zero */
    if (InterlockedDecrement(&ctx->refcount) == 0)
    {
        TRACE_(eventlog)("BC service deregistered: %p\n", ctx);
        free(ctx);
    }

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

    return (HANDLE)0xcafe4242;
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

    return (HANDLE)0xcafe4242;
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
 * is_bc_service
 *
 * Detect if source name matches Business Central service patterns.
 */
static BOOL is_bc_service( LPCWSTR lpSourceName )
{
    static const WCHAR bc_prefix_nav[] = {
        'M','i','c','r','o','s','o','f','t','D','y','n','a','m','i','c','s',
        'N','a','v','S','e','r','v','e','r','$',0
    };
    static const WCHAR bc_prefix_365[] = {
        'M','i','c','r','o','s','o','f','t','D','y','n','a','m','i','c','s',' ',
        '3','6','5',' ','B','u','s','i','n','e','s','s',' ',
        'C','e','n','t','r','a','l',' ','S','e','r','v','e','r','$',0
    };
    static const WCHAR bc_prefix_nav_alt[] = {
        'M','i','c','r','o','s','o','f','t',' ','D','y','n','a','m','i','c','s',' ',
        'N','A','V',' ','S','e','r','v','e','r','$',0
    };

    if (!lpSourceName) return FALSE;

    /* Case-insensitive prefix matching for BC service names */
    if (!wcsnicmp(lpSourceName, bc_prefix_nav, wcslen(bc_prefix_nav)))
        return TRUE;
    if (!wcsnicmp(lpSourceName, bc_prefix_365, wcslen(bc_prefix_365)))
        return TRUE;
    if (!wcsnicmp(lpSourceName, bc_prefix_nav_alt, wcslen(bc_prefix_nav_alt)))
        return TRUE;

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
    struct bc_event_ctx *ctx;

    TRACE("(%s,%s)\n", debugstr_w(lpUNCServerName), debugstr_w(lpSourceName));

    /* Fast path: non-BC services get shared dummy handle */
    if (!is_bc_service(lpSourceName))
    {
        FIXME("(%s,%s): stub\n", debugstr_w(lpUNCServerName), debugstr_w(lpSourceName));
        return non_bc_dummy_handle;
    }

    /* BC service detected - allocate refcounted context */
    ctx = malloc(sizeof(*ctx));
    if (!ctx)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    ctx->refcount = 1;
    ctx->is_bc = TRUE;
    ctx->magic = BC_EVENT_MAGIC;

    TRACE_(eventlog)("BC service registered: %s (handle=%p)\n", debugstr_w(lpSourceName), ctx);

    return (HANDLE)ctx;
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

    FIXME("(%p,0x%04x,0x%04x,0x%08lx,%p,0x%04x,0x%08lx,%p,%p): stub\n", hEventLog,
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
    struct bc_event_ctx *ctx = (struct bc_event_ctx *)hEventLog;
    UINT i;

    /* Check if this is a BC service handle */
    if (ctx && ctx != &non_bc_dummy_ctx && ctx->magic == BC_EVENT_MAGIC && ctx->is_bc)
    {
        /* BC service - output detailed event information */
        TRACE_(eventlog)("[BC Event 0x%08lx] Type=0x%04x Category=0x%04x\n",
                         dwEventID, wType, wCategory);

        if (wNumStrings > 0 && lpStrings)
        {
            for (i = 0; i < wNumStrings; i++)
            {
                if (lpStrings[i])
                    TRACE_(eventlog)("  String[%u]: %s\n", i, debugstr_w(lpStrings[i]));
            }
        }

        if (dwDataSize > 0 && lpRawData)
        {
            TRACE_(eventlog)("  Data: %lu bytes\n", dwDataSize);
        }

        return TRUE;
    }

    /* Non-BC service - use original implementation */
    FIXME("(%p,0x%04x,0x%04x,0x%08lx,%p,0x%04x,0x%08lx,%p,%p): stub\n", hEventLog,
          wType, wCategory, dwEventID, lpUserSid, wNumStrings, dwDataSize, lpStrings, lpRawData);

    /* partial stub */

    if (wNumStrings == 0) return TRUE;
    if (!lpStrings) return TRUE;

    for (i = 0; i < wNumStrings; i++)
    {
        const WCHAR *line = lpStrings[i];

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
                ERR_(eventlog)("%s\n", debugstr_wn(line, next - line));
                break;
            case EVENTLOG_WARNING_TYPE:
                WARN_(eventlog)("%s\n", debugstr_wn(line, next - line));
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
