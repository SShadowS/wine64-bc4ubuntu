/*
 * Business Central WebSocket hooks for WinHTTP
 * 
 * Minimal implementation to detect and log BC WebSocket connections
 * without interfering with normal WinHTTP WebSocket operation.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winhttp.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winhttp);

static BOOL bc_hooks_enabled = FALSE;

/* Check if port is a BC port */
static BOOL is_bc_port(INTERNET_PORT port)
{
    return (port == 7049 || port == 7086);
}

/* Initialize BC hooks - called from DllMain */
void init_bc_hooks(void)
{
    /* Always enabled for BC-only Wine build */
    bc_hooks_enabled = TRUE;
    TRACE("BC WebSocket hooks active - logging mode\n");
}

/* Hook for WinHttpConnect - detect BC connections */
void bc_hook_connect(LPCWSTR server_name, INTERNET_PORT port)
{
    if (!bc_hooks_enabled)
        return;
        
    if (is_bc_port(port))
    {
        TRACE("BC connection detected: %S:%d\n", server_name, port);
        TRACE("This is a Business Central server - WebSocket upgrade may follow\n");
    }
}

/* Hook for WinHttpReceiveResponse - detect 101 upgrade */
void bc_hook_receive_response(HINTERNET request, DWORD status_code)
{
    if (!bc_hooks_enabled)
        return;
        
    if (status_code == 101)
    {
        TRACE("WebSocket upgrade successful! (101 Switching Protocols)\n");
        TRACE("WinHTTP will now handle WebSocket frames correctly\n");
    }
    else if (status_code == 401)
    {
        TRACE("401 Unauthorized - NTLM authentication in progress\n");
    }
}

/* Hook for WinHttpWebSocketCompleteUpgrade - WebSocket established */
void bc_hook_websocket_upgrade(HINTERNET request)
{
    if (!bc_hooks_enabled)
        return;
        
    TRACE("WebSocket connection fully established via WinHttpWebSocketCompleteUpgrade\n");
    TRACE("BC cmdlets should now work correctly\n");
}

/* Hook for WinHttpWebSocketReceive - log received frames */
void bc_hook_websocket_receive(PVOID buffer, DWORD bytes_read, 
                               WINHTTP_WEB_SOCKET_BUFFER_TYPE buffer_type)
{
    if (!bc_hooks_enabled)
        return;
        
    TRACE("WebSocket frame received: %lu bytes, type %d\n", bytes_read, buffer_type);
    
    /* Log SOAP messages for debugging */
    if (buffer_type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE && bytes_read > 0)
    {
        /* Show first 100 chars of SOAP message */
        char preview[101];
        DWORD copy_len = min(bytes_read, 100);
        memcpy(preview, buffer, copy_len);
        preview[copy_len] = '\0';
        TRACE("SOAP message preview: %.100s\n", preview);
    }
}

/* Hook for WinHttpWebSocketSend - log sent frames */  
void bc_hook_websocket_send(PVOID buffer, DWORD buffer_length,
                            WINHTTP_WEB_SOCKET_BUFFER_TYPE buffer_type)
{
    if (!bc_hooks_enabled)
        return;
        
    TRACE("WebSocket frame sending: %lu bytes, type %d\n", buffer_length, buffer_type);
}