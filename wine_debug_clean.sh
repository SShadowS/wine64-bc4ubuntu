#!/bin/bash

# Wine Debug Clean Script
# Filters out repetitive trace messages while showing important events

# Configuration
LOG_DIR="wine_debug_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/wine_debug_${TIMESTAMP}.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Default environment
export WINE_NTLM_BYPASS=1
export WINE_WEBSOCKET_ENABLE=1
export WINE_WSS_ENABLE=1
export WINEPREFIX=/home/sshadows/.local/share/wineprefixes/bc1

# Parse arguments
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [options] <wine-command>"
    echo ""
    echo "Options:"
    echo "  -d <channels>  Debug channels (default: +ntlm,+http,+winsock)"
    echo "  -f <pattern>   Additional filter pattern for console"
    echo "  -a             All debug channels (+all)"
    echo "  --show-trace   Show trace messages (normally hidden)"
    echo ""
    echo "Examples:"
    echo "  $0 pwsh                           # Run with clean output"
    echo "  $0 -f 'BYPASS' pwsh               # Show only BYPASS messages"
    echo "  $0 --show-trace pwsh              # Include trace messages"
    exit 0
fi

# Default settings
DEBUG_CHANNELS="+ntlm,+http,+winhttp,+wininet,+httpapi,+winsock,+secur32,+websocket,-thread,-combase,-ntdll,+msv1_0"
CUSTOM_FILTER=""
SHOW_TRACE=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        -d)
            DEBUG_CHANNELS="$2"
            shift 2
            ;;
        -f)
            CUSTOM_FILTER="$2"
            shift 2
            ;;
        -a)
            DEBUG_CHANNELS="+all"
            shift
            ;;
        --show-trace)
            SHOW_TRACE=true
            shift
            ;;
        *)
            break
            ;;
    esac
done

# Remaining arguments are the wine command
if [ $# -eq 0 ]; then
    echo "Error: No wine command specified"
    echo "Use -h for help"
    exit 1
fi

WINE_CMD="$@"

echo "========================================="
echo "Wine Debug (Clean Output)"
echo "========================================="
echo "Timestamp: $TIMESTAMP"
echo "Log file: $LOG_FILE"
echo "Debug channels: $DEBUG_CHANNELS"
echo "Environment:"
echo "  WINE_NTLM_BYPASS=$WINE_NTLM_BYPASS"
echo "  WINE_WEBSOCKET_ENABLE=$WINE_WEBSOCKET_ENABLE"
echo "  WINE_WSS_ENABLE=$WINE_WSS_ENABLE"
if [ -n "$CUSTOM_FILTER" ]; then
    echo "Custom filter: $CUSTOM_FILTER"
fi
echo "Command: wine $WINE_CMD"
echo "========================================="
echo ""

# Set debug channels
export WINEDEBUG="$DEBUG_CHANNELS"

# Create a named pipe
PIPE=$(mktemp -u)
mkfifo "$PIPE"

# Start background process to save everything to file
cat "$PIPE" > "$LOG_FILE" &
CAT_PID=$!

# Run wine and filter output
if [ "$SHOW_TRACE" = true ]; then
    # Show everything except the most repetitive messages
    wine $WINE_CMD 2>&1 | tee "$PIPE" | grep -v "async_recv_proc 0x101" &
elif [ -n "$CUSTOM_FILTER" ]; then
    # Apply custom filter only
    wine $WINE_CMD 2>&1 | tee "$PIPE" | grep -E "$CUSTOM_FILTER" &
else
    # Default: exclude trace messages and show only important stuff
    wine $WINE_CMD 2>&1 | tee "$PIPE" | grep -v "^[0-9a-f]*:trace:" | grep -E "WINE_NTLM_BYPASS|FIXME|ERROR|WARNING|Server|401|101|WebSocket|WSS:|Success|Failed|ready|BC " &
fi

WINE_PID=$!

# Wait for wine to finish
wait $WINE_PID
EXIT_CODE=$?

# Clean up
sleep 0.5
kill $CAT_PID 2>/dev/null
rm -f "$PIPE"

echo ""
echo "========================================="
echo "Debug session completed (exit code: $EXIT_CODE)"
echo "Full log saved to: $LOG_FILE"
echo ""
echo "To view the full log:"
echo "  less $LOG_FILE"
echo ""
echo "To check for WebSocket 101 responses:"
echo "  grep -c 'async_recv_proc 0x101' $LOG_FILE"
echo ""
echo "To see NTLM bypass activity:"
echo "  grep 'NTLM_BYPASS' $LOG_FILE"
echo ""
echo "To see WSS (WebSocket over TLS) activity:"
echo "  grep 'WSS:' $LOG_FILE"
echo ""
echo "To see BC-specific WebSocket activity:"
echo "  grep 'BC ' $LOG_FILE | grep -E 'connection|SOAP|PowerShell'"
echo "========================================="

exit $EXIT_CODE