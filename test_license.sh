LICENSE_ID=$(uvx --from ida-hcli hcli --disable-updates license list | grep -E "[0-9A-F]{2}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}" | head -n 1 | awk -F'│' '{print $2}' | tr -d ' ' | tr -d '\r')
echo "Using license ID: '$LICENSE_ID'"
