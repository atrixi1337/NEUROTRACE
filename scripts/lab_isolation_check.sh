#!/bin/bash
# Prove the lab profile has no outbound network.
set +e
echo "=== interfaces ==="
ip -br addr 2>/dev/null || ifconfig 2>/dev/null || echo "(no ip/ifconfig)"
echo "=== try outbound http ==="
curl -fsS --max-time 3 http://1.1.1.1 >/dev/null 2>&1
echo "curl_exit=$? (non-zero = isolated, good)"
echo "=== try DNS ==="
python -c "import socket; socket.gethostbyname('example.com')" 2>/dev/null
echo "dns_exit=$? (non-zero = isolated, good)"
echo "=== neurotrace CLI still works offline ==="
python -m neurotrace.cli health 2>&1 | head -15
