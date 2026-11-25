#!/bin/sh
# Report optional scan binaries. Missing tools are skipped by CYBOT.
# Pass --install to try a package install. A failure there still exits 0.
set -u

INSTALL=0
if [ "${1:-}" = "--install" ]; then
  INSTALL=1
fi

TOOLS="subfinder httpx naabu katana nuclei dnsx ffuf gobuster dalfox sqlmap nmap whatweb wafw00f dig whois"

missing=""
for tool in $TOOLS; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "ready $tool"
  else
    echo "missing $tool"
    missing="$missing $tool"
  fi
done

if [ -n "$missing" ] && [ "$INSTALL" -eq 1 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y nmap whatweb wafw00f dnsutils whois || echo "package install failed; continuing"
  else
    echo "no apt-get; install the missing binaries yourself"
  fi
  echo "ProjectDiscovery tools, ffuf, gobuster, dalfox, and sqlmap are not installed from distro packages here."
  echo "CYBOT still runs. Each missing binary is skipped."
fi

if [ -n "$missing" ]; then
  echo "degraded:$missing"
fi
exit 0
