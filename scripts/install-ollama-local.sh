#!/bin/sh
# Install a small CPU model for provider ollama-local.
# A Sprite has 8 vCPUs and a 100 GB disk. Memory is assigned per Sprite and
# grows under pressure, so this script reads the live figures and stays in
# the 1-4B range either way. Ollama Cloud is still the preferred real-run path.
set -eu

echo "Fly.io Sprite shape: 8 vCPUs, platform-managed memory, 100 GB disk."
cpus="$(nproc 2>/dev/null || echo unknown)"
mem_kb="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
disk_kb="$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')"
echo "This machine: CPUs=${cpus} MemAvailable_kB=${mem_kb} disk_free_kB=${disk_kb:-unknown}"

if [ -n "${disk_kb}" ] && [ "${disk_kb}" -lt 4000000 ]; then
  echo "Need about 4 GB free disk for the model. Free some space and run this again."
  exit 1
fi

# MemAvailable can look low before the platform grows memory. A 1.5B model
# is the default under 4 GB reported free; 3B is still inside the 1-4B brief.
if [ "${mem_kb}" -ge 4000000 ] 2>/dev/null; then
  MODEL="qwen2.5:3b"
  echo "Reported free memory is at least 4 GB. Using qwen2.5:3b (about 2 GB on disk)."
else
  MODEL="qwen2.5:1.5b"
  echo "Using qwen2.5:1.5b (about 1 GB on disk). Safer when reported free memory is modest."
fi

echo "On 8 vCPUs, expect roughly 10-25 tokens/sec for the 1.5B model and less for 3B."
echo "A triage can take a few minutes. Prefer the Ollama Cloud connector for a real run."

if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi

export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA_BIN="$(command -v ollama)"

if command -v sprite-env >/dev/null 2>&1; then
  if sprite-env services list 2>/dev/null | grep -q ollama; then
    sprite-env services restart ollama || true
  else
    sprite-env services create ollama \
      --cmd "$OLLAMA_BIN" \
      --args serve \
      --env "OLLAMA_HOST=${OLLAMA_HOST}" || sprite-env services restart ollama
  fi
else
  OLLAMA_HOST="$OLLAMA_HOST" "$OLLAMA_BIN" serve >/tmp/ollama-local.log 2>&1 &
fi

sleep 2
"$OLLAMA_BIN" pull "$MODEL"
echo "Model ready: ${MODEL}"
echo "In CYBOT set provider ollama-local and model ${MODEL}."
echo "Leave OLLAMA_HOST at 127.0.0.1:11434 so the daemon is not on the public URL."
