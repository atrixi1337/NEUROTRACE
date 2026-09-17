#!/bin/bash
# List and extract a .7z safely inside the lab container.
set -euo pipefail
SRC="${1:-/opt/neurotrace/uploads/imagery.7z}"
DEST="${2:-/opt/neurotrace/uploads/extracted}"
mkdir -p "$DEST"
echo "=== listing $SRC ==="
if command -v 7z >/dev/null 2>&1; then
  7z l "$SRC"
  echo "=== extracting to $DEST ==="
  7z x -y "-o$DEST" "$SRC"
elif command -v 7za >/dev/null 2>&1; then
  7za l "$SRC"
  7za x -y "-o$DEST" "$SRC"
else
  python - <<'PY'
import sys
try:
    import py7zr
except ImportError:
    print("py7zr not installed either"); sys.exit(2)
print("py7zr available")
PY
fi
echo "=== extracted ==="
find "$DEST" -type f -printf '%s\t%p\n' | sort -n
