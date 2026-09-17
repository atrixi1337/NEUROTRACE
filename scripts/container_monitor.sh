#!/bin/bash
echo "=== processes ==="
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
  [ -n "$cmd" ] && echo "$pid $cmd"
done
echo "=== uploads ==="
ls -lah /opt/neurotrace/uploads/ 2>/dev/null
echo "=== reports ==="
ls -lah /opt/neurotrace/reports/ 2>/dev/null
echo "=== open files by python ==="
for p in /proc/[0-9]*; do
  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
  case "$cmd" in
    *python*)
      echo "--- pid ${p#/proc/}: $cmd ---"
      ls -l "$p/fd" 2>/dev/null | grep -E 'uploads|imagery|7z' || true
      ;;
  esac
done
