#!/usr/bin/env bash
# 03_internal_api.sh — 扫描 JDK 内部 API 使用（sun.* / jdk.internal.* 等）
export LC_ALL=C.UTF-8 LANG=C.UTF-8
# 用法: bash 03_internal_api.sh <项目根目录>
set -euo pipefail
DIR="${1:-.}"; cd "$DIR"
echo "文件,行号,内容,API类型"

scan() {
  local pat="$1" type="$2"; shift 2
  grep -rn "$pat" --include="*.java" "$@" . 2>/dev/null \
    | grep -v '^\s*//' | grep -v '^\s*\*' \
    | while IFS=: read -r f l c; do
      printf '%s,%s,%s,%s\n' "$f" "$l" "$(echo "$c" | tr ',' ';' | xargs)" "$type"
    done
}

scan "sun\.misc\."                    sun.misc
scan "sun\.reflect\."                 sun.reflect
scan "com\.sun\."                     com.sun
scan "jdk\.internal\."                jdk.internal
scan "setAccessible\s*(true)"         setAccessible
scan "SecurityManager\|checkPermission\|AccessController" SecurityManager
