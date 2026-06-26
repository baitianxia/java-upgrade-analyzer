#!/usr/bin/env bash
# 07_config_keys.sh — 提取项目所有配置属性键（用于 Spring Boot 3 迁移比对）
export LC_ALL=C.UTF-8 LANG=C.UTF-8
# 用法: bash 07_config_keys.sh <项目根目录>
set -euo pipefail
DIR="${1:-.}"; cd "$DIR"
echo "文件,行号,配置键,当前值"

# properties 文件
find . -name "*.properties" ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" -type f 2>/dev/null | while read -r f; do
  grep -n "^[a-zA-Z]" "$f" 2>/dev/null | grep -v "^[0-9]*:#" | while IFS=: read -r l c; do
    key=$(echo "$c" | cut -d'=' -f1 | xargs)
    val=$(echo "$c" | cut -d'=' -f2- | tr ',' ';' | xargs)
    [ -n "$key" ] && printf '%s,%s,%s,%s\n' "$f" "$l" "$key" "$val"
  done
done

# yml/yaml 文件
find . \( -name "*.yml" -o -name "*.yaml" \) ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" -type f 2>/dev/null | while read -r f; do
  grep -n "^\s*[a-zA-Z].*:" "$f" 2>/dev/null | while IFS=: read -r l c; do
    key=$(echo "$c" | sed 's/:.*//' | xargs)
    val=$(echo "$c" | grep -oP '(?<=: ).*' | tr ',' ';' | xargs 2>/dev/null || echo "")
    [ -n "$key" ] && printf '%s,%s,%s,%s\n' "$f" "$l" "$key" "$val"
  done
done
