#!/usr/bin/env bash
# 11_autoconfig_scan.sh — 扫描自动装配配置文件，检查是否需要迁移
export LC_ALL=C.UTF-8 LANG=C.UTF-8
# Spring Boot 3 要求从 spring.factories 迁移到 AutoConfiguration.imports
# 用法: bash 11_autoconfig_scan.sh <项目根目录>
set -euo pipefail
DIR="${1:-.}"; cd "$DIR"

echo "# 自动装配配置扫描 | $(date)"
echo ""

echo "=== spring.factories 文件（Spring Boot 2 格式）==="
found_factories=0
find . -name "spring.factories" ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" -type f 2>/dev/null | while read -r f; do
  echo "发现: $f"
  grep -i "EnableAutoConfiguration\|AutoConfigurationImportFilter\|ApplicationListener\|EnvironmentPostProcessor" "$f" 2>/dev/null \
    | head -10 || echo "  (无标准自动装配条目)"
  found_factories=1
done
[ "$found_factories" -eq 0 ] && echo "✅ 无 spring.factories 文件"

echo ""
echo "=== AutoConfiguration.imports 文件（Spring Boot 3 格式）==="
find . -path "*/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports" \
  ! -path "*/.git/*" ! -path "*/target/*" -type f 2>/dev/null | while read -r f; do
  echo "✅ 发现: $f"
  wc -l < "$f"
  echo " 条自动装配配置"
done || echo "❌ 未发现 AutoConfiguration.imports（若有自定义Starter则需要创建）"

echo ""
echo "=== 自定义 Starter 检测 ==="
# 检查是否有 @AutoConfiguration 或 @EnableAutoConfiguration 的类
grep -rn "@AutoConfiguration\b\|@EnableAutoConfiguration\b" \
  --include="*.java" . 2>/dev/null \
  | grep -v "test\|Test\|#" | head -20 || echo "未发现自定义自动装配类"

echo ""
echo "=== @ConstructorBinding 使用检测（Spring Boot 3 需移到构造函数上）==="
grep -rn "@ConstructorBinding" --include="*.java" . 2>/dev/null \
  | grep -v "//\|test\|Test" | head -20 || echo "未发现 @ConstructorBinding 使用"
