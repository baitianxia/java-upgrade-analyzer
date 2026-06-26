#!/usr/bin/env bash
# 04_removed_api.sh — 扫描 JDK 9~21 中已移除/废弃的 API
export LC_ALL=C.UTF-8 LANG=C.UTF-8
# 用法: bash 04_removed_api.sh <项目根目录>
set -euo pipefail
DIR="${1:-.}"; cd "$DIR"
echo "文件,行号,内容,API,移除版本,替换方案"

hit() {
  local pat="$1" api="$2" ver="$3" fix="$4"
  grep -rn "$pat" --include="*.java" . 2>/dev/null | while IFS=: read -r f l c; do
    printf '%s,%s,%s,%s,%s,%s\n' \
      "$f" "$l" "$(echo "$c" | tr ',' ';' | xargs)" "$api" "$ver" "$fix"
  done
}

hit "javax\.xml\.bind"       JAXB             JDK11  "jakarta.xml.bind + impl依赖"
hit "javax\.xml\.ws"         JAX-WS           JDK11  "jakarta.xml.ws依赖"
hit "javax\.activation"      Activation       JDK11  "jakarta.activation依赖"
hit "org\.omg\.\|javax\.rmi\." CORBA          JDK11  "需重构，无直接替代"
hit "jdk\.nashorn\|NashornScriptEngine" Nashorn JDK15 "GraalJS或其他JS引擎"
hit "\.stop()\|\.suspend()\|\.resume()" Thread.stop JDK20 "interrupt()+协作中断"
hit "java\.rmi\.activation"  RMI_Activation   JDK17  "无直接替代"
hit "java\.applet\|JApplet"  Applet           JDK17  "JavaFX或Web技术"
hit "protected void finalize" finalize        JDK18  "Cleaner或try-with-resources"
hit "new URL("               URL_constructor  JDK20  "URI.create(s).toURL()"
hit "runFinalizersOnExit"    runFinalizersOnExit JDK11 "无替代"
hit "Class\.newInstance()"   Class.newInstance JDK9  "getDeclaredConstructor().newInstance()"
