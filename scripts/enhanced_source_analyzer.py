#!/usr/bin/env python3
"""
enhanced_source_analyzer.py

增强型源码分析引擎

技术栈：
  - Java 主引擎：tree-sitter AST 分析器（TreeSitterAnalyzer，默认主路径）
  - 降级引擎：增强正则分析器（EnhancedRegexAnalyzer）
  - Kotlin：当前仍走增强正则路径

核心改进：
  ✓ Lambda表达式识别
  ✓ 方法引用识别
  ✓ 泛型类型解析
  ✓ 嵌套类识别
  ✓ 字段类型推断
  ✓ 构造器与 lambda 参数类型传播
  ✓ 字符串/注释过滤（减少误报）
  ✓ 控制流关键字过滤（if/while/for不再误识别为方法）

准确性：
  - 增强正则：70-80%（降级路径）
  - tree-sitter：90-95%（Java 默认主路径）
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field

from signature_utils import normalize_signature_for_lookup, split_signature_params


def _current_python_pip_install_cmd():
    python_exe = sys.executable or "python"
    if " " in python_exe:
        python_exe = f'"{python_exe}"'
    return f"{python_exe} -m pip install tree-sitter tree-sitter-java"


def _env_flag_enabled(name):
    return str(os.environ.get(name, '') or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _step5_debug_enabled():
    return _env_flag_enabled('JUA_STEP5_DEBUG')


def _step5_debug_break_enabled():
    return _env_flag_enabled('JUA_STEP5_DEBUG_BREAK')


def _step5_debug(topic, message, **fields):
    if not _step5_debug_enabled():
        return
    payload = {
        'topic': str(topic or '').strip(),
        'message': str(message or '').strip(),
    }
    for key, value in (fields or {}).items():
        if value is None:
            continue
        payload[key] = value
    print(f"[step5-debug] {json.dumps(payload, ensure_ascii=False, sort_keys=True)}", file=sys.stderr)


def _step5_debug_break(topic, **fields):
    if not _step5_debug_break_enabled():
        return
    _step5_debug(topic, 'breakpoint triggered', **fields)
    breakpoint()


def _strip_balanced_outer_parens(expr):
    text = (expr or '').strip()
    while text.startswith('(') and text.endswith(')'):
        depth = 0
        balanced = True
        for idx, ch in enumerate(text):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth < 0:
                    balanced = False
                    break
                if depth == 0 and idx != len(text) - 1:
                    balanced = False
                    break
        if not balanced or depth != 0:
            break
        text = text[1:-1].strip()
    return text


def _normalize_type_hint(type_name):
    text = re.sub(r'<.*?>', '', str(type_name or '').strip())
    if not text:
        return ''
    text = text.replace('...', '[]')
    if '.' in text:
        text = text.rsplit('.', 1)[-1]
    return text


def _collect_candidate_signatures_for_receiver(receiver_type, method_name, method_def):
    signatures = set()
    if receiver_type == getattr(method_def, 'class_fqcn', ''):
        signatures.update(
            (getattr(method_def, 'local_method_return_types', {}) or {}).get(method_name, {}).keys()
        )
    signatures.update(
        (
            ((getattr(method_def, 'known_method_return_types_by_signature', {}) or {}).get(receiver_type, {}) or {})
            .get(method_name, {})
            .keys()
        )
    )
    return {sig for sig in signatures if str(sig or '').strip()}


def resolve_invocation_signature_from_partial_hints(receiver_type, method_name, arg_type_hints, method_def):
    normalized_hints = [_normalize_type_hint(item) for item in (arg_type_hints or [])]
    if not receiver_type or not method_name or not normalized_hints or not any(normalized_hints):
        return ''

    candidate_signatures = sorted(
        _collect_candidate_signatures_for_receiver(receiver_type, method_name, method_def)
    )
    if not candidate_signatures:
        return ''

    compatible = []
    for signature in candidate_signatures:
        params = split_signature_params(signature)
        if params is None or len(params) != len(normalized_hints):
            continue
        normalized_params = [_normalize_type_hint(item) for item in params]
        if all((not hint) or hint == param for hint, param in zip(normalized_hints, normalized_params)):
            compatible.append(signature)

    if len(compatible) == 1:
        _step5_debug(
            'signature_partial_resolution',
            'resolved unique signature from partial argument hints',
            receiver_type=receiver_type,
            method_name=method_name,
            arg_type_hints=normalized_hints,
            resolved_signature=compatible[0],
        )
        return compatible[0]

    if candidate_signatures and any(normalized_hints):
        _step5_debug(
            'signature_partial_resolution',
            'unable to resolve unique signature from partial argument hints',
            receiver_type=receiver_type,
            method_name=method_name,
            arg_type_hints=normalized_hints,
            candidate_signatures=candidate_signatures,
            compatible_signatures=compatible,
        )
        if len(compatible) > 1:
            _step5_debug_break(
                'signature_partial_resolution',
                receiver_type=receiver_type,
                method_name=method_name,
                arg_type_hints=normalized_hints,
                compatible_signatures=compatible,
            )
    return ''

# 降级方案：如果tree-sitter未安装，使用增强正则
try:
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    print("⚠️  tree-sitter未安装，降级使用增强正则方案", file=sys.stderr)
    print(
        f"   请使用当前执行解释器安装：{_current_python_pip_install_cmd()}",
        file=sys.stderr,
    )


@dataclass
class MethodDef:
    """
    方法定义（增强版，支持延迟加载）

    内存优化：
      - body_text 可选延迟加载，避免同时保存所有方法体
      - 提供 body_text_lazy 属性用于按需读取
    """
    symbol_id: str
    qualified_key: str
    simple_key: str
    class_fqcn: str
    class_name: str
    method_name: str
    return_type: str
    file: str
    line: int
    end_line: int
    package_name: str
    owner_type: str
    owner_coord: str
    module: str
    source_root: str
    language: str
    is_test: bool
    param_types: dict = field(default_factory=dict)
    param_declared_types: dict = field(default_factory=dict)
    imports: dict = field(default_factory=dict)
    static_imports: dict = field(default_factory=dict)
    wildcard_imports: list = field(default_factory=list)
    field_types: dict = field(default_factory=dict)
    field_declared_types: dict = field(default_factory=dict)
    annotations: list = field(default_factory=list)
    modifiers: list = field(default_factory=list)
    class_annotations: list = field(default_factory=list)
    is_static: bool = False
    is_interface: bool = False
    local_method_return_types: dict = field(default_factory=dict)
    known_method_return_types: dict = field(default_factory=dict)
    known_method_return_types_by_signature: dict = field(default_factory=dict)
    local_var_types: dict = field(default_factory=dict)
    ast_local_var_sites: list = field(default_factory=list)
    ast_call_sites: list = field(default_factory=list)
    # 【内存优化】可选的延迟加载
    body_text: str = ""  # 保留兼容，为空时使用延迟加载
    _body_text_cached: str = field(default="", repr=False)  # 缓存
    _body_lines: tuple = field(default_factory=lambda: (), repr=False)  # 原始行

    @property
    def body_text_lazy(self) -> str:
        """延迟加载方法体（按需读取文件）"""
        if self._body_text_cached:
            return self._body_text_cached

        if self._body_lines:
            self._body_text_cached = ''.join(self._body_lines)
            self._body_lines = ()  # 释放内存
            return self._body_text_cached

        # 回退：从文件读取
        try:
            with open(self.file, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                start_idx = max(0, self.line - 1)
                end_idx = min(len(lines), self.end_line)
                self._body_text_cached = ''.join(lines[start_idx:end_idx])
                return self._body_text_cached
        except Exception:
            return ""

    def get_body_text(self) -> str:
        """获取方法体（优先使用缓存）"""
        if self.body_text:
            return self.body_text
        return self.body_text_lazy


@dataclass
class CallEdge:
    """调用边（增强版）"""
    caller_symbol_id: str
    callee_key: str
    callee_simple_key: str
    evidence_type: str
    confidence: str
    file: str
    line: int
    content: str
    owner_type: str
    owner_coord: str
    module: str
    is_test: bool
    caller_qualified_key: str = ""
    callee_param_types: list = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════
# 增强正则方案（tree-sitter未安装时的降级方案）
# ══════════════════════════════════════════════════════════════════

# 改进的方法识别正��（支持泛型）
ENHANCED_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:@\w+[^(]*\([^)]*\)\s*)*"  # 注解
    r"(?:(?:public|private|protected)\s+)?"
    r"(?:(?:static|final|synchronized|abstract|default|native)\s+)*"
    r"(?:[\w<>\[\],.@?]+(?:\s+extends\s+[\w<>\[\],.?]+)?\s+)?"  # 返回值类型
    r"(?!if\b|while\b|do\b|for\b|switch\b)([a-zA-Z_]\w*)\s*"  # 方法名（排除控制流关键字）
    r"\(([^)]*)\)\s*"  # 参数列表
    r"(?:throws\b[^{;=]+)?(?:\{|;|=).*"  # 支持方法体、抽象/接口声明、Kotlin风格表达式体
)


# Kotlin方法识别（新增 - 支持Kotlin源码）
KOTLIN_METHOD_RE = re.compile(
    r"^\s*(?:@\w+[^(]*\([^)]*\)\s*)*"  # 注解
    r"(?:(?:public|private|protected|internal)\s+)?"
    r"(?:(?:suspend|inline|reified|operator|infix|tailrec)\s+)*"
    r"fun\s+"  # fun关键字（Kotlin特有）
    r"(?:[\w.<>\[\],?]+\s+)??"  # 可选的receiver type (extension function)
    r"(?!if\b|while\b|do\b|for\b|switch\b)([a-zA-Z_]\w*)\s*"  # 方法名（排除控制流关键字）
    r"\(([^)]*)\)\s*"  # 参数列表
    r"(?::\s*[\w.<>\[\],?]+\s*)?"  # 可选的返回类型
    r"(?:throws[^{;=]+)?(?:\{|=|;).*"  # 方法体/表达式体/接口声明
)

# Lambda表达式识别（新增）
LAMBDA_RE = re.compile(
    r"(?:\([^)]*\)|[a-zA-Z_]\w*|\w+\.\w+)\s*->\s*([^;{}]+)"
)

# 方法引用识别（新增）
METHOD_REF_RE = re.compile(
    r"([A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)*)\s*::\s*([a-zA-Z_]\w*)"
)

# 泛型类型提取（新增）
GENERIC_TYPE_RE = re.compile(
    r"<([^>]+)>"
)

# 嵌套类识别（新增）
NESTED_CLASS_RE = re.compile(
    r"(?:class|interface|enum)\s+([A-Z][A-Za-z0-9_]*)\s*(?:extends|implements|\{)"
)

# ��口声明识别（用于判断类是否为接口）
INTERFACE_DECL_RE = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*"  # 前置注解
    r"(?:public\s+)?"  # 可见的 public
    r"(?:abstract\s+)?"  # 可选的 abstract
    r"interface\s+([A-Z][A-Za-z0-9_]*)"  # interface 关键字
)

# 字段声明识别（增强版 - 支持无初始化字段）
FIELD_DECL_RE = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*"  # 支持多行注解
    r"(?:private|protected|public)?\s*"  # 访问修饰符
    r"(?:static)?\s*(?:final)?\s*"  # 其他修饰符
    r"([A-Za-z_]\w*(?:<[^;=]+>)?(?:\[\])*)\s+"  # 类型（含泛型和数组）
    r"([a-zA-Z_]\w*)\s*"  # 字段名
    r"((?:\s*\[\s*\])*)\s*"  # 支持 String field[] 写法
    r"(?:=|;)"  # 匹配初始化或声明结束（支持无初始化）
)


class EnhancedRegexAnalyzer:
    """
    增强正则分析器（降级方案）

    改进点：
      1. 支持泛型类型提取
      2. Lambda表达式识别
      3. 方法引用识别
      4. 嵌套类完整FQN构建
    """

    def __init__(self, file_path, source_root):
        self.file_path = file_path
        self.source_root = source_root
        self.language = "kotlin" if file_path.endswith(".kt") else "java"
        self.package_name = ""
        self.imports = {}
        self.static_imports = {}
        self.wildcard_imports = []
        self.class_stack = []
        self.field_types = {}
        self.field_declared_types = {}
        self.type_metadata = {}

    def analyze(self):
        """分析单个源码文件"""
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                original_lines = list(f)
        except Exception:
            return []

        sanitized_lines = self._sanitize_structure_lines(original_lines)

        # Phase 1: 提取包名、imports、类结构、字段
        self.package_name = self._detect_package(sanitized_lines)
        self.imports, self.static_imports, self.wildcard_imports = self._detect_imports(sanitized_lines)
        self._scan_class_structure(sanitized_lines)
        self._scan_fields(sanitized_lines)

        # Phase 2: 提取方法定义
        methods = self._extract_methods(sanitized_lines, original_lines=original_lines)

        return methods

    def _sanitize_structure_lines(self, lines):
        """
        结构扫描前统一屏蔽注释内容，同时保留行数与非注释代码布局。

        这样 tree-sitter 降级到 regex 后，不会把整段块注释中的类/字段/方法
        误识别为真实源码结构。
        """
        sanitized = []
        in_block_comment = False
        for raw_line in lines:
            line = []
            i = 0
            n = len(raw_line)
            in_string = False
            in_char = False
            while i < n:
                ch = raw_line[i]
                nxt = raw_line[i + 1] if i + 1 < n else ""
                if in_block_comment:
                    if ch == '*' and nxt == '/':
                        line.extend([' ', ' '])
                        in_block_comment = False
                        i += 2
                    else:
                        line.append('\n' if ch == '\n' else ' ')
                        i += 1
                    continue
                if in_string:
                    line.append(ch)
                    if ch == '\\' and i + 1 < n:
                        line.append(raw_line[i + 1])
                        i += 2
                        continue
                    if ch == '"':
                        in_string = False
                    i += 1
                    continue
                if in_char:
                    line.append(ch)
                    if ch == '\\' and i + 1 < n:
                        line.append(raw_line[i + 1])
                        i += 2
                        continue
                    if ch == "'":
                        in_char = False
                    i += 1
                    continue
                if ch == '"':
                    in_string = True
                    line.append(ch)
                    i += 1
                    continue
                if ch == "'":
                    in_char = True
                    line.append(ch)
                    i += 1
                    continue
                if ch == '/' and nxt == '/':
                    line.extend(' ' for _ in raw_line[i:] if _ != '\n')
                    if raw_line.endswith('\n'):
                        line.append('\n')
                    break
                if ch == '/' and nxt == '*':
                    line.extend([' ', ' '])
                    in_block_comment = True
                    i += 2
                    continue
                line.append(ch)
                i += 1
            sanitized.append(''.join(line))
        return sanitized

    def _detect_package(self, lines):
        """提取包名"""
        for line in lines[:40]:
            m = re.match(r"^\s*package\s+([A-Za-z_][\w.]*)\s*;", line)
            if m:
                return m.group(1)
        return ""

    def _detect_imports(self, lines):
        """提取imports（增强：区分静态导入）"""
        imports = {}
        static_imports = {}
        wildcard_imports = []

        for line in lines[:200]:
            # 静态导入
            static_m = re.match(r"^\s*import\s+static\s+([A-Za-z_][\w.]*)\s*;", line)
            if static_m:
                fq_member = static_m.group(1)
                simple = fq_member.rsplit('.', 1)[-1]
                static_imports[simple] = fq_member
                continue

            # 普通导入
            m = re.match(r"^\s*import\s+([A-Za-z_][\w.]*)(?:\.\*)?\s*;", line)
            if m:
                fqcn = m.group(1)
                if line.strip().endswith(".*;"):
                    wildcard_imports.append(fqcn)
                else:
                    simple = fqcn.rsplit('.', 1)[-1]
                    imports[simple] = fqcn

        return imports, static_imports, wildcard_imports

    def _scan_class_structure(self, lines):
        """第一遍：记录每个类声明行的 brace_depth（供 _extract_methods 内联使用）"""
        self.class_at_line = {}  # line_idx -> (class_name, brace_depth_before, is_interface, class_annotations)
        brace_depth = 0
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            class_m = NESTED_CLASS_RE.search(line)
            if class_m:
                class_name = class_m.group(1)
                # 检查是否是接口
                is_interface = bool(INTERFACE_DECL_RE.search(line))
                class_annotations = self._extract_leading_annotations(lines, idx)
                self.class_at_line[idx] = (class_name, brace_depth, is_interface, class_annotations)
            open_count = line.count('{')
            close_count = line.count('}')
            brace_depth += open_count - close_count

    def _scan_fields(self, lines):
        """
        扫描字段声明，解析类型并填充 field_types（增强版）

        增强改进：
          1. 支持无初始化字段声明
          2. 支持多行注解字段（@Autowired等）
          3. 推断构造器注入的字段类型
        """
        # Phase 1: 扫描显式字段声明
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            if re.match(r'^(?:return|throw|if|for|while|switch|case|else|catch|new)\b', stripped):
                continue

            candidate = line
            if ';' not in stripped and '(' not in stripped and ')' not in stripped:
                buffer = [stripped]
                for follow in lines[idx + 1:idx + 5]:
                    buffer.append(follow.strip())
                    if ';' in follow:
                        break
                candidate = ' '.join(part for part in buffer if part)

            fm = FIELD_DECL_RE.match(candidate)
            if fm:
                raw_type = fm.group(1)
                field_name = fm.group(2)
                suffix_arrays = fm.group(3) or ''
                raw_type = raw_type + ('[]' * suffix_arrays.count('['))
                resolved = self._resolve_simple_type(raw_type)
                self.field_types[field_name] = resolved
                self.field_declared_types[field_name] = raw_type
                continue

            # Phase 2: 【新增】扫描构造器参数推断字段类型
            # 模式: public ClassName(TypeA fieldA, TypeB fieldB) { this.fieldA = fieldA; }
            # 从构造器参数推断未声明的字段类型
            constructor_match = re.match(
                r'^\s*(?:public|private|protected)?\s*([A-Z][A-Za-z0-9_]*)\s*\(([^)]*)\)',
                line
            )
            if constructor_match:
                params_str = constructor_match.group(2).strip()

                if params_str:
                    # 解析参数列表
                    for param in params_str.split(','):
                        param = param.strip()
                        if not param:
                            continue

                        # 分离类型和参数名
                        parts = param.split()
                        if len(parts) >= 2:
                            # 去掉final等修饰符
                            parts = [p for p in parts if p not in ('final', 'transient')]
                            if len(parts) >= 2:
                                type_expr = ' '.join(parts[:-1])
                                param_name = parts[-1]

                                # 解析类型
                                resolved_type = self._resolve_simple_type(type_expr)

                                # 只有当字段未声明时才从构造器推断
                                # 避免覆盖已有的字段声明
                                if param_name not in self.field_types:
                                    self.field_types[param_name] = resolved_type
                                    self.field_declared_types[param_name] = type_expr

    def _extract_methods(self, lines, original_lines=None):
        """提取方法定义（含方法体内容用于调用边提取）"""
        methods = []
        n = len(lines)
        original_lines = list(original_lines or lines)

        # 内联维护类栈：在每行方法定义时 class_stack 处于正确状态
        class_stack = []
        brace_depth = 0

        idx = 0
        while idx < n:
            line = lines[idx]
            stripped = line.strip()

            if not stripped or stripped.startswith('//'):
                idx += 1
                continue
            if stripped.startswith('/*'):
                idx += 1
                continue

            open_count = line.count('{')
            close_count = line.count('}')

            # 类声明 push（在更新 brace_depth 之前，记录进入前的深度）
            if idx in self.class_at_line:
                cls_name, _, is_interface_decl, class_annotations = self.class_at_line[idx]
                parent_chain = [c['name'] for c in class_stack]
                full_chain = parent_chain + [cls_name]
                class_fqcn = '.'.join(
                    part for part in [self.package_name, *full_chain] if part
                )
                class_stack.append({
                    'name': cls_name,
                    'fqcn': class_fqcn,
                    'depth': brace_depth,  # 记录进入前的深度
                    'line': idx,
                    'is_interface': is_interface_decl,  # 记录是否是接口
                    'annotations': class_annotations,
                })

            # 更新 brace_depth
            new_depth = brace_depth + open_count - close_count

            # 类结束：当 brace_depth 回到栈顶类进入前的深度或更低时，pop 栈顶
            # 关键修复：使用 <= 因为嵌套类结束时 depth 等于父类进入时的 depth
            while class_stack and new_depth <= class_stack[-1]['depth']:
                # 但要避免在同一行 push 后立即 pop（class Foo { 的情况）
                if new_depth == class_stack[-1]['depth'] and idx == class_stack[-1]['line']:
                    break
                class_stack.pop()

            # 更新 brace_depth
            brace_depth = new_depth

            # 方法匹配
            method_m = ENHANCED_JAVA_METHOD_RE.match(line) or KOTLIN_METHOD_RE.match(line)
            if not method_m:
                idx += 1
                continue

            if not class_stack:
                idx += 1
                continue

            method_name = method_m.group(1)
            params_part = method_m.group(2)
            current_class = class_stack[-1]
            class_fqcn = current_class['fqcn']
            class_name = current_class['name']
            is_interface = current_class.get('is_interface', False)  # 获取接口信息
            class_annotations = current_class.get('annotations', [])

            return_type = self._extract_return_type(line, method_name)
            param_types = self._extract_param_types(params_part)
            param_declared_types = dict(param_types)

            # 关键修复：提取多行注解（回溯查找方法前的注解）
            annotations = self._extract_annotations_multiline(lines, idx)
            modifiers = self._extract_modifiers(line)

            # 【关键修复】提取方法体 - 正确处理单行方法体
            # 问题：void f() { doWork(); } 这种单行方法在同一行有 { 和 }
            # 原代码只处理了 {，导致 body_brace_depth 保持为正，继续吞掉后续行
            body_brace_depth = 0
            body_lines = []
            capture = False

            # 在方法声明行上统计括号
            for ch in stripped:
                if ch == '{':
                    body_brace_depth += 1
                    capture = True
                elif ch == '}':
                    body_brace_depth -= 1  # 单行方法体：同一行的 } 抵消

            if capture:
                body_lines.append(original_lines[idx])

            # 继续处理后续行
            j = idx + 1
            while j < n and body_brace_depth > 0:
                l = lines[j]
                ls = l.strip()

                # 统计该行的括号
                for ch in ls:
                    if ch == '{':
                        body_brace_depth += 1
                    elif ch == '}':
                        body_brace_depth -= 1

                body_lines.append(original_lines[j])
                j += 1

            end_line = idx if not capture else min(j, n - 1)
            symbol_id = f"{class_fqcn}#{method_name}@{os.path.abspath(self.file_path)}:{idx + 1}"

            # 【内存优化】使用 _body_lines tuple 而非直接保存 body_text 字符串
            # MethodDef 会在需要时懒加载
            method_def = MethodDef(
                symbol_id=symbol_id,
                qualified_key=f"{class_fqcn}.{method_name}",
                simple_key=f"method:{method_name}",
                class_fqcn=class_fqcn,
                class_name=class_name,
                method_name=method_name,
                return_type=return_type,
                file=os.path.abspath(self.file_path),
                line=idx + 1,
                end_line=end_line + 1,
                package_name=self.package_name,
                owner_type=self.source_root.get('owner_type', 'business'),
                owner_coord=self.source_root.get('owner_coord', 'BUSINESS'),
                module=self.source_root.get('module', 'root'),
                source_root=self.source_root.get('root', ''),
                language=self.language,
                is_test='/test/' in self.file_path or 'Test' in class_name,
                param_types=param_types,
                param_declared_types=param_declared_types,
                imports=dict(self.imports),
                static_imports=dict(self.static_imports),
                wildcard_imports=list(self.wildcard_imports),
                field_types=self.field_types,
                field_declared_types=dict(self.field_declared_types),
                annotations=annotations,
                modifiers=modifiers,
                class_annotations=class_annotations,
                is_static='static' in modifiers,
                is_interface=is_interface,  # 使用实际检测的接口信息
                local_method_return_types={},
                body_text="",  # 不直接保存，让 MethodDef 使用延迟加载
                _body_lines=tuple(body_lines)  # 使用 tuple 节省内存
            )
            methods.append(method_def)
            body_delta = sum(
                lines[k].count('{') - lines[k].count('}')
                for k in range(idx + 1, j)
            )
            brace_depth += body_delta
            idx = j

        local_method_returns = defaultdict(dict)
        local_method_returns_by_signature = defaultdict(lambda: defaultdict(dict))
        for method in methods:
            if method.return_type:
                local_method_returns[method.class_fqcn][method.method_name] = method.return_type
                signature = _build_signature_from_param_values(method.param_declared_types.values())
                local_method_returns_by_signature[method.class_fqcn][method.method_name][signature] = method.return_type
        known_method_return_types_by_signature = {
            class_fqcn: {
                method_name: dict(signatures)
                for method_name, signatures in method_map.items()
            }
            for class_fqcn, method_map in local_method_returns_by_signature.items()
        }
        for method in methods:
            method.local_method_return_types = {
                method_name: dict(signatures)
                for method_name, signatures in local_method_returns_by_signature.get(method.class_fqcn, {}).items()
            }
            method.known_method_return_types = dict(local_method_returns.get(method.class_fqcn, {}))
            method.known_method_return_types_by_signature = known_method_return_types_by_signature

        self.class_stack = class_stack
        return methods

    def _extract_return_type(self, line, method_name):
        """提取返回值类型（增强：处理泛型）"""
        # 提取方法签名部分
        before_method = line.split(method_name, 1)[0] if method_name in line else line

        # 去除注解和修饰符
        before_method = re.sub(r'@\w+[^(]*\([^)]*\)\s*', '', before_method)
        before_method = re.sub(
            r'\b(?:public|private|protected|static|final|synchronized|abstract|default|native)\b',
            '',
            before_method
        )

        # 清理空格
        before_method = ' '.join(before_method.split()).strip()

        if not before_method:
            return ""

        # 处理泛型：提取<...>部分
        generic_m = GENERIC_TYPE_RE.search(before_method)
        if generic_m:
            # 保留泛型参数
            return before_method.strip()

        # 简单类型
        return self._resolve_type(before_method.strip())

    def _extract_param_types(self, params_part):
        """提取参数类型（增强：处理泛型）"""
        if not params_part or params_part.strip() == '':
            return {}

        param_types = {}
        params = [p.strip() for p in params_part.split(',') if p.strip()]

        for param in params:
            # 分离类型和参数名
            parts = param.split()
            if len(parts) >= 2:
                type_expr = ' '.join(parts[:-1])  # 类型部分
                var_name = parts[-1].replace('...', '').strip()  # 参数名

                # 处理泛型
                resolved_type = self._resolve_type(type_expr)
                if resolved_type:
                    param_types[var_name] = resolved_type

        return param_types

    def _resolve_type(self, type_expr):
        """
        类型解析（增强版）

        处理：
          - 泛型：Map<String, Foo> → Map（保留泛��信息）
          - 嵌套类：Outer.Inner → 从class_stack查找
          - 导入类：Foo → 从imports查找FQN
        """
        type_expr = type_expr.strip()

        # 基础类型
        if type_expr in {'int', 'long', 'double', 'float', 'boolean', 'char', 'byte', 'short', 'void'}:
            return type_expr

        # 去除泛型参数（保留FQN）
        if '<' in type_expr:
            base_type = type_expr.split('<')[0].strip()
            # 解析base_type
            return self._resolve_simple_type(base_type)

        # 数组类型
        if type_expr.endswith('[]'):
            base_type = type_expr[:-2].strip()
            return self._resolve_simple_type(base_type)

        # 嵌套类
        if '.' in type_expr:
            # 检查是否是内部类引用
            parts = type_expr.split('.')
            if len(parts) == 2:
                # 可能是 Outer.Inner 或 imported.Class
                outer = parts[0]
                inner = parts[1]

                # 检查是否是当前文件的内部类
                for class_info in self.class_stack:
                    if class_info['name'] == outer:
                        return f"{class_info['fqcn']}.{inner}"

            # FQN类型
            return type_expr

        # 简单类型名
        return self._resolve_simple_type(type_expr)

    def _resolve_simple_type(self, simple_name):
        """解析简单类型名"""
        # 从imports查找
        if simple_name in self.imports:
            return self.imports[simple_name]

        for wildcard_pkg in self.wildcard_imports:
            if wildcard_pkg:
                return f"{wildcard_pkg}.{simple_name}"

        java_util_types = {
            'List', 'Map', 'Set', 'Collection', 'Iterable',
            'ArrayList', 'HashMap', 'HashSet', 'LinkedList',
            'Optional', 'Stream', 'Function', 'Predicate', 'Consumer'
        }
        if simple_name in java_util_types:
            return f"java.util.{simple_name}"

        # java.lang包（只包含真正的java.lang类）
        java_lang_types = {
            'String', 'Object', 'Class', 'Integer', 'Long', 'Double',
            'Exception', 'RuntimeException', 'Throwable', 'Void', 'Boolean'
        }
        if simple_name in java_lang_types:
            return f"java.lang.{simple_name}"

        # 当前包内的类放在最后，避免把常见JDK/显式 wildcard import 类型误判到本包
        if self.package_name:
            return f"{self.package_name}.{simple_name}"

        return simple_name

    def _extract_annotations(self, line):
        """提取注解"""
        annotations = []
        for m in re.finditer(r'@(\w+)', line):
            annotations.append(m.group(1))
        return annotations

    def _extract_leading_annotations(self, lines, anchor_idx, max_search=10):
        """
        提取某个声明前连续出现的多行注解

        Java中常见的注解写法：
          @GetMapping("/users")
          @Transactional
          @Autowired
          @Component(value = "service")

        需要回溯查找声明前的多行注解
        """
        annotations = []
        max_search = min(max_search, anchor_idx)  # 最多回溯10行

        for i in range(anchor_idx - 1, max(anchor_idx - max_search, -1), -1):
            line = lines[i].strip()

            # 遇到空行停止（注解之间不应有空行）
            if not line:
                break

            # 检查是否是注解
            if line.startswith('@'):
                # 提取注解名
                match = re.match(r'@(\w+)', line)
                if match:
                    annotations.insert(0, match.group(1))
            else:
                # 非注解、非空行，停止
                break

        return annotations

    def _extract_annotations_multiline(self, lines, method_idx):
        """兼容旧调用：提取方法前的多行注解"""
        return self._extract_leading_annotations(lines, method_idx)

    def _extract_modifiers(self, line):
        """提取修饰符"""
        modifiers = []
        modifier_keywords = [
            'public', 'private', 'protected', 'static', 'final',
            'synchronized', 'abstract', 'default', 'native'
        ]
        for keyword in modifier_keywords:
            if re.search(rf'\b{keyword}\b', line):
                modifiers.append(keyword)
        return modifiers


# ═════════════��════════════════════════════════════════════════════
# tree-sitter AST分析器（完整方案，需安装依赖）
# ══════════════════════════════════════════════════════════════════

class TreeSitterAnalyzer:
    """
    tree-sitter AST分析器（完整方案）

    优势：
      - 完整AST解析（准确度 90-95%）
      - 支持复杂语法结构（Lambda、泛型、嵌套类）
      - 性能比正则快 3-5倍

    需安装：
      使用当前执行解释器安装，避免装到错误环境：
      <当前 Python> -m pip install tree-sitter tree-sitter-java
    """

    def __init__(self, file_path, source_root):
        self.file_path = file_path
        self.source_root = source_root
        self.language = "java" if file_path.endswith('.java') else "kotlin"
        self.helper = EnhancedRegexAnalyzer(file_path, source_root)
        self.error_nodes = 0
        self.non_empty_source = False
        self.has_type_declarations = False

        # tree-sitter only supports Java, skip Kotlin files
        if file_path.endswith('.kt') or file_path.endswith('.kts'):
            raise ImportError("tree-sitter does not support Kotlin, use regex analyzer instead")

        # 初始化parser
        self.parser = Parser()
        language = Language(tsjava.language())
        if hasattr(self.parser, 'set_language'):
            self.parser.set_language(language)
        else:
            self.parser.language = language

    def analyze(self):
        """使用tree-sitter分析源码"""
        try:
            with open(self.file_path, 'rb') as f:
                source_code = f.read()
        except Exception:
            return []

        try:
            text = source_code.decode('utf-8', errors='replace')
        except Exception:
            text = ""
        lines = text.splitlines(keepends=True)
        self.non_empty_source = bool(text.strip())

        # 复用增强正则的文件级补充能力：包名、imports、字段、嵌套类元信息。
        # tree-sitter 负责主结构定位；这些补充信息用于调用边提取和类型推断。
        self.helper.package_name = self.helper._detect_package(lines)
        self.helper.imports, self.helper.static_imports, self.helper.wildcard_imports = self.helper._detect_imports(lines)
        self.helper._scan_class_structure(lines)
        self.helper._scan_fields(lines)

        # 构建AST
        tree = self.parser.parse(source_code)
        self.error_nodes = self._count_error_nodes(tree.root_node)

        # 提取方法定义
        methods = self._extract_methods_from_ast(tree.root_node, source_code, lines)
        self.has_type_declarations = any(
            node.type in {
                'class_declaration',
                'interface_declaration',
                'enum_declaration',
                'annotation_type_declaration',
                'record_declaration',
            }
            for node in self._walk_ast(tree.root_node)
        )

        local_method_returns = defaultdict(dict)
        local_method_returns_by_signature = defaultdict(lambda: defaultdict(dict))
        for method in methods:
            if method.return_type:
                local_method_returns[method.class_fqcn][method.method_name] = method.return_type
                signature = _build_signature_from_param_values(method.param_declared_types.values())
                local_method_returns_by_signature[method.class_fqcn][method.method_name][signature] = method.return_type
        known_method_return_types = {
            class_fqcn: dict(return_types)
            for class_fqcn, return_types in local_method_returns.items()
        }
        known_method_return_types_by_signature = {
            class_fqcn: {
                method_name: dict(signatures)
                for method_name, signatures in method_map.items()
            }
            for class_fqcn, method_map in local_method_returns_by_signature.items()
        }
        for method in methods:
            method.local_method_return_types = {
                method_name: dict(signatures)
                for method_name, signatures in local_method_returns_by_signature.get(method.class_fqcn, {}).items()
            }
            method.known_method_return_types = known_method_return_types
            method.known_method_return_types_by_signature = known_method_return_types_by_signature
            method.local_var_types = resolve_ast_local_var_types(method)

        return methods

    def _extract_methods_from_ast(self, root_node, source_code, lines):
        """从AST提取方法定义"""
        methods = []

        # 遍历AST节点
        for node in self._walk_ast(root_node):
            if node.type in {'method_declaration', 'constructor_declaration'}:
                method_def = self._parse_method_node(node, source_code, lines)
                if method_def:
                    methods.append(method_def)

        return methods

    def _count_error_nodes(self, root_node):
        return sum(1 for node in self._walk_ast(root_node) if node.type == 'ERROR')

    def _walk_ast(self, node):
        """递归遍历AST"""
        yield node
        for child in node.children:
            yield from self._walk_ast(child)

    def _parse_method_node(self, node, source_code, lines):
        """解析方法节点（含类上下文）"""
        # 向上查找类上下文（支持嵌套类）
        class_nodes = self._find_enclosing_types(node)
        class_fqcn, class_name, class_annotations, is_interface = self._build_class_context(class_nodes, source_code, lines)
        if not class_fqcn:
            return None

        method_name = self._field_text(node, 'name', source_code)
        if node.type == 'constructor_declaration':
            method_name = method_name or class_name
            raw_return_type = ""
            return_type = ""
        else:
            if not method_name:
                return None
            raw_return_type = self._field_text(node, 'type', source_code) or ""
            return_type = self.helper._resolve_type(raw_return_type) if raw_return_type else ""

        param_types, param_declared_types = self._parse_params(
            node.child_by_field_name('parameters'), source_code
        )

        symbol_id = f"{class_fqcn}#{method_name}@{self.file_path}:{node.start_point.row + 1}"
        declaration_text = self._node_text(node, source_code)
        start_row = node.start_point.row
        end_row = node.end_point.row
        annotations = self._collect_node_annotations(node, source_code)
        if not annotations and lines:
            annotations = self.helper._extract_leading_annotations(lines, start_row)
        modifiers = self._collect_node_modifiers(node, source_code) or self.helper._extract_modifiers(declaration_text)
        body_lines = tuple(lines[start_row:end_row + 1]) if lines else ()

        method_def = MethodDef(
            symbol_id=symbol_id,
            qualified_key=f"{class_fqcn}.{method_name}",
            simple_key=f"method:{method_name}",
            class_fqcn=class_fqcn,
            class_name=class_name,
            method_name=method_name,
            return_type=return_type,
            file=self.file_path,
            line=node.start_point.row + 1,
            end_line=node.end_point.row + 1,
            package_name=self.helper.package_name,
            owner_type=self.source_root.get('owner_type', 'business'),
            owner_coord=self.source_root.get('owner_coord', 'BUSINESS'),
            module=self.source_root.get('module', 'root'),
            source_root=self.source_root.get('root', ''),
            language=self.language,
            is_test=False,
            param_types=param_types,
            param_declared_types=param_declared_types,
            imports=dict(self.helper.imports),
            static_imports=dict(self.helper.static_imports),
            wildcard_imports=list(self.helper.wildcard_imports),
            field_types=dict(self.helper.field_types),
            field_declared_types=dict(self.helper.field_declared_types),
            annotations=annotations,
            modifiers=modifiers,
            class_annotations=class_annotations,
            is_static='static' in modifiers,
            is_interface=is_interface,
            body_text="",
            _body_lines=body_lines,
        )

        body_node = node.child_by_field_name('body')
        if body_node is not None:
            local_var_types, local_var_sites = self._collect_local_variable_types(body_node, source_code, method_def)
            method_def.local_var_types = local_var_types
            method_def.ast_local_var_sites = local_var_sites
            method_def.ast_call_sites = self._collect_call_sites(body_node, source_code, method_def, local_var_types)

        return method_def

    def _field_text(self, node, field_name, source_code):
        child = node.child_by_field_name(field_name)
        if not child:
            return None
        return source_code[child.start_byte:child.end_byte].decode('utf-8')

    def _node_text(self, node, source_code):
        return source_code[node.start_byte:node.end_byte].decode('utf-8')

    def _find_enclosing_types(self, node):
        """从方法节点向上找到所有嵌套的类型声明节点"""
        classes = []
        current = node.parent
        while current:
            if current.type in ('class_declaration', 'interface_declaration', 'enum_declaration'):
                classes.append(current)
            current = current.parent
        return list(reversed(classes))  # 恢复从外到内的顺序

    def _build_class_context(self, class_nodes, source_code, lines):
        """
        根据类型声明节点构建完整 FQCN 与类级上下文。
        """
        if not class_nodes:
            return "", "", [], False

        package_name = self.helper.package_name

        # 从外到内拼接类名
        parts = []
        class_annotations = []
        for cn in class_nodes:
            name_node = cn.child_by_field_name('name')
            if name_node:
                parts.append(self._node_text(name_node, source_code))
            else:
                parts.append('Unknown')
        innermost = class_nodes[-1]
        class_annotations = self._collect_node_annotations(innermost, source_code)
        if not class_annotations and lines:
            class_annotations = self.helper._extract_leading_annotations(lines, innermost.start_point.row)
        is_interface = innermost.type == 'interface_declaration'

        class_name = parts[-1]
        fqcn = '.'.join([package_name] + parts) if package_name else '.'.join(parts)
        return fqcn, class_name, class_annotations, is_interface

    def _parse_params(self, params_node, source_code):
        """解析参数列表"""
        param_types = {}
        param_declared_types = {}
        if not params_node:
            return param_types, param_declared_types

        for child in params_node.children:
            if child.type in {'formal_parameter', 'spread_parameter'}:
                # 提取参数类型
                type_node = child.child_by_field_name('type')
                name_node = child.child_by_field_name('name')

                if type_node and name_node:
                    raw_type = source_code[type_node.start_byte:type_node.end_byte].decode('utf-8')
                    param_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    param_types[param_name] = self.helper._resolve_type(raw_type)
                    param_declared_types[param_name] = raw_type.strip()
            elif child.type == 'receiver_parameter':
                type_node = child.child_by_field_name('type')
                name_node = child.child_by_field_name('name')
                if type_node and name_node:
                    raw_type = source_code[type_node.start_byte:type_node.end_byte].decode('utf-8')
                    param_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    param_types[param_name] = self.helper._resolve_type(raw_type)
                    param_declared_types[param_name] = raw_type.strip()

        return param_types, param_declared_types

    def _collect_local_variable_types(self, body_node, source_code, method_def):
        local_var_types = {}
        local_var_sites = []
        for node in self._walk_ast(body_node):
            if node.type != 'local_variable_declaration':
                continue
            type_node = node.child_by_field_name('type')
            declarator = node.child_by_field_name('declarator')
            if not type_node or not declarator:
                continue
            name_node = declarator.child_by_field_name('name')
            value_node = declarator.child_by_field_name('value')
            if not name_node:
                continue
            var_name = self._node_text(name_node, source_code).strip()
            declared_type = self._node_text(type_node, source_code).strip()
            initializer_expr = self._node_text(value_node, source_code).strip() if value_node is not None else ''
            resolved_type = None
            if _is_inferred_local_decl_type(declared_type, method_def):
                if value_node is not None:
                    resolved_type = self._infer_expression_type(value_node, source_code, method_def, local_var_types)
            else:
                resolved_type = self.helper._resolve_type(declared_type)
            local_var_sites.append({
                'name': var_name,
                'declared_type': declared_type,
                'initializer_expr': initializer_expr,
                'resolved_declared_type': resolved_type or '',
            })
            if resolved_type:
                local_var_types[var_name] = resolved_type
        return local_var_types, local_var_sites

    def _collect_call_sites(self, body_node, source_code, method_def, local_var_types):
        call_sites = []
        declared_local_types = {
            site.get('name', ''): site.get('resolved_declared_type') or site.get('declared_type', '')
            for site in getattr(method_def, 'ast_local_var_sites', []) or []
            if site.get('name')
        }

        def collect(node, scoped_local_types, scoped_declared_types):
            if node.type == 'lambda_expression':
                lambda_local_types, lambda_declared_types = self._infer_lambda_parameter_types(
                    node,
                    source_code,
                    method_def,
                    scoped_declared_types,
                )
                merged_local_types = dict(scoped_local_types)
                merged_local_types.update(lambda_local_types)
                merged_declared_types = dict(scoped_declared_types)
                merged_declared_types.update(lambda_declared_types)
                body_child = node.child_by_field_name('body')
                if body_child is not None:
                    collect(body_child, merged_local_types, merged_declared_types)
                return

            if node.type == 'method_invocation':
                name_node = node.child_by_field_name('name')
                if name_node:
                    object_node = node.child_by_field_name('object')
                    arguments_node = node.child_by_field_name('arguments')
                    arg_exprs = []
                    if arguments_node:
                        for child in arguments_node.children:
                            if child.type in {',', '(', ')'}:
                                continue
                            arg_exprs.append(self._node_text(child, source_code).strip())
                    call_sites.append({
                        'kind': 'method_invocation',
                        'receiver_expr': self._node_text(object_node, source_code).strip() if object_node else '',
                        'method_name': self._node_text(name_node, source_code).strip(),
                        'arg_exprs': arg_exprs,
                        'line': node.start_point.row + 1,
                        'content': self._node_text(node, source_code).strip()[:200],
                        'scope_local_var_types': dict(scoped_local_types),
                    })
            elif node.type == 'method_reference':
                reference_text = self._node_text(node, source_code).strip()
                if '::' in reference_text:
                    receiver_expr, method_name = [part.strip() for part in reference_text.split('::', 1)]
                    call_sites.append({
                        'kind': 'method_reference',
                        'receiver_expr': receiver_expr,
                        'method_name': method_name,
                        'arg_exprs': [],
                        'line': node.start_point.row + 1,
                        'content': reference_text[:200],
                        'scope_local_var_types': dict(scoped_local_types),
                    })
            elif node.type == 'object_creation_expression':
                type_node = node.child_by_field_name('type')
                if type_node is not None:
                    resolved_type = self.helper._resolve_type(self._node_text(type_node, source_code).strip())
                    arguments_node = node.child_by_field_name('arguments')
                    arg_exprs = []
                    if arguments_node:
                        for child in arguments_node.children:
                            if child.type in {',', '(', ')'}:
                                continue
                            arg_exprs.append(self._node_text(child, source_code).strip())
                    call_sites.append({
                        'kind': 'constructor_invocation',
                        'receiver_expr': '',
                        'receiver_type': resolved_type,
                        'method_name': resolved_type.rsplit('.', 1)[-1] if resolved_type else '',
                        'arg_exprs': arg_exprs,
                        'line': node.start_point.row + 1,
                        'content': self._node_text(node, source_code).strip()[:200],
                        'scope_local_var_types': dict(scoped_local_types),
                    })

            for child in node.children:
                collect(child, scoped_local_types, scoped_declared_types)

        collect(body_node, dict(local_var_types), declared_local_types)
        return call_sites

    def _infer_lambda_parameter_types(self, lambda_node, source_code, method_def, scoped_declared_types):
        lambda_local_types = {}
        lambda_declared_types = {}
        parameters_node = lambda_node.child_by_field_name('parameters')
        if parameters_node is None:
            return lambda_local_types, lambda_declared_types

        inferred_param_names = []
        parameter_nodes = []
        if parameters_node.type in {'identifier', 'inferred_parameter', 'formal_parameter', 'spread_parameter'}:
            parameter_nodes = [parameters_node]
        else:
            parameter_nodes = [child for child in parameters_node.children if child.type not in {',', '(', ')'}]

        for child in parameter_nodes:
            if child.type in {',', '(', ')'}:
                continue
            if child.type in {'formal_parameter', 'spread_parameter'}:
                type_node = child.child_by_field_name('type')
                name_node = child.child_by_field_name('name')
                if not name_node:
                    continue
                param_name = self._node_text(name_node, source_code).strip()
                raw_type = self._node_text(type_node, source_code).strip() if type_node is not None else ''
                if raw_type:
                    lambda_declared_types[param_name] = raw_type
                    lambda_local_types[param_name] = self.helper._resolve_type(raw_type)
            elif child.type in {'identifier', 'inferred_parameter'}:
                inferred_param_names.append(self._node_text(child, source_code).strip())

        if inferred_param_names:
            inferred_types = self._infer_lambda_parameter_types_from_context(
                lambda_node,
                source_code,
                method_def,
                scoped_declared_types,
                inferred_param_names,
            )
            for param_name in inferred_param_names:
                inferred_type = inferred_types.get(param_name)
                if inferred_type:
                    lambda_local_types[param_name] = inferred_type

        return lambda_local_types, lambda_declared_types

    def _infer_lambda_parameter_types_from_context(self, lambda_node, source_code, method_def, scoped_declared_types, inferred_param_names):
        inferred = {}
        if not inferred_param_names:
            return inferred

        current = lambda_node.parent
        invocation_node = None
        while current is not None:
            if current.type == 'method_invocation':
                invocation_node = current
                break
            current = current.parent

        if invocation_node is None:
            return inferred

        object_node = invocation_node.child_by_field_name('object')
        if object_node is None:
            return inferred

        receiver_node = object_node
        if receiver_node.type == 'method_invocation':
            receiver_name_node = receiver_node.child_by_field_name('name')
            receiver_method_name = self._node_text(receiver_name_node, source_code).strip() if receiver_name_node else ''
            if receiver_method_name in {'stream', 'parallelStream'}:
                upstream_object = receiver_node.child_by_field_name('object')
                if upstream_object is not None:
                    receiver_node = upstream_object

        raw_receiver_type = self._infer_expression_declared_type(
            receiver_node,
            source_code,
            method_def,
            scoped_declared_types,
        )
        element_type = extract_generic_type(raw_receiver_type or '')
        if not element_type:
            return inferred

        resolved_element_type = resolve_type_fqn(element_type, method_def)
        for param_name in inferred_param_names:
            inferred[param_name] = resolved_element_type
        return inferred

    def _infer_expression_declared_type(self, node, source_code, method_def, scoped_declared_types):
        if node is None:
            return None
        if node.type == 'identifier':
            name = self._node_text(node, source_code).strip()
            if name in scoped_declared_types:
                return scoped_declared_types[name]
            if name in method_def.param_declared_types:
                return method_def.param_declared_types[name]
            if name in method_def.field_declared_types:
                return method_def.field_declared_types[name]
            return None
        if node.type == 'field_access':
            object_node = node.child_by_field_name('object')
            field_node = node.child_by_field_name('field')
            if object_node is not None and object_node.type == 'this' and field_node is not None:
                field_name = self._node_text(field_node, source_code).strip()
                if field_name in method_def.field_declared_types:
                    return method_def.field_declared_types[field_name]
            if object_node is not None:
                return self._infer_expression_declared_type(object_node, source_code, method_def, scoped_declared_types)
            text = self._node_text(node, source_code).strip()
            base = text.split('.', 1)[0]
            if base in scoped_declared_types:
                return scoped_declared_types[base]
            if base in method_def.param_declared_types:
                return method_def.param_declared_types[base]
            if base in method_def.field_declared_types:
                return method_def.field_declared_types[base]
        return None

    def _infer_expression_type(self, node, source_code, method_def, local_var_types):
        if node is None:
            return None
        node_type = node.type

        if node_type == 'super':
            return _resolve_super_type(method_def)

        if node_type == 'identifier':
            name = self._node_text(node, source_code).strip()
            if name in local_var_types:
                return local_var_types[name]
            if name in method_def.param_types:
                return method_def.param_types[name]
            if name in method_def.field_types:
                return method_def.field_types[name]
            if name and name[0].isupper():
                return resolve_type_fqn(name, method_def)
            return None

        if node_type == 'this':
            return method_def.class_fqcn

        if node_type == 'object_creation_expression':
            type_node = node.child_by_field_name('type')
            if type_node:
                return self.helper._resolve_type(self._node_text(type_node, source_code))
            return None

        if node_type == 'method_invocation':
            object_node = node.child_by_field_name('object')
            name_node = node.child_by_field_name('name')
            arguments_node = node.child_by_field_name('arguments')
            method_name = self._node_text(name_node, source_code).strip() if name_node else ''
            if not method_name:
                return None
            if object_node is None:
                receiver_type = method_def.class_fqcn
            else:
                receiver_type = self._infer_expression_type(object_node, source_code, method_def, local_var_types)
            arg_exprs = []
            if arguments_node is not None:
                for child in arguments_node.children:
                    if child.type in {',', '(', ')'}:
                        continue
                    arg_exprs.append(self._node_text(child, source_code).strip())
            inferred_param_types = []
            for arg_expr in arg_exprs:
                inferred_type = infer_param_type_from_expression(arg_expr, method_def, local_var_types)
                if inferred_type:
                    inferred_param_types.append(inferred_type)
            invocation_signature = build_invocation_signature(arg_exprs, inferred_param_types)
            return infer_invocation_return_type(
                receiver_type,
                method_name,
                method_def,
                invocation_signature=invocation_signature,
            )

        if node_type == 'field_access':
            object_node = node.child_by_field_name('object')
            if object_node is not None:
                return self._infer_expression_type(object_node, source_code, method_def, local_var_types)
            text = self._node_text(node, source_code).strip()
            base = text.split('.', 1)[0]
            return local_var_types.get(base) or method_def.param_types.get(base) or method_def.field_types.get(base)

        if node_type == 'parenthesized_expression':
            for child in node.children:
                if child.type not in {'(', ')'}:
                    return self._infer_expression_type(child, source_code, method_def, local_var_types)
            return None

        if node_type == 'cast_expression':
            type_node = node.child_by_field_name('type')
            if type_node:
                return self.helper._resolve_type(self._node_text(type_node, source_code))
            return None

        if node_type == 'string_literal':
            return 'java.lang.String'
        if node_type in {'decimal_integer_literal', 'hex_integer_literal', 'binary_integer_literal', 'octal_integer_literal'}:
            return 'int'
        if node_type in {'decimal_floating_point_literal', 'hex_floating_point_literal'}:
            return 'double'
        if node_type in {'true', 'false', 'boolean_literal'}:
            return 'boolean'

        return None

    def _collect_node_annotations(self, node, source_code):
        annotations = []
        modifiers_node = next((child for child in node.children if child.type == 'modifiers'), None)
        if not modifiers_node:
            return annotations
        for child in modifiers_node.children:
            if child.type in ('marker_annotation', 'annotation'):
                annotation_text = self._node_text(child, source_code).strip()
                match = re.match(r'@([A-Za-z_]\w*)', annotation_text)
                if match:
                    annotations.append(match.group(1))
        return annotations

    def _collect_node_modifiers(self, node, source_code):
        modifiers = []
        modifiers_node = next((child for child in node.children if child.type == 'modifiers'), None)
        if not modifiers_node:
            return modifiers
        for child in modifiers_node.children:
            if child.type == 'marker_annotation' or child.type == 'annotation':
                continue
            token = self._node_text(child, source_code).strip()
            if token:
                modifiers.append(token)
        return modifiers


# ══════════════════════════════════════════════════════════════════
# 统一分析入口
# ══════════════════════════════════════════════════════════════════

def analyze_file(file_path, source_root, prefer_tree_sitter=True, return_diagnostics=False):
    """
    Unified source analysis entry point

    Auto-selects:
      - tree-sitter (installed and prefer_tree_sitter=True and language=java)
      - Enhanced regex (fallback, or Kotlin sources)

    Args:
        file_path: Source file path
        source_root: Source root config
        prefer_tree_sitter: Whether to prefer tree-sitter

    Returns:
        List[MethodDef] or (List[MethodDef], parser_info)

    Key fix: Kotlin doesn't support tree-sitter-java, must use enhanced regex
    """
    # Key fix: Kotlin sources must skip tree-sitter-java
    # tree-sitter-java only parses Java syntax, produces wrong AST for Kotlin
    is_kotlin = file_path.endswith('.kt') or file_path.endswith('.kts')
    parser_info = {
        'preferred_parser': 'tree_sitter' if prefer_tree_sitter and not is_kotlin else 'regex',
        'actual_parser': 'regex',
        'fallback_reason': '',
        'tree_sitter_available': TREE_SITTER_AVAILABLE,
        'language': 'kotlin' if is_kotlin else 'java',
        'error_nodes': 0,
    }

    methods = []
    if TREE_SITTER_AVAILABLE and prefer_tree_sitter and not is_kotlin:
        try:
            analyzer = TreeSitterAnalyzer(file_path, source_root)
            methods = analyzer.analyze()
            parser_info['actual_parser'] = 'tree_sitter'
            parser_info['error_nodes'] = getattr(analyzer, 'error_nodes', 0)
            has_valid_methodless_java = (
                os.path.basename(file_path) == 'package-info.java' or
                getattr(analyzer, 'has_type_declarations', False)
            )
            if analyzer.non_empty_source and not methods and not has_valid_methodless_java:
                raise RuntimeError('tree_sitter_empty_result')
        except Exception as exc:
            parser_info['actual_parser'] = 'regex'
            parser_info['fallback_reason'] = f"tree_sitter_runtime_error:{exc.__class__.__name__}"
            analyzer = EnhancedRegexAnalyzer(file_path, source_root)
            methods = analyzer.analyze()
    else:
        analyzer = EnhancedRegexAnalyzer(file_path, source_root)
        methods = analyzer.analyze()
        if is_kotlin:
            parser_info['fallback_reason'] = 'unsupported_language_kotlin'
        elif not TREE_SITTER_AVAILABLE and prefer_tree_sitter:
            parser_info['fallback_reason'] = 'tree_sitter_unavailable'
        elif not prefer_tree_sitter:
            parser_info['fallback_reason'] = 'prefer_tree_sitter_disabled'

    if return_diagnostics:
        return methods, parser_info
    return methods



def _strip_strings_and_comments(text):
    """
    从方法体中剥离字符串字面量、行注释、块注释。
    避免 "http://api.foo()" 或 /* x.foo() */ 等被误当成真实调用。
    """
    result = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        # 字符串字面量（双引号）——完全移除，包括引号
        if ch == '"':
            i += 1
            while i < n:
                c = text[i]
                if c == '\\':
                    i += 2  # 跳过转义序列
                elif c == '"':
                    i += 1  # 跳过右引号
                    break
                else:
                    i += 1
            # 不向result添加任何内容
        # 字符字面量（单引号）——完全移除
        elif ch == "'":
            i += 1
            while i < n:
                c = text[i]
                if c == '\\':
                    i += 2  # 跳过转义序列
                elif c == "'":
                    i += 1  # 跳过右引号
                    break
                else:
                    i += 1
        # 块注释
        elif ch == '/' and i + 1 < n and text[i + 1] == '*':
            end = text.find('*/', i + 2)
            if end >= 0:
                i = end + 2
            else:
                i = n
        # 行注释（但要确保 // 不在字符串内——已在上面处理）
        elif ch == '/' and i + 1 < n and text[i + 1] == '/':
            # 跳过到行尾
            while i < n and text[i] != '\n':
                i += 1
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


def extract_call_edges_enhanced(method_def, include_low_confidence=False):
    """
    提取调用边（增强版）

    先清理字符串字面量和注释，再做正则匹配，显著减少误报。

    【内存优化】支持延迟加载：优先使用 body_text，为空时使用 body_text_lazy
    """
    edges = []
    if method_def.language == 'java' and method_def.ast_call_sites:
        ast_edges = extract_ast_call_edges(method_def, include_low_confidence)
        if ast_edges:
            return ast_edges

    # 【优化】支持延迟加载：优先使用已缓存的 body_text
    body_text = method_def.body_text or method_def.body_text_lazy
    if not body_text:
        return edges

    # 清理后再提取
    cleaned = _strip_strings_and_comments(body_text)

    lambda_calls = extract_lambda_calls(cleaned, method_def)
    edges.extend(lambda_calls)

    method_refs = extract_method_refs(cleaned, method_def)
    edges.extend(method_refs)

    normal_calls = extract_normal_calls_enhanced(cleaned, method_def, include_low_confidence)
    edges.extend(normal_calls)

    return edges


def extract_ast_call_edges(method_def, include_low_confidence=False):
    edges = []
    seen = set()
    local_var_types = resolve_ast_local_var_types(method_def)

    for site in method_def.ast_call_sites:
        kind = site.get('kind')
        method_name = site.get('method_name', '')
        receiver_expr = site.get('receiver_expr', '')
        arg_exprs = site.get('arg_exprs', []) or []
        site_local_var_types = dict(local_var_types)
        site_local_var_types.update(site.get('scope_local_var_types') or {})
        callee_param_types = []
        for arg_expr in arg_exprs:
            inferred = infer_param_type_from_expression(arg_expr, method_def, site_local_var_types)
            callee_param_types.append(inferred or '')

        resolved_receiver_type = ''
        if kind == 'constructor_invocation':
            receiver_type = site.get('receiver_type', '')
            resolved_receiver_type = receiver_type
            confidence = 'high' if receiver_type else 'medium'
            callee_key = f"{receiver_type}.{method_name}" if receiver_type and method_name else f"method:{method_name}"
            callee_simple_key = f"method:{method_name}"
            evidence_type = 'constructor_invocation'
        elif kind == 'method_reference':
            if receiver_expr == 'this':
                resolved_receiver = method_def.class_fqcn
                confidence = 'high'
            elif receiver_expr == 'super':
                resolved_receiver = _resolve_super_type(method_def)
                confidence = 'high' if resolved_receiver else 'medium'
            elif _looks_like_static_receiver_expr(receiver_expr, method_def, site_local_var_types):
                resolved_receiver = resolve_type_fqn(receiver_expr, method_def)
                confidence = 'high'
            elif receiver_expr and receiver_expr[0].isupper():
                resolved_receiver = resolve_type_fqn(receiver_expr, method_def)
                confidence = 'high'
            else:
                resolved_receiver = infer_receiver_type_enhanced(receiver_expr, method_def, site_local_var_types)
                confidence = 'high' if resolved_receiver else 'medium'
            resolved_receiver_type = resolved_receiver or ''
            callee_key = f"{resolved_receiver}.{method_name}" if resolved_receiver else f"method:{method_name}"
            callee_simple_key = f"method:{method_name}"
            evidence_type = 'method_reference'
        else:
            if not receiver_expr:
                receiver_type = method_def.class_fqcn
                resolved_receiver_type = receiver_type
                confidence = 'high'
                callee_key = f"{receiver_type}.{method_name}"
            else:
                if receiver_expr == 'super':
                    receiver_type = _resolve_super_type(method_def)
                    confidence = 'high' if receiver_type else 'medium'
                elif _looks_like_static_receiver_expr(receiver_expr, method_def, site_local_var_types):
                    receiver_type = resolve_type_fqn(receiver_expr, method_def)
                    confidence = 'high'
                else:
                    receiver_type = infer_receiver_type_enhanced(receiver_expr, method_def, site_local_var_types)
                    confidence = 'high' if receiver_type else 'low'
                resolved_receiver_type = receiver_type or ''
                callee_key = f"{receiver_type}.{method_name}" if receiver_type else f"method:{method_name}"
            callee_simple_key = f"method:{method_name}"
            evidence_type = 'ast_method_invocation'

        # Method references are not concrete call expressions, so an empty arg list
        # here does not mean the referenced target is a zero-arg overload.
        sig_str = '' if kind == 'method_reference' else build_invocation_signature(arg_exprs, callee_param_types)
        if not sig_str and kind != 'method_reference':
            sig_str = resolve_invocation_signature_from_partial_hints(
                resolved_receiver_type,
                method_name,
                callee_param_types,
                method_def,
            )
        if not sig_str and kind != 'method_reference' and arg_exprs:
            _step5_debug(
                'call_edge_signature',
                'signature missing after argument inference',
                method=getattr(method_def, 'qualified_key', ''),
                receiver_expr=receiver_expr,
                receiver_type=resolved_receiver_type,
                callee_method=method_name,
                arg_exprs=arg_exprs,
                arg_type_hints=callee_param_types,
                evidence_type=evidence_type,
            )
        if sig_str:
            callee_key = f"{callee_key}{sig_str}"
            callee_simple_key = f"{callee_simple_key}{sig_str}"

        edge_key = (callee_key, callee_simple_key, site.get('line'), evidence_type)
        if edge_key in seen:
            continue
        seen.add(edge_key)
        edges.append(CallEdge(
            caller_symbol_id=method_def.symbol_id,
            caller_qualified_key=method_def.qualified_key,
            callee_key=callee_key,
            callee_simple_key=callee_simple_key,
            evidence_type=evidence_type,
            confidence=confidence,
            file=method_def.file,
            line=site.get('line') or method_def.line,
            content=site.get('content', '')[:100],
            owner_type=method_def.owner_type,
            owner_coord=method_def.owner_coord,
            module=method_def.module,
            is_test=method_def.is_test,
            callee_param_types=callee_param_types,
        ))

    return edges


def build_invocation_signature(arg_exprs, inferred_param_types):
    """
    仅在签名信息完整时生成调用签名：
      - 0 参数调用统一生成 ()
      - N 参数调用只有在 N 个参数类型都成功推断时才生成
    """
    arg_count = len(arg_exprs or [])
    if arg_count == 0:
        return '()'
    if len(inferred_param_types or []) != arg_count:
        return ''
    if any(not str(item or '').strip() for item in (inferred_param_types or [])):
        return ''
    return '(' + ', '.join(inferred_param_types) + ')'


def _build_signature_from_param_values(param_values):
    values = [str(item or '').strip() for item in (param_values or []) if str(item or '').strip()]
    if not values:
        return '()'
    normalized = []
    for item in values:
        text = item.replace('...', '[]')
        if '<' in text:
            text = text.split('<', 1)[0].strip()
        if '.' in text:
            text = text.rsplit('.', 1)[-1]
        normalized.append(text)
    return '(' + ', '.join(normalized) + ')'


def _is_inferred_local_decl_type(declared_type, method_def=None):
    declared_type = (declared_type or '').strip()
    if not declared_type:
        return False
    if declared_type in {'var', 'val', 'lombok.val'}:
        return True
    imports = getattr(method_def, 'imports', {}) or {}
    return declared_type in imports and imports.get(declared_type) == 'lombok.val'


def _resolve_super_type(method_def):
    type_metadata = getattr(method_def, 'known_type_metadata', {}) or {}
    class_meta = type_metadata.get(getattr(method_def, 'class_fqcn', ''), {}) or {}
    extends = class_meta.get('extends', []) or []
    if extends:
        return extends[0]
    return None


def _looks_like_static_receiver_expr(receiver_expr, method_def, local_var_types=None):
    expr = (receiver_expr or '').strip()
    if not expr or expr in {"this", "super", "class"} or '(' in expr:
        return False

    local_var_types = local_var_types or {}
    root = expr.split('.', 1)[0]
    leaf = expr.rsplit('.', 1)[-1]
    if not leaf or not leaf[0].isupper():
        return False
    if root in local_var_types:
        return False
    if root in getattr(method_def, 'field_types', {}):
        return False
    if root in getattr(method_def, 'param_types', {}):
        return False
    return True


def extract_lambda_calls(body_text, method_def):
    """
    提取Lambda表达式调用（增强版）

    示例：
      list.stream().map(x -> x.changedMethod())
      orders.stream().filter(order -> order.isValid())

    增强改进：
      1. 推断Lambda参数类型（从Stream/Collection泛型推断）
      2. 提高置信度（从medium改为high，当类型可推断时）
      3. 生成完整的callee_key（而不是只有method:name）
    """
    edges = []

    # 增强：提取Lambda前的上下文，推断Stream元素类型
    # 例如: List<Order> orders; orders.stream().map(x -> x.method())
    # 需要推断 x 的类型是 Order
    lambda_context_type = infer_lambda_parameter_type_from_context(body_text, method_def)

    for m in LAMBDA_RE.finditer(body_text):
        lambda_expr = m.group(0)
        lambda_body = m.group(1)

        # 从Lambda body提取调用
        # 支持: x.method(), x.field.method(), x.method().method2()
        call_m = re.search(r'([a-zA-Z_]\w*)\s*\.\s*([a-zA-Z_]\w*)\s*\(', lambda_body)
        if call_m:
            receiver = call_m.group(1)
            callee_method = call_m.group(2)

            # 【增强】尝试推断receiver类型
            receiver_type = None

            # 1. 从上下文推断（Stream元素类型）
            if lambda_context_type and receiver in lambda_context_type:
                receiver_type = lambda_context_type[receiver]

            # 2. 从字段/参数类型推断
            if not receiver_type:
                receiver_type = method_def.field_types.get(receiver) or method_def.param_types.get(receiver)

            # 3. 构建调用边
            if receiver_type:
                # 类型已推断，使用完整FQN，提高置信度
                callee_key = f"{receiver_type}.{callee_method}"
                confidence = 'high'  # 提升置信度
            else:
                # 类型未推断，降级为简单方法名
                callee_key = f"method:{callee_method}"
                confidence = 'medium'  # Lambda路径仍不确定

            edges.append(CallEdge(
                caller_symbol_id=method_def.symbol_id,
                caller_qualified_key=method_def.qualified_key,
                callee_key=callee_key,  # 使用增强的key
                callee_simple_key=f"method:{callee_method}",
                evidence_type='lambda_call',
                confidence=confidence,  # 动态置信度
                file=method_def.file,
                line=method_def.line,
                content=lambda_expr[:100],
                owner_type=method_def.owner_type,
                owner_coord=method_def.owner_coord,
                module=method_def.module,
                is_test=method_def.is_test
            ))

    return edges


def infer_lambda_parameter_type_from_context(body_text, method_def):
    """
    从Lambda上下文推断参数类型

    策略：
      1. 识别 collection.stream() 模式，提取collection的泛型类型
      2. 识别 Stream<Type> 变量声明
      3. 从方法返回值推断

    返回：
      dict: {lambda_param_name: inferred_type}

    示例：
      List<Order> orders = ...;
      orders.stream().filter(order -> order.isValid())
      -> {'order': 'Order'}
    """
    lambda_param_types = {}

    # 模式1: collection.stream().operation(param -> ...)
    # 提取 collection 的类型
    stream_pattern = re.compile(
        r'([a-zA-Z_]\w*)\s*\.\s*stream\s*\(\s*\)\s*\.\s*\w+\s*\(\s*([a-zA-Z_]\w*)\s*->'
    )

    for match in stream_pattern.finditer(body_text):
        collection_var = match.group(1)
        lambda_param = match.group(2)

        # 从字段/参数推断collection类型
        collection_type = method_def.field_types.get(collection_var) or method_def.param_types.get(collection_var)

        if collection_type:
            # 提取泛型参数: List<Order> -> Order
            element_type = extract_generic_type(collection_type)
            if element_type:
                lambda_param_types[lambda_param] = element_type

    # 模式2: Stream<Type> 变量声明
    # Stream<Order> orderStream = ...; orderStream.filter(order -> ...)
    stream_var_pattern = re.compile(
        r'Stream\s*<\s*([A-Za-z_]\w*)\s*>\s+([a-zA-Z_]\w*)'
    )

    for match in stream_var_pattern.finditer(body_text):
        element_type = match.group(1)
        stream_var = match.group(2)

        # 查找该stream变量后续的Lambda
        lambda_usage = re.search(
            rf'{stream_var}\s*\.\s*\w+\s*\(\s*([a-zA-Z_]\w*)\s*->',
            body_text
        )
        if lambda_usage:
            lambda_param = lambda_usage.group(1)
            # 解析element_type为完整FQN
            resolved_type = resolve_type_fqn(element_type, method_def)
            lambda_param_types[lambda_param] = resolved_type

    return lambda_param_types


def extract_generic_type(type_expr):
    """
    提取泛型类型参数

    示例：
      List<Order> -> Order
      Map<String, Order> -> String (取第一个)
      Optional<User> -> User
    """
    match = re.search(r'<\s*([A-Za-z_][\w.]*)', type_expr)
    if match:
        return match.group(1)
    return None


def extract_method_refs(body_text, method_def):
    """
    提取方法引用（增强版）

    示例：
      stream().map(Foo::changedMethod)  // 静态方法引用或实例方法引用
      stream().map(Order::toDTO)        // 实例方法引用

    增强改进：
      1. 区分静态方法引用和实例方法引用
      2. 对于实例方法引用，尝试推断类型
      3. 提高置信度（当类型明确时）
    """
    edges = []

    for m in METHOD_REF_RE.finditer(body_text):
        target_class = m.group(1)
        target_method = m.group(2)

        # 解析目标类FQN
        target_fqn = resolve_type_fqn(target_class, method_def)

        # 【增强】判断是否是实例方法引用
        # 如果target_class在字段/参数中，说明是对象引用，需要推断其类型
        if target_class in method_def.field_types or target_class in method_def.param_types:
            # 这是对象引用: obj::method
            instance_type = method_def.field_types.get(target_class) or method_def.param_types.get(target_class)
            if instance_type:
                target_fqn = instance_type

        # 判断置信度
        # 类方法引用（ClassName::method）: high
        # 实例方法引用（obj::method）: medium（取决于是否推断出类型）
        if target_fqn and ('.' in target_fqn or target_fqn[0].isupper()):
            confidence = 'high'
        else:
            confidence = 'medium'

        edges.append(CallEdge(
            caller_symbol_id=method_def.symbol_id,
            caller_qualified_key=method_def.qualified_key,
            callee_key=f"{target_fqn}.{target_method}",
            callee_simple_key=f"method:{target_method}",
            evidence_type='method_reference',
            confidence=confidence,  # 动态置信度
            file=method_def.file,
            line=method_def.line,
            content=m.group(0),
            owner_type=method_def.owner_type,
            owner_coord=method_def.owner_coord,
            module=method_def.module,
            is_test=method_def.is_test
        ))

    return edges


def extract_normal_calls_enhanced(body_text, method_def, include_low_confidence):
    """
    提取普通方法调用（增强：类型推断）

    改进：
      - 链式调用：obj.method1().method2()
      - 字段访问：this.field.method()
      - 参数传递：param.method()
    """
    edges = []

    # 简化版：后续完整实现需要类型传播图
    # 当前使用正则匹配 + 简单类型推断

    call_pattern = re.compile(
        r'((?:this|[a-zA-Z_]\w*)(?:\([^)]*\))?(?:\.(?:[a-zA-Z_]\w*)(?:\([^)]*\))?)*)\s*\.\s*([a-zA-Z_]\w*)\s*\(([^)]*)\)'
    )

    for m in call_pattern.finditer(body_text):
        receiver_expr = m.group(1)
        callee_method = m.group(2)
        params_str = m.group(3).strip() if m.lastindex >= 3 else ''

        # Extract parameter types for signature matching
        callee_param_types = []
        if params_str:
            # Parse argument expressions to infer types
            for param in params_str.split(','):
                param = param.strip()
                if param:
                    # Try to infer type from the expression
                    inferred_type = infer_param_type_from_expression(param, method_def)
                    callee_param_types.append(inferred_type or '')

        # Key fix: detect static call ClassName.staticMethod()
        # ClassName starts with uppercase, not this/field/param
        is_static_call = _looks_like_static_receiver_expr(receiver_expr, method_def)

        resolved_receiver_type = ''
        if is_static_call:
            # Static call, resolve class FQN
            resolved_type = resolve_type_fqn(receiver_expr, method_def)
            resolved_receiver_type = resolved_type
            callee_key = f"{resolved_type}.{callee_method}"
            confidence = "high"
        elif receiver_expr == "super":
            receiver_type = _resolve_super_type(method_def)
            if receiver_type:
                resolved_receiver_type = receiver_type
                callee_key = f"{receiver_type}.{callee_method}"
                confidence = "high"
            else:
                callee_key = f"method:{callee_method}"
                confidence = "low"
        else:
            # Instance call, infer receiver type
            receiver_type = infer_receiver_type_enhanced(receiver_expr, method_def)
            if receiver_type:
                resolved_receiver_type = receiver_type
                callee_key = f"{receiver_type}.{callee_method}"
                confidence = "high"
            else:
                callee_key = f"method:{callee_method}"
                confidence = "low"

        # 仅在签名完整时生成签名 key，避免半截类型误导重载匹配
        sig_str = build_invocation_signature(
            [p.strip() for p in params_str.split(',') if p.strip()] if params_str else [],
            callee_param_types,
        )
        if not sig_str and params_str:
            sig_str = resolve_invocation_signature_from_partial_hints(
                resolved_receiver_type,
                callee_method,
                callee_param_types,
                method_def,
            )
        if not sig_str and params_str:
            _step5_debug(
                'call_edge_signature',
                'regex path signature missing after argument inference',
                method=getattr(method_def, 'qualified_key', ''),
                receiver_expr=receiver_expr,
                receiver_type=resolved_receiver_type,
                callee_method=callee_method,
                params_str=params_str,
                arg_type_hints=callee_param_types,
                evidence_type='instance_call',
            )
        if sig_str:
            callee_key_with_sig = f"{callee_key}{sig_str}"
            callee_simple_key_with_sig = f"method:{callee_method}{sig_str}"
        else:
            callee_key_with_sig = callee_key
            callee_simple_key_with_sig = f"method:{callee_method}"

        edges.append(CallEdge(
            caller_symbol_id=method_def.symbol_id,
            caller_qualified_key=method_def.qualified_key,
            callee_key=callee_key_with_sig,
            callee_simple_key=callee_simple_key_with_sig,
            evidence_type='instance_call',
            confidence=confidence,
            file=method_def.file,
            line=method_def.line,
            content=m.group(0)[:100],
            owner_type=method_def.owner_type,
            owner_coord=method_def.owner_coord,
            module=method_def.module,
            is_test=method_def.is_test,
            callee_param_types=callee_param_types
        ))

    return edges


def resolve_type_fqn(type_expr, method_def):
    """Resolve type FQN (improved version)

    Improvements:
      1. Check if it's inner class of current class
      2. Check if it's common Java class (java.lang.*, java.util.*)
      3. Resolve imported outer-class inner-class references (Foo.Inner)
      4. Search method_def field_types/param_types for matching simple class name
      5. Otherwise return original expr (tracer will match via simple_key)
    """
    if not type_expr:
        return type_expr

    # Current class or inner class
    if type_expr == method_def.class_name or type_expr.startswith(method_def.class_name + "."):
        if "." not in type_expr:
            return method_def.class_fqcn
        inner_suffix = type_expr.split(".", 1)[1]
        return f"{method_def.class_fqcn}.{inner_suffix}"

    # Common Java classes (reduce false positives)
    java_lang_classes = ["String", "Integer", "Long", "Double", "Float", "Boolean", "Object", "Class", "Exception", "RuntimeException"]
    java_util_classes = ["List", "ArrayList", "Map", "HashMap", "Set", "HashSet", "Optional", "Stream", "Collector"]

    if type_expr in java_lang_classes:
        return f"java.lang.{type_expr}"
    if type_expr in java_util_classes:
        return f"java.util.{type_expr}"

    imports = getattr(method_def, 'imports', {}) or {}
    if type_expr in imports:
        return imports[type_expr]
    if '.' in type_expr:
        outer, inner_suffix = type_expr.split('.', 1)
        if outer in imports:
            return f"{imports[outer]}.{inner_suffix}"

    # Search field types
    for field_type in method_def.field_types.values():
        if field_type.endswith(f".{type_expr}") or field_type == type_expr:
            return field_type

    # Search param types
    for param_type in method_def.param_types.values():
        if param_type.endswith(f".{type_expr}") or param_type == type_expr:
            return param_type

    package_name = getattr(method_def, 'package_name', '') or ''
    if package_name and '.' not in type_expr:
        return f"{package_name}.{type_expr}"

    # Not found, return original (tracer will use simple_key matching)
    return type_expr


def infer_invocation_return_type(receiver_type, method_name, method_def, invocation_signature=''):
    if not method_name:
        return None

    known_method_return_types = getattr(method_def, 'known_method_return_types', {}) or {}
    known_method_return_types_by_signature = (
        getattr(method_def, 'known_method_return_types_by_signature', {}) or {}
    )
    invocation_signature = (invocation_signature or '').strip()
    normalized_signature = normalize_signature_for_lookup(invocation_signature)

    def _match_from_bucket(bucket):
        if not bucket:
            return None
        if isinstance(bucket, str):
            return bucket
        if not isinstance(bucket, dict):
            return None
        if invocation_signature and bucket.get(invocation_signature):
            return bucket.get(invocation_signature)
        if normalized_signature and bucket.get(normalized_signature):
            return bucket.get(normalized_signature)
        if len(bucket) == 1:
            return next(iter(bucket.values()))
        return None

    if receiver_type == method_def.class_fqcn:
        matched = _match_from_bucket(method_def.local_method_return_types.get(method_name))
        if matched:
            return matched
    if receiver_type and receiver_type in known_method_return_types_by_signature:
        matched = _match_from_bucket(
            known_method_return_types_by_signature.get(receiver_type, {}).get(method_name)
        )
        if matched:
            return matched
    if receiver_type and receiver_type in known_method_return_types:
        bucket = known_method_return_types.get(receiver_type, {})
        if isinstance(bucket, dict):
            direct = bucket.get(method_name)
            if isinstance(direct, str):
                return direct
            if isinstance(direct, dict):
                matched = _match_from_bucket(direct)
                if matched:
                    return matched
    return None


def resolve_ast_local_var_types(method_def):
    local_var_types = dict(getattr(method_def, 'local_var_types', {}) or {})
    for site in getattr(method_def, 'ast_local_var_sites', []) or []:
        name = site.get('name', '')
        declared_type = site.get('declared_type', '')
        initializer_expr = (site.get('initializer_expr') or '').strip()
        resolved_type = (site.get('resolved_declared_type') or '').strip() or None
        if not resolved_type and declared_type and not _is_inferred_local_decl_type(declared_type, method_def):
            resolved_type = resolve_type_fqn(declared_type, method_def)
        elif not resolved_type and initializer_expr:
            resolved_type = infer_expression_type_from_text(initializer_expr, method_def, local_var_types)
        if name and resolved_type:
            local_var_types[name] = resolved_type
    method_def.local_var_types = local_var_types
    return local_var_types


def infer_expression_type_from_text(expr, method_def, local_var_types=None):
    expr = _strip_balanced_outer_parens((expr or '').strip())
    if not expr:
        return None
    local_var_types = local_var_types or getattr(method_def, 'local_var_types', {}) or {}

    if expr.startswith('new '):
        match = re.match(r'new\s+([A-Za-z_][\w.]*)', expr)
        if match:
            return resolve_type_fqn(match.group(1), method_def)

    direct = infer_receiver_type_enhanced(expr, method_def, local_var_types)
    if direct:
        return direct

    bare_method_call_match = re.match(r'^(?P<method>[A-Za-z_]\w*)\s*\((?P<args>.*)\)$', expr)
    if bare_method_call_match:
        method_name = bare_method_call_match.group('method').strip()
        args_text = bare_method_call_match.group('args').strip()
        arg_exprs = [part.strip() for part in args_text.split(',') if part.strip()] if args_text else []
        inferred_param_types = []
        for arg_expr in arg_exprs:
            inferred_type = infer_param_type_from_expression(arg_expr, method_def, local_var_types)
            if inferred_type:
                inferred_param_types.append(inferred_type)
        invocation_signature = build_invocation_signature(arg_exprs, inferred_param_types)
        return infer_invocation_return_type(
            method_def.class_fqcn,
            method_name,
            method_def,
            invocation_signature=invocation_signature,
        )

    if expr[0].isupper():
        return resolve_type_fqn(expr, method_def)

    return None


def _to_simple_type_name(type_name):
    if not type_name:
        return None
    base = re.sub(r'<.*?>', '', type_name).strip()
    if not base:
        return None
    return base.rsplit('.', 1)[-1]


def infer_known_library_method_return_type(receiver_type, method_name):
    """
    为少量高置信度 JDK/库方法提供返回类型兜底。
    这里只补稳定场景，避免把签名匹配放宽成误报源。
    """
    if not receiver_type or not method_name:
        return None

    normalized_receiver = re.sub(r'<.*?>', '', receiver_type).strip()
    simple_receiver = normalized_receiver.rsplit('.', 1)[-1]
    receiver_candidates = {normalized_receiver, simple_receiver}

    if method_name == 'toString':
        return 'java.lang.String'

    if receiver_candidates & {'java.lang.Class', 'Class'}:
        if method_name in {'getCanonicalName', 'getName', 'getSimpleName', 'getTypeName'}:
            return 'java.lang.String'

    return None


def infer_param_type_from_expression(expr, method_def, local_var_types=None):
    """
    Infer parameter type from expression for signature matching

    Supports:
      - Literal values: "string", 123, true → String, int, boolean
      - Variable references: param → param_types
      - Field access: this.field → field_types
      - Class references: ClassName.class → Class
      - Stable method-call expressions: clazz.getCanonicalName() → String
    """
    expr = _strip_balanced_outer_parens(expr.strip())
    local_var_types = local_var_types or getattr(method_def, 'local_var_types', {}) or {}

    # String literal
    if expr.startswith('"') and expr.endswith('"'):
        return 'String'

    # String concatenation like `"prefix" + value` should also be treated as String.
    if '+' in expr and '"' in expr:
        return 'String'

    # Numeric literal
    if expr.isdigit() or (expr.replace('.', '').isdigit() and expr.count('.') == 1):
        if '.' in expr:
            return 'double'
        else:
            return 'int'

    # Boolean literal
    if expr in ('true', 'false'):
        return 'boolean'

    # Null literal
    if expr == 'null':
        return 'Object'

    # Class literal (ClassName.class) should match declared parameter type `Class`
    if expr.endswith('.class'):
        return 'Class'

    # this.field access
    if expr.startswith('this.'):
        field_name = expr[5:]
        if field_name in method_def.field_types:
            fqn = method_def.field_types[field_name]
            return fqn.rsplit('.', 1)[-1] if '.' in fqn else fqn

    # Parameter reference
    if expr in method_def.param_types:
        fqn = method_def.param_types[expr]
        return fqn.rsplit('.', 1)[-1] if '.' in fqn else fqn

    # Local variable reference
    if expr in local_var_types:
        fqn = local_var_types[expr]
        return fqn.rsplit('.', 1)[-1] if '.' in fqn else fqn

    # Field reference
    if expr in method_def.field_types:
        fqn = method_def.field_types[expr]
        return fqn.rsplit('.', 1)[-1] if '.' in fqn else fqn

    # Method invocation (receiver.method(...))
    method_call_match = re.match(r'^(?P<receiver>.+)\.(?P<method>[A-Za-z_]\w*)\s*\((?P<args>.*)\)$', expr)
    if method_call_match:
        receiver_expr = method_call_match.group('receiver').strip()
        method_name = method_call_match.group('method').strip()
        args_text = method_call_match.group('args').strip()
        arg_exprs = []
        if args_text:
            arg_exprs = [part.strip() for part in args_text.split(',') if part.strip()]
        inferred_param_types = []
        for arg_expr in arg_exprs:
            inferred_type = infer_param_type_from_expression(arg_expr, method_def, local_var_types)
            if inferred_type:
                inferred_param_types.append(inferred_type)
        invocation_signature = build_invocation_signature(arg_exprs, inferred_param_types)
        receiver_type = infer_expression_type_from_text(receiver_expr, method_def, local_var_types)
        return_type = infer_invocation_return_type(
            receiver_type,
            method_name,
            method_def,
            invocation_signature=invocation_signature,
        )
        if not return_type:
            return_type = infer_known_library_method_return_type(receiver_type, method_name)
        _step5_debug(
            'param_type_inference',
            'method call expression inferred',
            expr=expr,
            receiver_expr=receiver_expr,
            receiver_type=receiver_type,
            method_name=method_name,
            invocation_signature=invocation_signature,
            return_type=return_type,
        )
        simple_name = _to_simple_type_name(return_type)
        if simple_name:
            return simple_name

    _step5_debug(
        'param_type_inference',
        'expression type inference fell back to unknown',
        expr=expr,
        method=getattr(method_def, 'qualified_key', ''),
    )

    # Static field access (ClassName.FIELD)
    if '.' in expr and expr[0].isupper():
        parts = expr.split('.')
        return parts[0]  # Use class name as type hint

    # Variable name starting with lowercase - try to match param/field
    if expr[0].islower():
        # Try parameter names first
        if expr in method_def.param_types:
            fqn = method_def.param_types[expr]
            return fqn.rsplit('.', 1)[-1] if '.' in fqn else fqn
        # Try field names
        if expr in method_def.field_types:
            fqn = method_def.field_types[expr]
            return fqn.rsplit('.', 1)[-1] if '.' in fqn else fqn

    return None


def infer_receiver_type_enhanced(expr, method_def, local_var_types=None):
    """
    推断receiver类型（��强版）

    支持：
      - this → 当前类
      - field → 字段类型
      - param → 参数类型
      - method() → 返回值类型
    """
    local_var_types = local_var_types or getattr(method_def, 'local_var_types', {}) or {}

    if expr == 'this':
        return method_def.class_fqcn
    if expr == 'super':
        return _resolve_super_type(method_def)

    if expr.startswith('this.'):
        expr = expr[5:]
    elif expr.startswith('super.'):
        expr = expr[6:]

    if expr in local_var_types:
        return local_var_types[expr]

    # 字段
    if expr in method_def.field_types:
        return method_def.field_types[expr]

    # 参数
    if expr in method_def.param_types:
        return method_def.param_types[expr]

    if _looks_like_static_receiver_expr(expr, method_def, local_var_types):
        return resolve_type_fqn(expr, method_def)

    if '.' in expr and '(' not in expr:
        root = expr.split('.', 1)[0]
        if root in local_var_types:
            return local_var_types[root]
        if root in method_def.field_types:
            return method_def.field_types[root]
        if root in method_def.param_types:
            return method_def.param_types[root]

    # 支持 getClient().call() / this.getClient().call() 这类常见零参数工厂调用
    if expr.endswith('()'):
        base_call = expr.rsplit('.', 1)[-1]
        if base_call.endswith('()'):
            callee = base_call[:-2]
            receiver_root = expr.rsplit('.', 1)[0] if '.' in expr else ''
            receiver_type = infer_receiver_type_enhanced(receiver_root, method_def, local_var_types) if receiver_root else method_def.class_fqcn
            return infer_invocation_return_type(receiver_type, callee, method_def, invocation_signature='()')

    # 方法返回值（简化版）
    # 注：更深层的类型传播仍需要全局类型图
    return None


# ══════════════════════════════════════════════════════════════════
# 测试入口
# ══════════════════════════════════════════════════════════════════

def test_analyzer(file_path):
    """测试增强分析器"""
    source_root = {
        'root': os.path.dirname(file_path),
        'owner_type': 'business',
        'owner_coord': 'BUSINESS',
        'module': 'test'
    }

    methods = analyze_file(file_path, source_root)

    print(f"\n文件：{file_path}")
    print(f"识别方法数：{len(methods)}")

    for method in methods[:5]:
        print(f"\n方法：{method.method_name}")
        print(f"  FQN：{method.qualified_key}")
        print(f"  返回值：{method.return_type}")
        print(f"  参数：{method.param_types}")
        print(f"  注解：{method.annotations}")
        print(f"  修饰符：{method.modifiers}")

    return methods


def main():
    ap = argparse.ArgumentParser(description='增强型源码分析器')
    ap.add_argument('--file', required=True, help='测试文件路径')
    ap.add_argument('--tree-sitter', action='store_true', help='优先使用tree-sitter')
    args = ap.parse_args()

    test_analyzer(args.file)
    return 0


if __name__ == '__main__':
    sys.exit(main())
