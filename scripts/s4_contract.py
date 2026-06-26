"""
s4_contract.py — Step 4 与 Step 5 之间的数据契约

all_changed_apis.csv 是 Step 4 的核心输出，Step 5 的核心输入。
格式在此文件中唯一定义，两侧脚本都 import 这里的常量，不允许各自硬编码。
"""

import re

# CSV 字段定义（顺序固定，不可随意调整）
ALL_CHANGED_APIS_FIELDS = [
    "coord",         # groupId:artifactId — 来自哪个依赖包
    "old_version",   # 旧版本号
    "new_version",   # 新版本号
    "change_type",   # REMOVED / SIGNATURE_CHANGED / BEHAVIOR_CHANGED / ACCESS_REDUCED
    "api_name",      # 完整限定名，如 javax.xml.bind.JAXBContext.newInstance
                     # Step 5 主 grep 关键词（置信度：高）
    "api_simple",    # 简单名，如 JAXBContext 或 newInstance
                     # Step 5 备用 grep 关键词（置信度：中，可能有同名方法）
    "symbol_kind",   # method / field / class / constructor
                     # 明确告诉 Step 5 当前变更符号的类型，避免靠命名猜测
    "api_signature", # 参数签名，如 (String) 或 (ClassLoader[])
                     # 仅 method/constructor 使用；空字符串表示无参数或签名未知
    "confirmed",     # "true"  = JApiCmp 二进制确认，结论可靠
                     # "false" = changelog 推断，需人工验证
    "severity",      # P0 / P1 / P2
    "source",        # japicmp / gitdiff / changelog
]

# change_type 枚举
CHANGE_TYPES = {
    "REMOVED":           "API 被删除，调用方编译必然失败",
    "SIGNATURE_CHANGED": "方法签名变更（参数/返回类型），编译失败",
    "BEHAVIOR_CHANGED":  "签名未变但行为变更，编译通过但运行时可能异常",
    "ACCESS_REDUCED":    "访问权限降低（public→protected），编译失败",
}

# severity 与 change_type 的默认映射
DEFAULT_SEVERITY = {
    "REMOVED":           "P0",
    "SIGNATURE_CHANGED": "P0",
    "ACCESS_REDUCED":    "P0",
    "BEHAVIOR_CHANGED":  "P2",  # 行为变更需运行时才能确认
}

# source 枚举
SOURCES = ["japicmp", "gitdiff", "changelog"]

SYMBOL_KINDS = {"method", "field", "class", "constructor"}


def validate_row(row: dict) -> list:
    """
    验证单行数据是否符合契约，返回错误列表（空表示合法）。
    Step 4 写入时调用，确保输出质量。
    """
    errors = []
    # api_signature 可以为空（签名未知的情况，如 git diff 提取的 BEHAVIOR_CHANGED、
    # 类级变更、字段变更等）
    required_fields = [f for f in ALL_CHANGED_APIS_FIELDS if f != 'api_signature']
    for field in required_fields:
        if field not in row or not str(row[field]).strip():
            errors.append(f"字段 '{field}' 缺失或为空")

    if row.get("change_type") and row["change_type"] not in CHANGE_TYPES:
        errors.append(f"change_type '{row['change_type']}' 不在允许值范围内")

    if row.get("severity") and row["severity"] not in ("P0", "P1", "P2"):
        errors.append(f"severity '{row['severity']}' 不在允许值范围内")

    if row.get("source") and row["source"] not in SOURCES:
        errors.append(f"source '{row['source']}' 不在允许值范围内")

    if row.get("symbol_kind") and row["symbol_kind"] not in SYMBOL_KINDS:
        errors.append(f"symbol_kind '{row['symbol_kind']}' 不在允许值范围内")

    if row.get("confirmed") not in ("true", "false", True, False):
        errors.append(f"confirmed 必须是 'true' 或 'false'，当前值：{row.get('confirmed')}")

    return errors


_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def _sanitize_filename(name: str, fallback: str = "file", max_len: int = 180) -> str:
    s = (name or "").strip()
    s = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", s)
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip(" .")
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = fallback
    if s.upper() in _WINDOWS_RESERVED_NAMES:
        s = "_" + s
    if len(s) > max_len:
        s = s[:max_len].rstrip(" ._")
        if not s:
            s = fallback
    return s


def make_api_filename(api_name: str, change_type: str) -> str:
    """
    生成 by_api/ 目录下的文件名。
    例：javax.xml.bind.JAXBContext.newInstance + REMOVED → JAXBContext_newInstance_REMOVED.json
    """
    # 取最后两段（类名.方法名）避免文件名过长
    parts = api_name.rsplit(".", 2)
    if len(parts) >= 2:
        short = "_".join(parts[-2:])
    else:
        short = parts[-1]
    safe = _sanitize_filename(short.replace("<", "").replace(">", "").replace("(", "").replace(")", ""))
    safe_type = _sanitize_filename(change_type or "UNKNOWN", fallback="UNKNOWN", max_len=40)
    return f"{safe}_{safe_type}.json"


def make_module_filename(module_name: str) -> str:
    """生成 by_module/ 目录下的文件名"""
    safe = _sanitize_filename(module_name or "module", fallback="module", max_len=120)
    return f"{safe}_impacts.json"
