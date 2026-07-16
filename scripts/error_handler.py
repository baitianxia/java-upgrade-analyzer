#!/usr/bin/env python3
"""
error_handler.py — 统一异常处理和用户协助

记录脚本执行中的错误，提供可操作的修复指导。

用法：
  # 记录错误（供脚本内部调用）
  python error_handler.py record `
    --report-dir .upgrade-report `
    --step s1_dep_diff `
    --type ENV_MISSING --subtype maven `
    --message "mvn 命令未找到"

  # 查看错误摘要（供门控调用）
  python error_handler.py summary --report-dir .upgrade-report
"""

import argparse, json, os, sys, traceback
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# 用户可操作指导
GUIDANCE = {
    'ENV_MISSING': {
        'maven': {
            'diagnosis': ['mvn --version'],
            'actions':   ['安装 Maven 3.6+：https://maven.apache.org/download.cgi',
                          '确认 JAVA_HOME 和 M2_HOME 已设置',
                          'Windows: 确认 mvn.cmd 在 PATH 中'],
            'workaround': '修复 Maven 环境后重新执行 Step1，使用 base/current 分支走真实构建',
        },
        'java': {
            'diagnosis': ['java -version', 'where java'],
            'actions':   ['安装 JDK（非 JRE），确认 java.exe 在 PATH 中'],
        },
        'jdeprscan': {
            'diagnosis': ['jdeprscan --version'],
            'actions':   ['jdeprscan 是 JDK 9+ 自带工具，需安装完整 JDK 9+'],
            'is_optional': True,
        },
    },
    'ENV_NETWORK': {
        'default': {
            'diagnosis': ['mvn help:effective-settings'],
            'actions':   ['检查 VPN 连接', '确认 ~/.m2/settings.xml 中配置了正确的 mirror'],
            'workaround': '预先手动下载 jar：mvn dependency:resolve -DincludeScope=compile',
        }
    },
    'ENV_AUTH': {
        'maven_repo': {
            'diagnosis': ['cat ~/.m2/settings.xml'],
            'actions':   ['检查 settings.xml 中 <server> 的 username/password',
                          '确认已连接 VPN（内网私服）'],
        }
    },
    'PROJECT_STRUCT': {
        'multi_module_no_root_pom': {
            'user_input_needed': '请在包含 <modules> 声明的 pom.xml 所在目录重新执行命令',
        },
        'nonstandard_source_dir': {
            'user_input_needed': '请用 --source-dir 参数指定实际的 Java 源码目录',
        },
    },
    'DATA_EMPTY': {
        'step1_scope_empty': {
            'diagnosis': ['mvn -pl <module> -am -DskipTests package', 'mvn -pl <module> -am -DskipTests dependency:list -DincludeScope=runtime'],
            'actions':   ['确认目标模块 package 成功（无报错）',
                          '确认当前模块最终产物或 runtime 依赖结果非空'],
        }
    },
    'TOOL_MISSING': {
        'japicmp': {
            'actions': [
                'mvn dependency:get '
                '-Dartifact=com.github.siom79.japicmp:japicmp:0.21.2:jar:jar-with-dependencies',
                '离线环境可提前下载 japicmp-*-jar-with-dependencies.jar，并在 main_state.json 的当前步骤输入中设置 japicmp_jar'
            ],
            'is_optional': False,
            'impact': '无法做精确的 Binary Incompatible 检测',
            'workaround': '不允许降级继续；请安装 JApiCmp 或提供 japicmp_jar 后重跑 Step4',
        }
    },
}


class ErrorRecorder:
    def __init__(self, report_dir, step_name):
        self.report_dir = report_dir
        self.step_name  = step_name
        self.error_dir  = os.path.join(report_dir, 'errors')
        os.makedirs(self.error_dir, exist_ok=True)

    def record(self, error_type, subtype='default', message='',
               exception=None, is_fatal=True):
        ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        guidance = (GUIDANCE.get(error_type, {}).get(subtype)
                    or GUIDANCE.get(error_type, {}).get('default'))
        record = {
            'timestamp':  datetime.now().isoformat(),
            'step':       self.step_name,
            'error_type': error_type,
            'subtype':    subtype,
            'message':    message,
            'is_fatal':   is_fatal,
            'exception':  str(exception) if exception else None,
            'traceback':  traceback.format_exc() if exception else None,
            'guidance':   guidance,
        }
        fpath = os.path.join(self.error_dir, f"{self.step_name}_{ts}.json")
        with open(fpath, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
        self._print(record)
        return fpath

    def _print(self, rec):
        severity = "❌ 致命" if rec['is_fatal'] else "⚠️  警告"
        print(f"\n{severity} [{rec['step']}] {rec['error_type']}/{rec['subtype']}",
              file=sys.stderr)
        print(f"  {rec['message']}", file=sys.stderr)
        g = rec.get('guidance') or {}
        if g.get('diagnosis'):
            print("  诊断：", file=sys.stderr)
            for cmd in g['diagnosis']:
                print(f"    $ {cmd}", file=sys.stderr)
        if g.get('actions'):
            print("  处理：", file=sys.stderr)
            for act in g['actions']:
                print(f"    {act}", file=sys.stderr)
        if g.get('workaround'):
            print(f"  替代方案：{g['workaround']}", file=sys.stderr)
        if g.get('user_input_needed'):
            print(f"  需要您提供：{g['user_input_needed']}", file=sys.stderr)
        if g.get('is_optional'):
            print("  此工具为可选，跳过不影响主要分析", file=sys.stderr)


def load_errors(report_dir, step_filter=None):
    error_dir = os.path.join(report_dir, 'errors')
    if not os.path.isdir(error_dir):
        return []
    errors = []
    for fname in sorted(os.listdir(error_dir)):
        if not fname.endswith('.json'):
            continue
        if step_filter and not fname.startswith(step_filter):
            continue
        try:
            with open(os.path.join(error_dir, fname),
                      encoding='utf-8', errors='replace', newline='') as f:
                errors.append(json.load(f))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            errors.append({
                "step": "error_handler",
                "category": "error_record_unreadable",
                "file": fname,
                "message": f"{type(exc).__name__}: {exc}",
            })
    return errors


def main():
    ap  = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd')

    rec = sub.add_parser('record')
    rec.add_argument('--report-dir', required=True)
    rec.add_argument('--step',       required=True)
    rec.add_argument('--type',       required=True, dest='error_type')
    rec.add_argument('--subtype',    default='default')
    rec.add_argument('--message',    required=True)
    rec.add_argument('--warning',    action='store_true')

    summ = sub.add_parser('summary')
    summ.add_argument('--report-dir', required=True)
    summ.add_argument('--step',       default=None)

    args = ap.parse_args()

    if args.cmd == 'record':
        r = ErrorRecorder(args.report_dir, args.step)
        r.record(args.error_type, args.subtype, args.message,
                 is_fatal=not args.warning)

    elif args.cmd == 'summary':
        errors = load_errors(args.report_dir, args.step)
        fatal    = [e for e in errors if e.get('is_fatal')]
        warnings = [e for e in errors if not e.get('is_fatal')]
        if warnings:
            print(f"\n⚠️  警告 ({len(warnings)} 个)：", file=sys.stderr)
            for e in warnings:
                print(f"  [{e['step']}] {e['message']}", file=sys.stderr)
        if fatal:
            print(f"\n❌ 致命错误 ({len(fatal)} 个)：", file=sys.stderr)
            for e in fatal:
                print(f"  [{e['step']}] {e['error_type']}: {e['message']}", file=sys.stderr)
                g = e.get('guidance') or {}
                if g.get('actions'):
                    print(f"    处理：{g['actions'][0]}", file=sys.stderr)
            sys.exit(1)
        else:
            print("✅ 无致命错误", file=sys.stderr)


if __name__ == '__main__':
    main()
