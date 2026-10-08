#!/usr/bin/env python3
"""Static checks for the embedded web UI (dashboard + captive portal).

Catches the bug class that shipped in 692f2a7: applyLang() dereferenced
`pausedur.options[0]` while the <select> was emitted with no <option> children,
so the initialiser threw on its first line and every label rendered blank. The
JavaScript was syntactically valid, so a syntax check cannot see it -- only
"does this node actually exist in the markup" can.

Run from the repo root:  python3 tools/check_ui.py
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
fails = []


def check(cond, msg):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


SKIP = {'window', 'document', 'console', 'Math', 'String', 'Object', 'Number',
        'localStorage', 'navigator', 'JSON', 'Array', 'Promise', 'FormData', 'this'}

# ---------------- dashboard (src/page.h) ----------------
page = (ROOT / 'src/page.h').read_text(encoding='utf-8')
html = re.search(r'R"HTML\((.*)\)HTML";', page, re.S).group(1)
js = re.findall(r'<script>(.*?)</script>', html, re.S)[0]
markup = html[:html.index('<script>')]
ids = set(re.findall(r'id=([A-Za-z_][\w-]*)', markup))
print(f"仪表盘: markup 中 {len(ids)} 个 id")

# 1. implicit-global DOM references must resolve to a real id
refs = set(re.findall(
    r"(?:^|[;\s(])([a-z][A-Za-z0-9_]*)\s*\.\s*"
    r"(?:textContent|innerHTML|style|placeholder|value|dataset)", js))
missing = sorted(r for r in refs - ids - SKIP)
check(not missing, f"脚本引用的 DOM id 都存在 (缺失: {missing or '无'})")

# 2. indexed option access must stay in range
sel = re.search(r'<select id=(\w+)[^>]*>(.*?)</select>', markup, re.S)
if sel:
    sid, body = sel.group(1), sel.group(2)
    n_opts = len(re.findall(r'<option', body))
    used = sorted({int(m) for m in re.findall(rf'{sid}\.options\[(\d+)\]', js)})
    check(n_opts > 0, f"<select id={sid}> 有 {n_opts} 个 <option> (旧 bug 这里为 0)")
    check(all(i < n_opts for i in used),
          f"options 索引 {used} 均在范围 0..{n_opts - 1} 内")
else:
    check(False, "未找到 <select id=pausedur>")

# 3. translation dictionaries must agree with each other and with t() usage
def keys(block):
    return set(re.findall(r"(?:^|[,{\s])([A-Za-z_]\w*):'", block))


zh = keys(js[js.index('zh:{'):js.index('en:{')])
en = keys(js[js.index('en:{'):js.index('}};')])
used_keys = set(re.findall(r"t\('(\w+)'\)", js))
check(zh == en, f"仪表盘 zh/en 键一致 ({len(zh)} / {len(en)})")
check(not (used_keys - zh), f"t() 的键都已定义 (缺失: {sorted(used_keys - zh) or '无'})")
check(not (zh - used_keys), f"无多余未用键 (多余: {sorted(zh - used_keys) or '无'})")

# ---------------- captive portal (src/main.cpp) ----------------
main = (ROOT / 'src/main.cpp').read_text(encoding='utf-8')
blk = re.search(r'static void handlePortalRoot\(\) \{(.*?)\n\}', main, re.S).group(1)
# Join the C++ string literals the way the compiler does, so ids/JS are checked
# on the markup the device actually serves.
lits = [m.group(1).replace('\\"', '"').replace('\\\\', '\\')
        for m in re.finditer(r'"((?:\\.|[^"\\])*)"', blk.split('String html =')[1])]
portal = ''.join(lits)
pids = set(re.findall(r'id=([A-Za-z_][\w-]*)', portal))
pjs = re.findall(r'<script>(.*?)</script>', portal, re.S)[0]
prefs = set(re.findall(
    r"(?:^|[;\s(])([a-z][A-Za-z0-9_]*)\s*\.\s*(?:textContent|placeholder|innerHTML)", pjs))
p_missing = sorted(p for p in prefs - pids - SKIP)
print(f"配网页: markup 中 {len(pids)} 个 id")
check(not p_missing, f"配网页脚本引用的 id 都存在 (缺失: {p_missing or '无'})")
for lang in ('zh', 'en'):
    check(f'{lang}:{{' in pjs, f"配网页含 {lang} 词条")

print()
if fails:
    print(f"❌ {len(fails)} 项失败")
    sys.exit(1)
print("✅ 全部通过")
