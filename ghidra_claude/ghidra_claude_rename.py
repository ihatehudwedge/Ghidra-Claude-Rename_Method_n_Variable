# @runtime PyGhidra
# -*- coding: utf-8 -*-
 
import json
import os
import urllib.request
import urllib.error
 
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import HighFunctionDBUtil
 
 
# ---------------------------------------------------------------------------
# 설정값
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(globals().get("__file__", "ghidra_claude_rename.py")))
API_KEY_FILE = os.path.join(SCRIPT_DIR, ".api")
 
API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"          # 비용을 낮추려면 claude-haiku-4-5-20251001 사용
ANTHROPIC_VERSION = "2023-06-01"
MAX_TOKENS = 1024
MAX_FUNCTIONS = 50                    # 1회 실행당 처리할 함수 수 상한 (비용 안전장치)
SKIP_LIBRARY_FUNCTIONS = True
DECOMPILE_TIMEOUT_SECONDS = 30
 
SYSTEM_PROMPT = (
    "You are a reverse engineering assistant. You will be given decompiled "
    "pseudo-C code from Ghidra. Suggest a better, descriptive function name "
    "and better names for its local variables and parameters, based only on "
    "what the code logically does. Respond with ONLY a raw JSON object, no "
    "markdown, no commentary, in exactly this shape:\n"
    '{"function_name": "suggested_name", '
    '"variables": {"old_name1": "new_name1", "old_name2": "new_name2"}}\n'
    "If you cannot confidently improve a name, omit it from the object "
    "rather than guessing randomly. Never invent variables that are not "
    "present in the code."
)
 
 
def load_api_key(path):
    """.api 파일에서 ANTHROPIC_API_KEY=... 라인을 읽어온다."""
    if not os.path.isfile(path):
        raise RuntimeError(
            "API 키 파일을 찾을 수 없습니다: %s\n"
            "ANTHROPIC_API_KEY=sk-ant-... 형식으로 .api 파일을 같은 폴더에 만들어 두세요." % path
        )
 
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                if key.strip() == "ANTHROPIC_API_KEY":
                    value = value.strip()
                    if value and not value.startswith("sk-ant-xxxx"):
                        return value
 
    raise RuntimeError(
        ".api 파일에서 유효한 ANTHROPIC_API_KEY 값을 찾지 못했습니다: %s" % path
    )
 
 
def call_claude(api_key, decompiled_code, function_name):
    """디컴파일된 코드를 Claude에 보내고 이름 제안 JSON을 받아온다."""
 
    user_prompt = (
        "Current function name: %s\n\nDecompiled code:\n```c\n%s\n```"
        % (function_name, decompiled_code)
    )
 
    payload = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": user_prompt}
        ],
    }
 
    body = json.dumps(payload).encode("utf-8")
 
    request = urllib.request.Request(API_URL, data=body)
    request.add_header("content-type", "application/json")
    request.add_header("x-api-key", api_key)
    request.add_header("anthropic-version", ANTHROPIC_VERSION)
 
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read()
 
    data = json.loads(raw)
    text_parts = [block["text"] for block in data.get("content", []) if block.get("type") == "text"]
    combined = "".join(text_parts).strip()
 
    if combined.startswith("```"):
        combined = combined.strip("`")
        if combined.lower().startswith("json"):
            combined = combined[4:]
        combined = combined.strip()
 
    return json.loads(combined)
 
 
def decompile_function(decomp_iface, function, monitor):
    result = decomp_iface.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor)
    if not result or not result.decompileCompleted():
        return None, None
    return result.getHighFunction(), result.getDecompiledFunction().getC()
 
 
def apply_suggestions(program, function, high_function, suggestions):
    """제안받은 이름을 실제 프로그램에 반영한다."""
 
    new_func_name = suggestions.get("function_name")
    var_map = suggestions.get("variables", {})
 
    tx_id = program.startTransaction("Claude auto-rename: %s" % function.getName())
    success = False
    try:
        if new_func_name and new_func_name != function.getName():
            function.setName(new_func_name, SourceType.USER_DEFINED)
 
        if var_map and high_function:
            symbol_map = high_function.getLocalSymbolMap()
            for high_symbol in symbol_map.getSymbols():
                old_name = high_symbol.getName()
                if old_name in var_map:
                    new_name = var_map[old_name]
                    try:
                        HighFunctionDBUtil.updateDBVariable(
                            high_symbol, new_name, None, SourceType.USER_DEFINED
                        )
                    except Exception as e:
                        print("  [경고] 변수 '%s' -> '%s' 리네임 실패: %s" % (old_name, new_name, e))
        success = True
    finally:
        program.endTransaction(tx_id, success)
 
 
def run():
    api_key = load_api_key(API_KEY_FILE)
 
    program = currentProgram  # PyGhidra도 Jython과 동일하게 전역 변수로 제공함 (함수 호출 아님)
    monitor = ConsoleTaskMonitor()
 
    decomp_iface = DecompInterface()
    decomp_iface.setOptions(DecompileOptions())
    decomp_iface.openProgram(program)
 
    function_manager = program.getFunctionManager()
    functions = list(function_manager.getFunctions(True))
 
    processed = 0
    try:
        for function in functions:
            if processed >= MAX_FUNCTIONS:
                print("MAX_FUNCTIONS(%d) 도달, 중단합니다." % MAX_FUNCTIONS)
                break
 
            if SKIP_LIBRARY_FUNCTIONS and (function.isThunk() or function.isExternal()):
                continue
 
            print("처리 중: %s @ %s" % (function.getName(), function.getEntryPoint()))
 
            try:
                high_function, c_code = decompile_function(decomp_iface, function, monitor)
                if not c_code:
                    print("  디컴파일 실패, 건너뜀")
                    continue
 
                suggestions = call_claude(api_key, c_code, function.getName())
                apply_suggestions(program, function, high_function, suggestions)
 
                print("  -> 함수명: %s, 변수 %d개 변경 제안됨" % (
                    suggestions.get("function_name", "(변경없음)"),
                    len(suggestions.get("variables", {}))
                ))
                processed += 1
 
            except urllib.error.HTTPError as e:
                print("  [오류] API 호출 실패 (HTTP %s): %s" % (e.code, e.read()))
            except Exception as e:
                print("  [오류] %s 처리 중 예외: %s" % (function.getName(), e))
    finally:
        decomp_iface.dispose()
 
    print("완료: 총 %d개 함수 처리" % processed)
 
 
run()