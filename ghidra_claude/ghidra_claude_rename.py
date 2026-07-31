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
SYSTEM_PROMPT_FILE = os.path.join(SCRIPT_DIR, "ghidra_prompt_advanced.md")

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"  # Model List (https://platform.claude.com/docs/en/about-claude/model-deprecations)
ANTHROPIC_VERSION = "2023-06-01"

MAX_TOKENS = 1024
MAX_FUNCTIONS = 50  # Cost safety margin: the upper limit on the number of functions processed per execution
SKIP_LIBRARY_FUNCTIONS = True
DECOMPILE_TIMEOUT_SECONDS = 30

# Prompt caching: this system prompt is long enough (well above the ~1,024
# token minimum for Sonnet 4.6) to actually benefit from caching. Using a
# 1-hour TTL instead of the default 5-minute TTL, since decompiling +
# analyzing many functions in a row can easily take longer than 5 minutes,
# which would otherwise let the cache expire between calls.
CACHE_TTL = "1h"  # "5m" (default) or "1h"


# Read Claude API Key in .api file
def load_api_key(path):
    if not os.path.isfile(path):
        raise RuntimeError(
            "Cannot found Claude API key: %s\n"
            "Create a .api file in the same folder as a template like (ANTHROPIC_API_KEY=sk-ant-...)." % path
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
        "Cannot found a Valid ANTROPIC_API_KEY in .api file: %s" % path
    )


# Load the (large) system prompt from an external .md file so it can be
# edited/reviewed independently of the script itself.
def load_system_prompt(path):
    if not os.path.isfile(path):
        raise RuntimeError(
            "Cannot found system prompt file: %s\n"
            "Place ghidra_prompt_advanced.md in the same folder as this script." % path
        )
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if not text.strip():
        raise RuntimeError("System prompt file is empty: %s" % path)
    return text


SYSTEM_PROMPT = load_system_prompt(SYSTEM_PROMPT_FILE)

# Cache control state: tracked across calls so we don't repeatedly retry
# a request shape the API has already rejected in this run.
#   None  = not yet tested
#   True  = cache_control accepted by the API
#   False = cache_control caused a request-level failure; fall back permanently
#           (keeps the pipeline running even if a future API/account/region
#           change stops supporting cache_control or the "ttl" field)
_CACHE_CONTROL_STATE = {"supported": None}


def _build_payload(user_prompt, use_cache_control):
    if use_cache_control:
        system_field = [
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral", "ttl": CACHE_TTL},
            }
        ]
    else:
        system_field = SYSTEM_PROMPT
    return {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": system_field,
        "messages": [{"role": "user", "content": user_prompt}],
    }


def _send_request(api_key, payload):
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(API_URL, data=body)
    request.add_header("content-type", "application/json")
    request.add_header("x-api-key", api_key)
    request.add_header("anthropic-version", ANTHROPIC_VERSION)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


# Send the decompiled code to Claude and receive the name suggestion JSON.
def call_claude(api_key, decompiled_code, function_name):
    user_prompt = (
        "Current function name: %s\n\nDecompiled code:\n```c\n%s\n```"
        % (function_name, decompiled_code)
    )

    use_cache = _CACHE_CONTROL_STATE["supported"] is not False
    try:
        data = _send_request(api_key, _build_payload(user_prompt, use_cache))
    except urllib.error.HTTPError as e:
        if use_cache:
            # cache_control / ttl may be rejected by a future or older API
            # version, region, or account tier. Fall back to a plain system
            # string and keep the pipeline running instead of aborting.
            print(" [Caution] cache_control request rejected (HTTP %s). "
                  "Falling back to non-cached system prompt for the rest of this run." % e.code)
            _CACHE_CONTROL_STATE["supported"] = False
            data = _send_request(api_key, _build_payload(user_prompt, use_cache_control=False))
        else:
            raise  # already fell back once; this is a real API error

    # Surface cache effectiveness in the log without ever failing the run
    # if the usage fields are renamed/removed by a future API version.
    try:
        usage = data.get("usage", {})
        cache_read = usage.get("cache_read_input_tokens", 0)
        cache_write = usage.get("cache_creation_input_tokens", 0)
        if cache_read or cache_write:
            print(" [Cache] read=%d write=%d tokens (ttl=%s)" % (cache_read, cache_write, CACHE_TTL))
    except Exception:
        pass  # never let usage-logging break the actual rename pipeline

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


# Reflect the proposed name in the actual program.
def apply_suggestions(program, function, high_function, suggestions):
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
                        print("  [Caution] Variable '%s' -> '%s' Naming failed: %s" % (old_name, new_name, e))
        success = True
    finally:
        program.endTransaction(tx_id, success)


def run():
    api_key = load_api_key(API_KEY_FILE)
    program = currentProgram  # Global Variable (not callback function)
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
                print("MAX_FUNCTIONS(%d) PEAKED, STOP IT." % MAX_FUNCTIONS)
                break

            if SKIP_LIBRARY_FUNCTIONS and (function.isThunk() or function.isExternal()):
                continue

            print("Processing: %s @ %s" % (function.getName(), function.getEntryPoint()))
            try:
                high_function, c_code = decompile_function(decomp_iface, function, monitor)
                if not c_code:
                    print("  Decompilation failed, skipped")
                    continue

                suggestions = call_claude(api_key, c_code, function.getName())
                apply_suggestions(program, function, high_function, suggestions)

                print("  -> Function name: %s, Variable %d / Change proposed" % (
                    suggestions.get("function_name", "(Not Changed)"),
                    len(suggestions.get("variables", {}))
                ))
                processed += 1
            except urllib.error.HTTPError as e:
                print("  [ERR] API call failed (HTTP %s): %s" % (e.code, e.read()))
            except Exception as e:
                print("  [ERR] %s Exception during processing: %s" % (function.getName(), e))
    finally:
        decomp_iface.dispose()

    print("Finish: Processed a total of %d functions" % processed)


run()
