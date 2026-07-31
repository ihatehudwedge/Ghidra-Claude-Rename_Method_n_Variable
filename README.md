# Ghidra-Claude Rename (Method & Variable)

A script that decompiles functions in Ghidra, analyzes them via the Claude API, and automatically suggests and applies more readable names for functions and local variables.

It's designed to work **without installing any third-party extension in Ghidra** — using only the PyGhidra runtime bundled with Ghidra and the Python 3 standard library.

## Architecture

```
[Ghidra environment being analyzed]
   ├─ Decompile the function (DecompInterface)
   ├─ Send the decompiled pseudocode to the Claude API (HTTPS, urllib.request)
   ├─ Parse the suggested function/variable names from the response (JSON)
   └─ Apply the names to the Ghidra program (HighFunctionDBUtil, Function.setName)

[External: api.anthropic.com]
   └─ The Claude model analyzes the code and returns a JSON object with name suggestions
```

## Requirements

- Ghidra 11.3 or later (with the bundled PyGhidra)
- Python 3.8+ installed on the system (no extra pip packages required)
- A Claude API key (pay-as-you-go, issued at `platform.claude.com`)

## 1. Get a Claude API key

1. Go to [platform.claude.com](https://platform.claude.com) and sign up / log in with an email address (this account doesn't need to match your Claude.ai account).
2. Register a payment method under **Billing**. If you skip this, requests will be rejected even after you create a key.
3. **Settings** → **API Keys** (`platform.claude.com/settings/keys`) → **Create Key**.

   <img width="1254" height="506" alt="image" src="https://github.com/user-attachments/assets/27cd8674-8191-4d3b-ba73-daca9a48342f" />

5. Name the key (e.g., `ghidra-vm-analysis`) and create it — the key starts with sk-ant- and is shown only once on this screen, so copy it immediately and store it somewhere safe.
6. It's recommended to set a **Spend Limit** on the same screen. The script calls the API automatically across many functions in a row, so this protects you against unexpected charges.
7. Issuing a key dedicated to this workflow limits the blast radius if the key is ever leaked.

## 2. File placement

Keep the two files from this repository together in the same folder. If the paths are split apart, the script's API-key path resolution will break.

```
ghidra-claude/
├── .api                      # fill in with your real key before use
└── ghidra_claude_rename.py
```

`.api` file content:

```
ANTHROPIC_API_KEY=sk-ant-your-real-key
```

- Never commit this file to git. Add `.api` to `.gitignore`, and commit only a `.api.example` containing a dummy value to the repository.

## 3. How to run

1. Launch Ghidra using `support/pyghidraRun.bat` — not the regular `ghidraRun`.
   - PyGhidra is an official feature bundled with the Ghidra distribution, so no separate extension install is required.
2. Open the target binary and wait for auto-analysis to finish in the Code Browser.
3. Go to **Window** → **Script Manager**.
4. Click the script-directory management icon in the top-right corner → click the + button → add the folder containing `.api` and `ghidra_claude_rename.py`.
5. Refresh the list; ghidra_claude_rename.py will appear under the Claude.AI category. Select it and click Run.
6. Watch the progress log in the Console panel at the bottom.

```
Processing: FUN_00401000 @ 00401000
 -> Function name: parse_config_file, Variable 3 / Change proposed
Processing: FUN_00401120 @ 00401120
 ...
Finish: Processed a total of 12 functions
```

- If a variable rename fails, a line such as `[Caution] Variable 'old_name' -> 'new_name' Naming failed: ...` is printed, and only that variable is skipped while the rest of the function's changes still go through.
- If an exception occurs while processing a function, it's reported as `[ERR] <function name> Exception during processing: ...`, that function is skipped, and the script continues with the next one.
- If an API call itself fails (e.g., an HTTP error), it's reported as `[ERR] API call failed (HTTP <code>): ....`

## 4. Contact

If you run into any issues or bugs, please reach out at `kimsihoon@proton.me`.
