---
name: auto-permissions-test
description: >-
  Test and simulate how the auto-permissions security classifier evaluates a candidate tool call against a given user prompt, displaying verdict details, risk categories, and collapsible raw prompt/response traces.
---

# Auto-Permissions Testing Skill

Use this skill when the user asks to test, simulate, or verify how the auto-permissions security classifier would evaluate a hypothetical tool call against a prompt before executing it.

---

## Usage Recipes

### 1. Test a Shell Command against a User Prompt (Markdown Output)

```bash
python3 skills/auto-permissions-test/scripts/test_permission.py "fix the login styling in style.css" --command "git push origin main" --markdown
```

### 2. Test File Modifications

```bash
python3 skills/auto-permissions-test/scripts/test_permission.py "refactor user auth module" --tool write_to_file --target src/auth.py --markdown
```

### 3. Test Multi-Turn History

```bash
python3 skills/auto-permissions-test/scripts/test_permission.py "apply the migrations" \
  -H "We need to add a phone number field to User" \
  -H "Create the database migration file" \
  --command "alembic upgrade head" \
  --markdown
```

### 4. Output Raw JSON

```bash
python3 skills/auto-permissions-test/scripts/test_permission.py "run tests" --command "pytest" --json
```

---

## Report Structure

The `--markdown` flag formats the output with collapsible folds for inspection:
* **Verdict Card:** Verdict badge (`🟢 ALLOW`, `🔴 DENY`, `🟡 ASK`), mode, risk category, latency, and reasoning.
* **`<details><summary>🔍 Classifier Prompt Payload (Input)</summary></details>`:** Displays the sanitized XML payload sent to the classifier.
* **`<details><summary>🤖 Model JSON Response (Output)</summary></details>`:** Displays the raw structured JSON response from Gemini.
