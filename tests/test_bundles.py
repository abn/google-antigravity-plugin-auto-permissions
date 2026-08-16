import json
import os

from hooks.bundles import (
    get_builtin_bundle,
    list_builtin_bundles,
    load_bundle_from_file,
)
from hooks.policy_engine import (
    evaluate_static_policies,
    expand_bundle_hierarchy,
    find_bundle_definition,
    list_available_bundles,
    migrate_config_layout,
    resolve_active_bundles,
    save_policy_file,
    update_bundles_in_scope,
)


def test_builtin_bundles_catalog():
    bundles = list_builtin_bundles()
    expected_slugs = {
        "git-inspect",
        "gh-readonly",
        "python-tooling",
        "rust-tooling",
        "node-tooling",
        "container-inspect",
        "dev-docs-read",
        "mcp-nmem",
    }
    assert expected_slugs.issubset(set(bundles.keys()))
    for slug in expected_slugs:
        bundle = get_builtin_bundle(slug)
        assert bundle is not None
        assert bundle.get("name") == slug
        assert isinstance(bundle.get("description"), str)
        assert isinstance(bundle.get("allow"), list)
        assert len(bundle.get("allow")) > 0


def test_get_builtin_bundle_not_found():
    assert get_builtin_bundle("non-existent-bundle-xyz") is None
    assert get_builtin_bundle("") is None


def test_load_bundle_from_file(tmp_path):
    bundle_file = tmp_path / "custom_test.json"
    bundle_data = {
        "name": "custom-test",
        "description": "Custom testing bundle",
        "allow": ["command(custom-test-cli *)"],
        "ask": ["command(custom-test-cli deploy)"],
        "deny": ["command(custom-test-cli wipe)"],
        "custom_guidelines": ["Always confirm before deploy."],
    }
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    loaded = load_bundle_from_file(str(bundle_file))
    assert loaded is not None
    assert loaded["name"] == "custom-test"
    assert loaded["allow"] == ["command(custom-test-cli *)"]
    assert loaded["custom_guidelines"] == ["Always confirm before deploy."]


def test_find_bundle_definition_sources(tmp_path):
    ws_dir = str(tmp_path / "ws")
    os.makedirs(ws_dir, exist_ok=True)

    # 1. Inline
    inline_def = {"name": "inline-b", "allow": ["command(inline)"]}
    found_inline = find_bundle_definition(
        "inline-b", workspace_paths=[ws_dir], custom_bundles_map={"inline-b": inline_def}
    )
    assert found_inline is not None
    assert found_inline["source"] == "inline"

    # 2. Project Tracked
    p_bundles_dir = os.path.join(ws_dir, ".agents", "auto-permissions", "bundles")
    os.makedirs(p_bundles_dir, exist_ok=True)
    p_file = os.path.join(p_bundles_dir, "my-proj-bundle.json")
    with open(p_file, "w", encoding="utf-8") as f:
        json.dump({"name": "my-proj-bundle", "allow": ["command(proj)"]}, f)

    found_proj = find_bundle_definition("my-proj-bundle", workspace_paths=[ws_dir])
    assert found_proj is not None
    assert found_proj["source"] == "project"

    # 3. Project Local
    pl_bundles_dir = os.path.join(ws_dir, ".agents", "auto-permissions", "bundles.local")
    os.makedirs(pl_bundles_dir, exist_ok=True)
    pl_file = os.path.join(pl_bundles_dir, "my-local-bundle.json")
    with open(pl_file, "w", encoding="utf-8") as f:
        json.dump({"name": "my-local-bundle", "allow": ["command(local)"]}, f)

    found_local = find_bundle_definition("my-local-bundle", workspace_paths=[ws_dir])
    assert found_local is not None
    assert found_local["source"] == "project_local"

    # 4. Built-in
    found_builtin = find_bundle_definition("git-inspect", workspace_paths=[ws_dir])
    assert found_builtin is not None
    assert found_builtin["source"] == "builtin"


def test_expand_bundle_hierarchy_inheritance_and_cycles():
    custom_bundles = {
        "bundle-a": {
            "name": "bundle-a",
            "extends": ["bundle-b"],
            "allow": ["command(a)"],
        },
        "bundle-b": {
            "name": "bundle-b",
            "extends": ["bundle-c", "bundle-a"],  # Cycle to bundle-a
            "allow": ["command(b)"],
            "deny": ["command(b-deny)"],
        },
        "bundle-c": {
            "name": "bundle-c",
            "allow": ["command(c)"],
            "custom_guidelines": ["Rule from C"],
        },
    }

    expanded = expand_bundle_hierarchy(
        bundle_names=["bundle-a"],
        custom_bundles_map=custom_bundles,
    )

    assert "bundle-a" in expanded["active_bundles"]
    assert "bundle-b" in expanded["active_bundles"]
    assert "bundle-c" in expanded["active_bundles"]
    assert set(expanded["allow"]) == {"command(a)", "command(b)", "command(c)"}
    assert expanded["deny"] == ["command(b-deny)"]
    assert expanded["custom_guidelines"] == ["Rule from C"]
    assert expanded["provenance"]["command(a)"] == "bundle-a"
    assert expanded["provenance"]["command(b)"] == "bundle-b"
    assert expanded["provenance"]["command(c)"] == "bundle-c"


def test_expand_bundle_hierarchy_with_disabled():
    custom_bundles = {
        "bundle-parent": {
            "name": "bundle-parent",
            "extends": ["bundle-child"],
            "allow": ["command(parent)"],
        },
        "bundle-child": {
            "name": "bundle-child",
            "allow": ["command(child)"],
        },
    }

    expanded = expand_bundle_hierarchy(
        bundle_names=["bundle-parent"],
        disabled_bundles={"bundle-child"},
        custom_bundles_map=custom_bundles,
    )

    assert "bundle-parent" in expanded["active_bundles"]
    assert "bundle-child" not in expanded["active_bundles"]
    assert expanded["allow"] == ["command(parent)"]


def test_resolve_active_bundles_across_scopes(tmp_path):
    ws_dir = str(tmp_path / "workspace")
    sess_dir = str(tmp_path / "session")
    os.makedirs(ws_dir, exist_ok=True)
    os.makedirs(sess_dir, exist_ok=True)

    # Project policy enabling git-inspect and python-tooling
    proj_cfg = os.path.join(ws_dir, ".agents", "auto-permissions", "config.json")
    save_policy_file(proj_cfg, {"bundles": ["git-inspect", "python-tooling"]})

    active = resolve_active_bundles(session_dir=sess_dir, workspace_paths=[ws_dir])
    assert "git-inspect" in active["active_bundles"]
    assert "python-tooling" in active["active_bundles"]
    assert "command(git status*)" in active["allow"]
    assert "command(pytest*)" in active["allow"]
    assert "command(poetry run *)" in active["allow"]
    assert "command(poetry check*)" in active["allow"]
    assert "command(poetry lock*)" in active["allow"]

    # Session override masks/disables python-tooling
    sess_file = os.path.join(sess_dir, "auto-permissions", "session_overrides.json")
    save_policy_file(sess_file, {"bundles": {"disabled": ["python-tooling"]}})

    active_sess = resolve_active_bundles(session_dir=sess_dir, workspace_paths=[ws_dir])
    assert "git-inspect" in active_sess["active_bundles"]
    assert "python-tooling" not in active_sess["active_bundles"]
    assert "command(git status*)" in active_sess["allow"]
    assert "command(pytest*)" not in active_sess["allow"]
    assert "command(poetry lock*)" not in active_sess["allow"]


def test_evaluate_static_policies_with_bundles(tmp_path):
    ws_dir = str(tmp_path / "workspace")
    os.makedirs(ws_dir, exist_ok=True)

    # Configure project with gh-readonly bundle
    proj_cfg = os.path.join(ws_dir, ".agents", "auto-permissions", "config.json")
    save_policy_file(proj_cfg, {"bundles": ["gh-readonly"]})

    # Allowed by bundle
    res = evaluate_static_policies(
        tool_name="run_command",
        tool_args={"CommandLine": "gh pr view 42"},
        workspace_paths=[ws_dir],
    )
    assert res is not None
    decision, reason, scope = res
    assert decision == "allow"
    assert "bundle:gh-readonly" in scope
    assert "gh-readonly" in reason

    # Explicit project deny overrides bundled allow
    save_policy_file(
        proj_cfg,
        {
            "bundles": ["gh-readonly"],
            "deny": ["command(gh pr view 42)"],
        },
    )
    res_deny = evaluate_static_policies(
        tool_name="run_command",
        tool_args={"CommandLine": "gh pr view 42"},
        workspace_paths=[ws_dir],
    )
    assert res_deny is not None
    d_dec, d_reason, d_scope = res_deny
    assert d_dec == "deny"
    assert d_scope == "project"


def test_update_bundles_in_scope(tmp_path):
    ws_dir = str(tmp_path / "workspace")
    os.makedirs(ws_dir, exist_ok=True)

    target_file = update_bundles_in_scope(
        enabled_bundles=["git-inspect", "rust-tooling"],
        scope="project",
        workspace_dir=ws_dir,
    )
    assert os.path.isfile(target_file)
    with open(target_file, encoding="utf-8") as f:
        data = json.load(f)
    assert data["bundles"] == ["git-inspect", "rust-tooling"]

    # Now disable rust-tooling
    update_bundles_in_scope(
        disabled_bundles=["rust-tooling"],
        scope="project",
        workspace_dir=ws_dir,
    )
    with open(target_file, encoding="utf-8") as f:
        data2 = json.load(f)
    assert isinstance(data2["bundles"], dict)
    assert data2["bundles"]["enabled"] == ["git-inspect"]
    assert data2["bundles"]["disabled"] == ["rust-tooling"]


def test_migrate_config_layout(tmp_path):
    ws_dir = str(tmp_path / "workspace")
    agents_dir = os.path.join(ws_dir, ".agents")
    os.makedirs(agents_dir, exist_ok=True)

    old_proj = os.path.join(agents_dir, "auto-permissions.json")
    old_local = os.path.join(agents_dir, "auto-permissions.local.json")

    with open(old_proj, "w", encoding="utf-8") as f:
        json.dump({"allow": ["command(legacy-proj)"]}, f)
    with open(old_local, "w", encoding="utf-8") as f:
        json.dump({"allow": ["command(legacy-local)"]}, f)

    res = migrate_config_layout(workspace_dir=ws_dir, migrate_global=False)

    assert "project" in res
    assert "project_local" in res
    assert not os.path.isfile(old_proj)
    assert not os.path.isfile(old_local)

    new_proj = os.path.join(agents_dir, "auto-permissions", "config.json")
    new_local = os.path.join(agents_dir, "auto-permissions", "config.local.json")
    assert os.path.isfile(new_proj)
    assert os.path.isfile(new_local)

    with open(new_proj, encoding="utf-8") as f:
        p_data = json.load(f)
    assert p_data["allow"] == ["command(legacy-proj)"]


def test_list_available_bundles(tmp_path):
    ws_dir = str(tmp_path / "workspace")
    os.makedirs(ws_dir, exist_ok=True)

    catalog = list_available_bundles(workspace_paths=[ws_dir])
    assert "git-inspect" in catalog
    assert "gh-readonly" in catalog
    assert "python-tooling" in catalog
    assert catalog["git-inspect"]["source"] == "builtin"
