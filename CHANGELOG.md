# Changelog

## [0.2.0](https://github.com/abn/google-antigravity-plugin-auto-permissions/compare/auto-permissions-v0.1.0...auto-permissions-v0.2.0) (2026-08-14)


### Features

* add auto-permissions-configure interactive policy management skill ([15372d2](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/15372d20aaf3101c458ffe2767072b5f0eb3aa7f))
* add auto-permissions-test skill for policy and classifier simulation ([185e4d0](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/185e4d073f7ce5706e0449468d5d42229dc6ead5))
* add comprehensive MCP tool interception and static ACL governance ([aa6dc68](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/aa6dc68ccfd67a7f817e5b176baec8cb1fe73878))
* add explicit session_goal support to security classifier payload ([3a092e4](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/3a092e413544b7c5fa171ed661abb4179be32c75))
* add multi-provider support for Google, OpenAI-wire, and Anthropic endpoints ([f3ddd7b](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/f3ddd7be0fcf6c1644a543892939c0c7fbfefb0a))
* add opt-in governance for subagents, scheduling, and image generation ([7220544](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/72205447b98697a0ca66f3b99094f0848e266ef7))
* add structured custom guidelines and issue diagnostics in audit skill ([37c1f56](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/37c1f56deb116eedff4125f4931448be64787f6f))
* **audit:** detect sandbox bypass elevation events and provide mitigation advice ([cbb53f1](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/cbb53f133864961bb5740db4a2db6058ada4e01a))
* enhance test simulation CLI with dynamic mode reporting and timeout configuration ([da41e55](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/da41e5547a0f18ebb288d5331ad9e66a1b38169f))
* implement autonomous security authorization moderator and auto-permissions plugin ([e75dc4e](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/e75dc4e5e09df740afbaad79801ee1316edb7654))
* implement symlink traversal protection and configurable allowed skill paths ([fd571b1](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/fd571b16103f8e5755cabfc7b530fbe8e8293d4a))
* implement turn-scoped delta filtering for pre-invocation security summary ([ea9d0be](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/ea9d0beb42ed3f7c7b780776c0ef262be89687ba))
* package and attach isolated runtime plugin release archives ([4e4595f](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/4e4595f305e11db4ccb12c448c4b2154cae262a8))
* preserve session anchor Turn 0 in transcript parser for long-session goal continuity ([992ad20](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/992ad208bad4e878e678b917866867d8995bc987))
* support model configuration across session, project, and global scopes ([5093c2e](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/5093c2e9bcb6fddae24b0f438234d52b8bbe95eb))


### Bug Fixes

* auto-resolve session_dir from environment in configure_permissions script ([977b988](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/977b9883e1e5149f3e1d85e254682531705655d5))


### Documentation

* add complete configuration levers reference table to README ([edcc11a](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/edcc11a1bd1b31d9e2ed98c287580f8299555619))
* add git and gh command whitelist examples to fix skill and README ([#4](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/4)) ([8a32b81](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/8a32b81b6b80e497009a9e954bba2cd9f177197a))
* add one-shot curl release artifact installation instructions to README ([#5](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/5)) ([d6be018](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/d6be018c517c1735472d1729ecb5b3cb475922b1))
* add PR-first and Release Please squash merge invariant to AGENTS.md ([#3](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/3)) ([4b5eb50](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/4b5eb505502f90878cf5e93376e4d880571fbf54))
* document AUTO_PERMISSIONS_TIMEOUT in README and architecture spec ([8d39cf8](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/8d39cf8ff089ef389db6c2ab77a6eefdd559f598))
* document two-tier security model and container sandbox mitigation ([842e7aa](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/842e7aa709e32ff7e351fa9f21d2cc4b44860b04))
* formalize architecture specification and streamline readme references ([af95d7f](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/af95d7f16591ca89d2bb7bdaca2bffc2d8687316))
* sanitize example paths and sample session identifier ([c1dda00](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/c1dda006b7e51c8ff27b4ca32a77e97ddc831f8e))
* standardize terminology replacing audit2allow/SELinux references with policy remediation ([42468d0](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/42468d0c3aae7d9d9da319af7661eb79c7966229))
* synchronize skill recipes and AGENTS manifest with status quo ([277b68e](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/277b68e5c13292f47eef1da64b055656006228c0))
