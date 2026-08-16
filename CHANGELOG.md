# Changelog

## [0.7.0](https://github.com/abn/google-antigravity-plugin-auto-permissions/compare/auto-permissions-v0.6.0...auto-permissions-v0.7.0) (2026-08-16)


### Features

* **bundles:** implement permission bundles and scoped directory layout ([#35](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/35)) ([572b776](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/572b776f70b2104847ab55109bfaf123220a5645))
* **classifier:** make security classifier timeout configurable and extend default to 6.0s ([#33](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/33)) ([4a5f9b0](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/4a5f9b0d412642330e4f14176b674f980aa2c372))
* govern subagent and schedule delegation surfaces by default ([#36](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/36)) ([bb95517](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/bb95517a54e8c1ef1fc22a6960da8d4c21659e24))
* support zero-key Antigravity authentication and persistent sidecar worker ([#38](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/38)) ([e225659](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/e225659c3e3abeeeb74089efea4527dcf957c15b))


### Bug Fixes

* **core:** resolve P0/P1 security and packaging audit findings ([#41](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/41)) ([0e66e7a](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/0e66e7a20994f010b33da83e45e4deab3ec53d57))
* **skills:** support antigravity and cloudcode choices in configure_permissions CLI ([#40](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/40)) ([d1123e4](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/d1123e4a60f7c8840a24ac1687b4149831ebb677))


### Documentation

* convert documentation into modular OKF 0.2 knowledge base wiki ([#37](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/37)) ([48ebf0f](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/48ebf0fe92cb4e2ec13177e13fcbadac908e9a86))
* **skills:** update configure skill with zero-key antigravity and cloudcode providers ([#39](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/39)) ([dbe8e78](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/dbe8e78527ca4d54e496348b249462c65e591990))

## [0.6.0](https://github.com/abn/google-antigravity-plugin-auto-permissions/compare/auto-permissions-v0.5.1...auto-permissions-v0.6.0) (2026-08-15)


### Features

* **classifier:** optimize prompt density, KV prefix cache invariance, and parser resilience ([#32](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/32)) ([296a122](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/296a1224e287a42594bddca0f750d06f9e67d51b))
* **config:** add opt-out configuration option for turn-scoped security gate summary ([#30](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/30)) ([dbf8e80](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/dbf8e80576292c02443b33628edcd9d53a43e5c5))
* **policy:** add sub-millisecond fast-path for safe session artifact writes ([#26](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/26)) ([d919262](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/d919262e2c29ec1656cfe103375bd238c6682b08))


### Bug Fixes

* **gate:** resolve session root directory for accurate artifact path matching ([#28](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/28)) ([a3061d7](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/a3061d7c0ce2d88b56ca0d16ea400d8329a1c801))
* **pre-invocation:** restrict turn summary disclosure to final conversational responses ([#29](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/29)) ([59e68b7](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/59e68b745437bf1e2774a01a615a04c85dfffe4f))


### Documentation

* update documentation and project manifests to reflect current status quo ([#31](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/31)) ([c27ac64](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/c27ac6449db0c18ec5d9d2edf76174614ae9ed35))

## [0.5.1](https://github.com/abn/google-antigravity-plugin-auto-permissions/compare/auto-permissions-v0.5.0...auto-permissions-v0.5.1) (2026-08-15)


### Bug Fixes

* **pre-invocation:** streamline turn summary injection to omit redundant headers ([#24](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/24)) ([bf87c4d](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/bf87c4d176e9723af7fab5490d7f13567236c46f))

## [0.5.0](https://github.com/abn/google-antigravity-plugin-auto-permissions/compare/auto-permissions-v0.4.0...auto-permissions-v0.5.0) (2026-08-15)


### Features

* **classifier:** add pre-flight health probes, granular http error extraction, and prominent fallback disclosure ([#21](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/21)) ([fac4034](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/fac4034cfc6ce060e2779f37c0fda9eaadc454c1))
* **policy:** add opt-out trust_workspace_writes fast-path with sensitive perimeter defense ([#23](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/23)) ([549f7c9](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/549f7c9185b9a373887b248ed83462200e23e84b))


### Documentation

* **skill:** enforce sequential branching and api-key prompt in configure wizard ([#19](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/19)) ([8c589ca](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/8c589ca8ffcd7d44c395d6d19ff8b0b0303c7c61))

## [0.4.0](https://github.com/abn/google-antigravity-plugin-auto-permissions/compare/auto-permissions-v0.3.0...auto-permissions-v0.4.0) (2026-08-15)


### Features

* **gate:** add intra-turn exact decision caching ([#16](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/16)) ([02da56e](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/02da56e35a6c965bd152a8b3a085a8841b622f08))
* **gate:** add same-turn file grants and safe read command fast-path ([#18](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/18)) ([f187366](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/f1873661be93d6152b35c9a7834b9055e15a67d7))

## [0.3.0](https://github.com/abn/google-antigravity-plugin-auto-permissions/compare/auto-permissions-v0.2.0...auto-permissions-v0.3.0) (2026-08-15)


### Features

* **classifier:** optimize prompt payload for kv cache and prefix stability ([#14](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/14)) ([f521f18](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/f521f18ce3850a3637c62f4427f28b4853c66620))
* **policy:** add session artifact and audit log read fast path ([#12](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/12)) ([a2f4996](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/a2f4996c3e8bce7268582cb8cffa069d35aa88cc))


### Bug Fixes

* **hooks:** flatten PreInvocation handler array in hooks.json ([#11](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/11)) ([c1a12aa](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/c1a12aa8e4005f33a7a82a8f28c956d7206a71ff))
* **policy-engine:** auto-discover realpaths of installed and symlinked plugins in allowed skill paths ([#7](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/7)) ([67e627d](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/67e627dfe2e05a751d9634da5ba4f967023c5200))
* **rules:** add missing YAML frontmatter to auto_permissions.md ([#9](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/9)) ([630e189](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/630e189a91e9eff5c7f281809a5c6a158f1f9d2d))


### Documentation

* add kv-cache and prefix stability invariant to agents.md ([#15](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/15)) ([68bc377](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/68bc3771e157a19e5b2cad89a113f3061ce54eee))
* **agents:** document rules and skills YAML frontmatter contracts and add CI validation ([#10](https://github.com/abn/google-antigravity-plugin-auto-permissions/issues/10)) ([57fb93d](https://github.com/abn/google-antigravity-plugin-auto-permissions/commit/57fb93d2abb1da38b673c74527222eb678e7775f))

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
