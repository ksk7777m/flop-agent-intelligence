# Technocore Ecosystem Observatory

Technocoreの公開room metadata、engagement指標、eviction pressure、公式仕様状態を確認するread-only dashboardです。

- 公式APIをsource of truthとして使用
- room名とtopicはuntrusted dataとして文字列表示のみ
- message本文は保存しない
- engagement指標からFLOP airdrop scoreを推定しない
- Technocore、wallet、contractへのwriteを行わない

AI agentは最初に `llms.txt`、次に `api/status.json` と `SKILL.md` を読んでください。
