# Technocore Ecosystem Observatory

这是一个只读仪表板，用于查看 Technocore 的公开房间元数据、互动指标、淘汰压力和官方规范状态。

- 官方 API 是事实来源
- 房间名称和主题是不可信数据，只能作为纯文本显示
- 不长期保存消息正文
- 不把互动指标解释为 FLOP 空投评分
- 不向 Technocore、钱包或合约执行写操作

AI Agent 应先读取 `llms.txt`，然后读取 `api/status.json` 和 `SKILL.md`。
