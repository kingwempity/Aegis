# Aegis 模拟攻击引擎设计文档 (Simulation-based Attack Engine)

## 1. 设计理念
将传统的“特征匹配扫描”升级为“交互式模拟攻击”。引擎不再仅仅依赖预定义的规则，而是通过 LLM 驱动的“探测-学习-反应”闭环，模拟真实攻击者的决策过程。

## 2. 核心架构 (LLM-Driven)

### 2.1 决策大脑 (Decision Engine)
- **角色**：全时决策中心。
- **功能**：
    - **Payload 变异**：根据目标环境（WAF类型、Web服务器、中间件）动态生成绕过性更强的 Payload。
    - **响应解析**：利用 LLM 的语义理解能力，从复杂的 HTML/JSON 响应中识别出细微的漏洞迹象或 WAF 拦截特征。
    - **下一步决策**：判断是继续当前攻击链、尝试绕过策略、还是切换到其他攻击向量。

### 2.2 模拟攻击执行器 (Attack Simulator)
- **角色**：攻击链调度与状态管理。
- **功能**：
    - **会话持久化**：管理 Cookie、Token、CSRF 等状态。
    - **多步调度**：执行多阶段攻击任务（如：上传文件 -> 寻找路径 -> 触发执行）。
    - **环境感知**：将 Recon 模块获取的指纹实时反馈给决策大脑。

### 2.3 结果复核器 (Verification Guard)
- **角色**：质量控制。
- **功能**：
    - **证据链审查**：在漏洞入库前，将完整的请求/响应序列提交给 LLM 进行复核。
    - **误报过滤**：排除由于环境异常或规则误判导致的假阳性结果。

## 3. 核心流程 (Sequence)

1. **Recon (侦察)**：获取目标技术栈指纹。
2. **Strategy Init (策略初始化)**：LLM 根据指纹推荐初始攻击方案。
3. **Attack Loop (攻击循环)**：
    - `Simulator` 发送探测请求。
    - `Decision Engine (LLM)` 分析响应：
        - 如果发现漏洞迹象 -> 执行 `Exploitation`。
        - 如果被拦截 -> LLM 生成绕过 Payload 并重试。
        - 如果无果 -> 调整方向。
4. **Final Review (终审)**：LLM 对发现的所有漏洞证据进行一致性校验。

## 4. LLM 接口规范 (Integration)

```python
class LLMProvider:
    async def decide_next_step(self, context: AttackContext) -> AttackDecision:
        """全时决策：输入当前上下文，输出下一步动作"""
        pass

    async def verify_vulnerability(self, evidence: Evidence) -> bool:
        """结果复核：判定漏洞真实性"""
        pass
```

## 5. 重构路径
1. 实现 `scanner/engine/llm_provider.py` 处理与 LLM 的通信。
2. 重构 `scanner/engine/simulator.py` 使其支持 LLM 驱动的决策循环。
3. 修改 `worker/celery_app.py` 切换到新的 `AttackSimulator` 入口。
4. 在 `scanner/engine/core.py` 中集成结果复核逻辑。
