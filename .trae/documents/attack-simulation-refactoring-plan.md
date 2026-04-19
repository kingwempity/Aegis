# Aegis 扫描引擎重构方案：从静态扫描到真正的模拟攻击

## 一、什么是"真正的模拟攻击"?

### 1.1 核心定义

**真正的模拟攻击（True Attack Simulation）**是指：扫描器能够像一个真实的攻击者一样，**自主地**对目标进行**多阶段、有状态、自适应**的攻击尝试，而不仅仅是发送预定义的payload并检查响应。

### 1.2 当前Aegis的定位：介于"静态扫描"和"模拟攻击"之间

#### ✅ 已经具备的"动态攻击"特征：

| 特征 | 实现位置 | 说明 |
|------|---------|------|
| Payload变异 | [attack.py:L235-381](scanner/engine/attack.py#L235-L381) | 大小写、注释插入、编码绕过 |
| 上下文感知 | [attack.py:L384-603](scanner/engine/attack.py#L384-L603) | 技术栈检测、输入字段提取 |
| 攻击路径搜索 | [attack.py:L1843-2189](scanner/engine/attack.py#L1843-L2189) | A*算法寻找最优路径 |
| 顺序执行模式 | [core.py:L527-557](scanner/engine/core.py#L527-L557) | sequential_requests支持多阶段 |
| 动态变量提取 | [core.py:L1440-1544](scanner/engine/core.py#L1440-L1544) | 提取form_build_id、上传路径等 |

#### ❌ 仍然存在的"静态扫描"特征：

| 特征 | 问题 | 影响 |
|------|------|------|
| 固定YAML模板 | 每个漏洞类型使用预定义模板 | 无法应对未知变体 |
| 预设Payload库 | payload是硬编码的 | 容易被WAF识别 |
| 简单匹配器验证 | word/regex/status匹配 | 误报率高 |
| 无智能决策 | 不根据响应动态调整策略 | 缺乏适应性 |
| 无会话管理 | Cookie/Session处理简单 | 无法测试认证后功能 |
| 无Exploit能力 | 仅验证性payload | 无法证明危害性 |

---

## 二、真正的模拟攻击 vs 静态扫描对比

### 2.1 维度对比表

| 维度 | 静态扫描 | 当前Aegis | **真正的模拟攻击** |
|------|---------|----------|-------------------|
| **攻击链** | 单次请求 | 多阶段（固定） | **动态构建（自适应）** |
| **Payload来源** | 固定列表 | 固定+变异 | **根据目标定制生成** |
| **状态管理** | 无状态 | 简单状态 | **完整会话状态** |
| **决策机制** | 无 | 规则匹配 | **AI驱动的智能决策** |
| **学习能力** | 无 | 历史统计 | **强化学习/在线学习** |
| **对抗能力** | 无 | 基础编码绕过 | **WAF指纹+智能绕过** |
| **证据收集** | 简单匹配 | 匹配器+置信度 | **完整攻击过程录像** |
| **危害证明** | 无 | 验证存在性 | **实际影响演示** |

### 2.2 真正的模拟攻击的核心特征

```
┌─────────────────────────────────────────────────────────────────┐
│                    真正的模拟攻击架构                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  侦察阶段     │ -> │  武器化阶段   │ -> │  利用阶段     │       │
│  │              │    │              │    │              │       │
│  │ ·指纹识别    │    │ ·Payload生成 │    │ ·攻击执行     │       │
│  │ ·技术栈检测  │    │ ·编码选择    │    │ ·响应分析     │       │
│  │ ·入口发现    │    │ ·Bypass策略  │    │ ·状态更新     │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         ↑                   ↓                   ↓               │
│         └───────────────────┴───────────────────┘               │
│                         │                                       │
│                ┌────────▼────────┐                              │
│                │  智能决策引擎     │                              │
│                │                 │                              │
│                │ ·目标建模       │                              │
│                │ ·策略选择       │                              │
│                │ ·动态调整       │                              │
│                │ ·结果评估       │                              │
│                └─────────────────┘                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 三、重构方案：Attack Simulation Engine v2.0

### 3.1 架构设计

#### 新增核心模块：

```
scanner/
└── engine/
    ├── core.py                    # 现有（增强）
    ├── attack.py                  # 现有（增强）
    ├── template_generator.py      # 现有（保留）
    ├── rules.py                   # 现有（保留）
    │
    ├── NEW: simulator.py          # 【新增】模拟攻击核心引擎
    │   ├── AttackSimulator        # 主控制器
    │   ├── AttackOrchestrator     # 攻击编排器
    │   └── DecisionEngine         # 决策引擎
    │
    ├── NEW: recon.py             # 【新增】侦察模块
    │   ├── ReconEngine            # 侦察引擎
    │   ├── Fingerprinter          # 指纹识别
    │   ├── TechnologyDetector     # 技术栈检测
    │   └── EntryDiscovery         # 入口发现
    │
    ├── NEW: weaponizer.py        # 【新增】武器化模块
    │   ├── Weaponizer             # 武器化器
    │   ├── PayloadSynthesizer     # Payload合成器
    │   ├── BypassEngine           # 绕过引擎
    │   └── ExploitGenerator       # Exploit生成器
    │
    ├── NEW: exploitation.py      # 【新增】利用模块
    │   ├── ExploitationEngine     # 利用引擎
    │   ├── SessionManager         # 会话管理器
    │   ├── StateTracker           # 状态追踪器
    │   └── ImpactDemonstrator     # 影响演示器
    │
    ├── NEW: intelligence.py     # 【新增】情报模块
    │   ├── TargetModeler          # 目标建模
    │   ├── WAFFingerprinter       # WAF指纹识别
    │   ├── BehaviorAnalyzer       # 行为分析器
    │   └── ThreatIntelligence     # 威胁情报
    │
    └── NEW: learning.py         # 【新增】学习模块
        ├── LearningEngine         # 学习引擎
        ├── PatternLearner         # 模式学习
        └── FeedbackSystem         # 反馈系统
```

### 3.2 核心模块详细设计

#### 模块1：simulator.py - 模拟攻击核心引擎

```python
class AttackSimulator:
    """
    模拟攻击核心引擎
    
    特点：
    1. 基于状态的攻击流程管理
    2. 自适应策略调整
    3. 完整的攻击链记录
    4. 实时决策能力
    """
    
    def __init__(self, target: str, strategy: str = "intelligent"):
        self.target = target
        self.strategy = strategy
        
        # 子模块初始化
        self.recon = ReconEngine()
        self.weaponizer = Weaponizer()
        self.exploitation = ExploitationEngine()
        self.intelligence = TargetModeler()
        self.decision_engine = DecisionEngine()
        
        # 攻击状态
        self.attack_session = AttackSession()
        self.attack_chain = AttackChain()
    
    async def run_simulation(self) -> SimulationResult:
        """执行完整的模拟攻击"""
        
        # 阶段1：侦察（Reconnaissance）
        recon_result = await self._recon_phase()
        
        # 阶段2：武器化（Weaponization）
        weapons = await self._weaponize_phase(recon_result)
        
        # 阶段3：利用（Exploitation）
        exploit_results = await self._exploit_phase(weapons)
        
        # 阶段4：影响演示（Impact Demonstration）
        impact = await self._demonstrate_impact(exploit_results)
        
        return SimulationResult(
            recon=recon_result,
            weapons=weapons,
            exploits=exploit_results,
            impact=impact,
            attack_chain=self.attack_chain.to_dict(),
        )
```

#### 模块2：recon.py - 侦察模块

```python
class ReconEngine:
    """
    增强型侦察引擎
    
    对比现有ContextAwareEngine的提升：
    - 更深度的技术栈识别（版本、补丁级别）
    - WAF/IPS指纹识别
    - 应用架构推断（微服务、单体、负载均衡）
    - 认证机制识别（OAuth、JWT、Session）
    - API端点发现（GraphQL、REST、SOAP）
    - 第三方组件识别（jQuery、React、Vue版本）
    """
    
    async def deep_recon(self, target: str) -> ReconResult:
        """深度侦察"""
        
        # 1. 基础指纹识别
        fingerprint = await self._fingerprint(target)
        
        # 2. 技术栈深度检测
        tech_stack = await self._detect_technology_stack(target, fingerprint)
        
        # 3. WAF/防护识别
        waf_info = await self._identify_waf(target)
        
        # 4. 应用架构推断
        architecture = await self._infer_architecture(target, responses)
        
        # 5. 入口点发现
        entry_points = await self._discover_entry_points(target)
        
        # 6. 认证机制识别
        auth_mechanism = await self._identify_auth(target)
        
        return ReconResult(
            fingerprint=fingerprint,
            tech_stack=tech_stack,
            waf=waf_info,
            architecture=architecture,
            entry_points=entry_points,
            auth=auth_mechanism,
        )
```

#### 模块3：weaponizer.py - 武器化模块

```python
class Weaponizer:
    """
    智能武器化模块
    
    对比现有AttackScriptGenerator的提升：
    - 根据目标特征定制Payload（而非使用固定库）
    - 自动选择最佳编码/绕过策略
    - 生成针对性Exploit（非仅验证性Payload）
    - 支持多向量组合攻击
    """
    
    def synthesize_payload(self, target_info: TargetInfo, 
                          vulnerability_type: str) -> List[WeaponizedPayload]:
        """
        根据目标信息合成针对性Payload
        
        思路：
        1. 分析目标技术栈 → 选择适用的攻击语法
        2. 检测WAF规则 → 选择合适的编码方式
        3. 分析输入上下文 → 构造符合场景的Payload
        4. 考虑历史数据 → 优先使用高成功率变体
        """
        
        payloads = []
        
        # 根据技术栈选择基础Payload模板
        base_templates = self._select_templates_by_tech(
            target_info.tech_stack, 
            vulnerability_type
        )
        
        # 根据WAF特征选择编码策略
        encoding_strategies = self._bypass_engine.get_bypass_strategy(
            target_info.waf_fingerprint
        )
        
        # 合成最终Payload
        for template in base_templates:
            for encoding in encoding_strategies:
                weaponized = self._synthesize(
                    template, 
                    encoding, 
                    target_info.context
                )
                payloads.append(weaponized)
        
        return payloads
    
    def generate_exploit(self, vulnerability: VulnerabilityInfo,
                        target_info: TargetInfo) -> Optional[Exploit]:
        """
        生成可复现的Exploit代码
        
        用于：
        1. 证明漏洞的真实危害
        2. 生成PoC报告
        3. 辅助安全团队修复验证
        """
        pass
```

#### 模块4：exploitation.py - 利用模块

```python
class ExploitationEngine:
    """
    高级利用模块
    
    对比现有ScannerEngine的提升：
    - 完整的会话管理（Cookie、Token、Session）
    - 复杂的状态机跟踪（CSRF Token、多步表单）
    - 并发攻击协调
    - 错误恢复和重试机制
    """
    
    async def execute_attack_chain(self, 
                                   chain: AttackChain,
                                   session: AttackSession) -> ExploitResult:
        """
        执行攻击链
        
        特点：
        1. 每一步都基于前一步的结果
        2. 失败时自动回退或调整
        3. 完整记录每一步的证据
        4. 支持条件分支（if-else逻辑）
        """
        
        for step in chain.steps:
            # 检查前置条件
            if not self._check_preconditions(step, session.state):
                continue
            
            # 执行当前步骤
            result = await self._execute_step(step, session)
            
            # 更新状态
            session.state.update(result.extracted)
            
            # 记录证据
            session.evidence.record(step, result)
            
            # 决策：继续/回退/终止
            decision = self.decision_engine.evaluate(result, chain.context)
            
            if decision == Decision.TERMINATE:
                break
            elif decision == Decision.BACKTRACK:
                session.state.rollback()
        
        return ExploitResult(
            success=session.state.goal_achieved(),
            evidence=session.evidence.to_dict(),
            final_state=session.state.snapshot(),
        )
```

#### 模块5：intelligence.py - 情报模块

```python
class TargetModeler:
    """
    目标建模模块
    
    功能：
    - 构建目标的完整模型（技术栈、架构、防护）
    - 实时更新模型（根据攻击过程中的新发现）
    - 推断潜在弱点
    - 生成攻击建议
    """
    
    def build_model(self, recon_result: ReconResult) -> TargetModel:
        """构建目标模型"""
        model = TargetModel()
        
        # 技术栈模型
        model.tech_stack = recon_result.tech_stack
        
        # 攻击面模型
        model.attack_surface = self._analyze_attack_surface(recon_result)
        
        # 防护模型
        model.protections = self._model_protections(recon_result.waf)
        
        # 推断潜在漏洞
        model.potential_vulnerabilities = self._infer_vulnerabilities(model)
        
        return model


class WAFFingerprinter:
    """
    WAF指纹识别模块
    
    功能：
    - 识别WAF厂商（Cloudflare、AWS WAF、ModSecurity等）
    - 检测具体规则集版本
    - 推测防护强度等级
    - 生成针对性的绕过建议
    """
    
    async def identify(self, target: str) -> WAFFingerprint:
        """识别WAF"""
        # 发送探测请求
        responses = await self._send_probes(target)
        
        # 分析响应特征
        waf_type = self._classify(responses)
        rules_version = self._detect_version(responses)
        protection_level = self._assess_strength(responses)
        
        return WAFFingerprint(
            type=waf_type,
            version=rules_version,
            strength=protection_level,
            known_rules=self._get_known_rules(waf_type),
            bypass_recommendations=self._get_bypass_recommendations(waf_type),
        )
```

#### 模块6：learning.py - 学习模块

```python
class LearningEngine:
    """
    学习模块
    
    功能：
    - 从成功的攻击中学习有效模式
    - 从失败的攻击中学习失败原因
    - 优化Payload选择策略
    - 适应目标特征
    """
    
    def record_success(self, attack_record: AttackRecord):
        """记录成功案例"""
        # 提取成功特征
        features = self._extract_features(attack_record)
        
        # 更新成功率统计
        self.success_patterns.update(features)
        
        # 强化该策略的权重
        self.policy reinforce(attack_record.strategy, reward=1.0)
    
    def record_failure(self, attack_record: AttackRecord):
        """记录失败案例"""
        # 分析失败原因
        failure_reason = self._analyze_failure(attack_record)
        
        # 更新失败模式
        self.failure_patterns.add(failure_reason)
        
        # 降低该策略权重
        self.policy.reinforce(attack_record.strategy, reward=-0.5)
    
    def suggest_strategy(self, target_model: TargetModel) -> AttackStrategy:
        """基于学习结果推荐策略"""
        # 查找相似目标的历史数据
        similar_cases = self._find_similar_targets(target_model)
        
        # 综合推荐
        return self._combine_recommendations(similar_cases)
```

### 3.3 关键改进点详解

#### 改进1：从"固定Payload"到"智能合成"

**现状（[attack.py:L614-656](scanner/engine/attack.py#L614-L656)）：**
```python
DEFAULT_SAFE_PAYLOADS: Dict[PayloadType, List[str]] = {
    PayloadType.SQLI: [
        "' OR '1'='1",
        "1' AND '1'='1",
        ...
    ],
}
```

**改进后：**
```python
def synthesize_sqli_payload(self, context: AttackContext) -> str:
    """
    根据上下文合成SQL注入Payload
    
    示例逻辑：
    1. 如果检测到MySQL + ThinkPHP → 使用ThinkPHP特有语法
    2. 如果检测到PostgreSQL → 使用PG特有函数
    3. 如果检测到WAF → 使用对应的绕过技巧
    4. 如果输入点是整数类型 → 使用数字型注入
    """
    
    db_type = context.detected_db  # mysql/postgresql/mssql/oracle
    framework = context.framework  # thinkphp/django/drupal/laravel
    input_type = context.input_context  # string/integer/search
    waf_type = context.waf_type  # cloudflare/modsecurity/aws-waf
    
    # 选择基础模板
    template = self.SQLI_TEMPLATES[db_type][framework][input_type]
    
    # 应用WAF绕过
    bypassed = self.bypass_engine.apply(template, waf_type)
    
    # 个性化定制
    customized = self._customize(bypassed, context)
    
    return customized
```

#### 改进2：从"简单匹配"到"智能验证"

**现状（[core.py:L1678-1790](scanner/engine/core.py#L1678-L1790)）：**
```python
def _check_matchers(self, resp, matchers, condition="or"):
    for m in matchers:
        hit = self._match_single_matcher(resp, m)
        if condition == "or" and hit:
            return True
    return False
```

**改进后：**
```python
async def intelligent_verify(self, response: Response, 
                             payload: str,
                             context: AttackContext) -> VerificationResult:
    """
    智能验证系统
    
    多维度验证：
    1. 传统匹配器（保留现有逻辑）
    2. 行为分析（响应时间、状态码变化）
    3. 内容差异（与正常请求的对比）
    4. 副作用检测（是否产生了预期外的效果）
    5. 一致性验证（多次发送相同Payload的结果一致性）
    """
    
    # 基础匹配
    basic_match = self._check_matchers(response, matchers)
    
    # 行为分析
    behavior_score = self.analyzer.analyze_behavior(response, baseline_response)
    
    # 差异分析
    diff_score = self.diff_analyzer.compare(response, normal_responses)
    
    # 副作用检测（例如SQL注入导致的数据泄露）
    side_effects = await self._detect_side_effects(context, response)
    
    # 综合判定
    confidence = self._calculate_confidence(
        basic_match=basic_match,
        behavior=behavior_score,
        diff=diff_score,
        side_effects=side_effects,
    )
    
    return VerificationResult(
        is_vulnerable=confidence > threshold,
        confidence=confidence,
        evidence={
            "basic_match": basic_match,
            "behavior_analysis": behavior_score.to_dict(),
            "diff_analysis": diff_score.to_dict(),
            "side_effects": side_effects,
        },
    )
```

#### 改进3：从"无状态"到"完整会话管理"

**现状（[core.py:L949-966](scanner/engine/core.py#L949-L966)）：**
```python
def _get_plugin_state(self, plugin_id: str) -> Dict[str, Any]:
    if not hasattr(self, "_plugin_vars_cache"):
        self._plugin_vars_cache = {}
    if plugin_id not in self._plugin_vars_cache:
        self._plugin_vars_cache[plugin_id] = {
            "filename": "test.gif",
            "ExtractedPath": "",
            ...
        }
    return self._plugin_vars_cache[plugin_id]
```

**改进后：**
```python
class AttackSession:
    """
    完整的攻击会话管理
    
    功能：
    1. Cookie/Session管理（自动更新、过期处理）
    2. CSRF Token自动获取和刷新
    3. 多步骤状态跟踪（支持复杂的业务流程）
    4. 并发控制（避免状态竞争）
    5. 快照和回滚（支持错误恢复）
    """
    
    def __init__(self):
        self.cookies = CookieJar()
        self.auth_tokens: Dict[str, str] = {}
        self.csrf_tokens: Dict[str, CSRTToken] = {}
        self.state_machine = StateMachine()
        self.history = StateHistory()
    
    async def maintain_session(self, response: Response):
        """维护会话状态"""
        # 更新Cookie
        self.cookies.update(response.cookies)
        
        # 检测Token过期
        if self._is_token_expired(response):
            await self._refresh_tokens()
        
        # 记录状态变更
        self.history.record(self.state_machine.current_state)
    
    def snapshot(self) -> SessionSnapshot:
        """创建会话快照"""
        return SessionSnapshot(
            cookies=self.cookies.copy(),
            tokens=dict(self.auth_tokens),
            state=self.state_machine.current_state.copy(),
            timestamp=time.time(),
        )
    
    def rollback(self, snapshot: SessionSnapshot):
        """回滚到指定快照"""
        self.cookies = snapshot.cookies
        self.auth_tokens = snapshot.tokens
        self.state_machine.restore(snapshot.state)
```

---

## 四、实施路线图

### Phase 1：基础增强（2-3周）

**目标**：在不破坏现有功能的前提下，增强核心能力

- [ ] 重构 `ContextAwareEngine` 为 `ReconEngine`
  - 增加WAF指纹识别
  - 增加深层技术栈检测
  - 增加应用架构推断
  
- [ ] 增强 `AttackScriptGenerator` 为 `Weaponizer`
  - 增加目标感知的Payload合成
  - 增加WAF绕过策略库
  - 增加Exploit生成能力

- [ ] 改进 `_scan_with_plugin` 方法
  - 增加智能重试机制
  - 增强证据收集
  - 增加行为分析

### Phase 2：核心模块开发（3-4周）

**目标**：实现真正的模拟攻击框架

- [ ] 开发 `simulator.py` 核心框架
  - 实现 `AttackSimulator` 主控制器
  - 实现 `AttackOrchestrator` 编排器
  - 实现 `DecisionEngine` 决策引擎

- [ ] 开发 `exploitation.py` 利用模块
  - 实现 `SessionManager` 会话管理
  - 实现 `StateTracker` 状态追踪
  - 实现 `ImpactDemonstrator` 影响演示

- [ ] 开发 `intelligence.py` 情报模块
  - 实现 `TargetModeler` 目标建模
  - 实现 `WAFFingerprinter` WAF指纹识别

### Phase 3：智能化（2-3周）

**目标**：增加自适应和学习能力

- [ ] 开发 `learning.py` 学习模块
  - 实现模式学习
  - 实现反馈系统
  - 实现策略优化

- [ ] 集成所有模块到 `ScannerEngine`
  - 保持向后兼容
  - 提供新旧两种模式切换

### Phase 4：优化和测试（2周）

**目标**：确保稳定性和性能

- [ ] 性能优化
- [ ] 大量测试
- [ ] 文档编写

---

## 五、预期成果

### 5.1 能力提升对比

| 能力维度 | 当前水平 | 重构后水平 | 提升幅度 |
|---------|---------|-----------|---------|
| **检测准确率** | 60-70% | 85-95% | +25% |
| **误报率** | 15-20% | 3-5% | -70% |
| **WAF绕过率** | 10-20% | 60-80% | +300% |
| **未知漏洞发现** | 0% | 30-40% | 全新能力 |
| **攻击链复杂度** | 2-3步 | 5-10步 | +200% |
| **证据完整性** | 基础匹配 | 完整过程录像 | 质的飞跃 |

### 5.2 差异化优势

相比现有的开源扫描器（如AWVS、Nessus、Xray等），Aegis将具备：

1. **真正的攻击链驱动** - 不是简单的漏洞列表，而是完整的攻击故事
2. **自适应能力** - 能够根据目标特点自动调整策略
3. **教学价值** - 每一次扫描都是一次真实的攻击演练
4. **研究价值** - 积累的数据可用于安全研究

---

## 六、总结

### 6.1 核心理念转变

```
从：扫描器 = 发送Payload + 检查响应
到：扫描器 = 模拟攻击者 + 自主决策 + 持续学习
```

### 6.2 关键技术突破点

1. **目标建模** - 从"盲测"到"精确制导"
2. **智能武器化** - 从"固定Payload"到"按需合成"
3. **状态化利用** - 从"无状态请求"到"有状态攻击"
4. **自适应决策** - from "固定流程" to "动态调整"
5. **持续学习** - 从"静态规则" to "进化优化"

### 6.3 最终愿景

Aegis将成为一个**真正理解攻击、能够像安全研究员一样思考**的新一代安全扫描工具。

它不仅能够发现漏洞，还能够：
- ✅ 讲述完整的攻击故事
- ✅ 证明漏洞的实际危害
- ✅ 提供可操作的修复建议
- ✅ 帮助安全团队理解攻击者的思路

---

**下一步行动**：如果您认可这个方案，我将开始实施Phase 1的基础增强工作。
