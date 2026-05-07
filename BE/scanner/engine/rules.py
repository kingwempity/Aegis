"""
scanner.engine.rules
--------------------
规则引擎：提供框架识别、插件隔离、路径验证、响应分析、版本确认与可配置化判定。
"""

import copy
import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


class FrameworkType(Enum):
    UNKNOWN = "unknown"
    THINKPHP = "thinkphp"
    DRUPAL = "drupal"
    DJANGO = "django"
    LARAVEL = "laravel"
    WORDPRESS = "wordpress"
    SPRING = "spring"
    STRUTS2 = "struts2"
    FLASK = "flask"
    EXPRESS = "express"
    JOOMLA = "joomla"
    WEBLOGIC = "weblogic"
    TOMCAT = "tomcat"
    NGINX = "nginx"
    APACHE = "apache"
    IIS = "iis"
    PHP = "php"
    PYTHON = "python"
    NODEJS = "nodejs"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    REDIS = "redis"
    MONGODB = "mongodb"


class ValidationLevel(Enum):
    LOOSE = 1
    MODERATE = 2
    STRICT = 3

FRAMEWORK_NAME_MAP: Dict[str, FrameworkType] = {
    "thinkphp": FrameworkType.THINKPHP,
    "drupal": FrameworkType.DRUPAL,
    "wordpress": FrameworkType.WORDPRESS,
    "laravel": FrameworkType.LARAVEL,
    "django": FrameworkType.DJANGO,
    "spring": FrameworkType.SPRING,
    "flask": FrameworkType.FLASK,
    "express": FrameworkType.EXPRESS,
    "joomla": FrameworkType.JOOMLA,
    "struts2": FrameworkType.STRUTS2,
    "weblogic": FrameworkType.WEBLOGIC,
    "tomcat": FrameworkType.TOMCAT,
    "nginx": FrameworkType.NGINX,
    "apache": FrameworkType.APACHE,
    "iis": FrameworkType.IIS,
    "php": FrameworkType.PHP,
    "python": FrameworkType.PYTHON,
    "nodejs": FrameworkType.NODEJS,
    "mysql": FrameworkType.MYSQL,
    "postgresql": FrameworkType.POSTGRESQL,
    "redis": FrameworkType.REDIS,
    "mongodb": FrameworkType.MONGODB,
}


@dataclass
class FrameworkSignature:
    framework: FrameworkType
    headers: Dict[str, str] = field(default_factory=dict)
    body_patterns: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)
    exclusive_signatures: List[str] = field(default_factory=list)
    version_patterns: List[str] = field(default_factory=list)


@dataclass
class ConfidenceAdjustment:
    factor_name: str
    condition: str
    adjustment: float
    description: str


@dataclass
class ExclusionRule:
    rule_id: str
    condition: str
    exclusion_patterns: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class VersionConstraint:
    min_inclusive: Optional[str] = None
    min_exclusive: Optional[str] = None
    max_inclusive: Optional[str] = None
    max_exclusive: Optional[str] = None


@dataclass
class DetectionRule:
    plugin_id: str
    expected_frameworks: List[FrameworkType] = field(default_factory=list)
    validation_level: ValidationLevel = ValidationLevel.MODERATE
    min_confidence: float = 0.3
    required_evidence_count: int = 1
    exclusion_rules: List[str] = field(default_factory=list)
    confidence_adjustments: List[ConfidenceAdjustment] = field(default_factory=list)
    required_path_patterns: List[str] = field(default_factory=list)
    allow_when_framework_unknown: bool = True
    version_constraints: List[VersionConstraint] = field(default_factory=list)


# 默认内置规则（作为兜底，优先加载外部 rules_config.yaml）
FRAMEWORK_SIGNATURES: Dict[FrameworkType, FrameworkSignature] = {
    FrameworkType.THINKPHP: FrameworkSignature(
        framework=FrameworkType.THINKPHP,
        headers={"X-Powered-By": r"ThinkPHP"},
        body_patterns=[
            r"十年磨一剑",
            r"ThinkPHP",
            r"think_session",
            r"Var_Pathinfo",
            r"think-error",
            r"thinkphp_show_page_trace",
        ],
        url_patterns=[r"s=/index/index", r"public/static", r"\?s=", r"/index\.php"],
        exclusive_signatures=[
            "X-Powered-By: ThinkPHP",
            "Think\\Db\\Exception",
            "Think\\Exception",
            "thinkphp_show_page_trace",
            "十年磨一剑",
        ],
        version_patterns=[r"ThinkPHP\s*[Vv/]?([0-9]+(?:\.[0-9]+)+)"],
    ),
    FrameworkType.DRUPAL: FrameworkSignature(
        framework=FrameworkType.DRUPAL,
        headers={"X-Generator": r"Drupal", "X-Drupal-Cache": r".*"},
        body_patterns=[
            r"Drupal\.settings",
            r"sites/default/files",
            r"drupal\.js",
            r'name="form_build_id"',
            r"jQuery\.extend\(Drupal\.settings",
        ],
        url_patterns=[r"sites/default/files", r"node/add", r"user/register", r"q=user"],
        exclusive_signatures=[
            "X-Generator: Drupal",
            "Drupal.settings",
            "form_build_id",
            "_drupal_ajax",
            "sites/default/files",
        ],
        version_patterns=[r"Drupal\s*([0-9]+(?:\.[0-9]+)+)", r"Drupal\s+([0-9]+)"],
    ),
    FrameworkType.DJANGO: FrameworkSignature(
        framework=FrameworkType.DJANGO,
        headers={"X-Frame-Options": r".*", "Server": r".*"},  # Django默认安全头
        body_patterns=[
            r"django",
            r"csrfmiddlewaretoken",
            r"CSRF token",
            r"DJANGO_SETTINGS_MODULE",
            r"django\.core",
            r"django\.db",
            r"django\.views",
            r"Exception Type",
            r"Exception Value",
            r"Traceback \(most recent call last\)",
            r"Request information",
            r"You're seeing this error because you have",
            r"DEBUG = True",
            r"Page not found",
            r"404\.html",
            r"500\.html",
            r"Django Software Foundation",
            r"powered by Django",
            r"View does not exist",
            r"No URL matches query",
        ],
        url_patterns=[r"/admin/", r"/create_user/", r"/static/", r"\.py[/\?]", r"csrfmiddlewaretoken"],
        exclusive_signatures=[
            "django.core",
            "django.db",
            "django.views",
            "CSRFToken",
            "csrfmiddlewaretoken",
            "Django Software Foundation",
            "DEBUG = True",
            "Exception Type",
            "Exception Value",
        ],
        version_patterns=[r"Django[ /]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r"Django-([0-9]+\.[0-9]+)"],
    ),
}


EXCLUSION_RULES: Dict[str, ExclusionRule] = {
    "response_has_thinkphp_exclusive_sig": ExclusionRule(
        rule_id="response_has_thinkphp_exclusive_sig",
        condition="framework_mismatch",
        exclusion_patterns=[r"X-Powered-By:\s*ThinkPHP", r"Think\\Db\\Exception", r"Var_Pathinfo"],
        description="当响应包含ThinkPHP独有特征时，排除非ThinkPHP漏洞误报",
    ),
    "response_has_drupal_exclusive_sig": ExclusionRule(
        rule_id="response_has_drupal_exclusive_sig",
        condition="framework_mismatch",
        exclusion_patterns=[r"X-Generator:\s*Drupal", r"Drupal\.settings", r"sites/default/files"],
        description="当响应包含Drupal独有特征时，排除非Drupal漏洞误报",
    ),
}


DETECTION_RULES: Dict[str, DetectionRule] = {
    "thinkphp-sqli": DetectionRule(
        plugin_id="thinkphp-sqli",
        expected_frameworks=[FrameworkType.THINKPHP],
        validation_level=ValidationLevel.STRICT,
        min_confidence=0.45,
        required_evidence_count=2,
        exclusion_rules=["response_has_drupal_exclusive_sig"],
        required_path_patterns=[r"/index\.php", r"[?&]s="],
        allow_when_framework_unknown=True,
    ),
    "drupal-cve-2019-6341": DetectionRule(
        plugin_id="drupal-cve-2019-6341",
        expected_frameworks=[FrameworkType.DRUPAL],
        validation_level=ValidationLevel.MODERATE,
        min_confidence=0.30,
        required_evidence_count=2,
        exclusion_rules=["response_has_thinkphp_exclusive_sig"],
        required_path_patterns=[r"/user/register", r"sites/default/files", r"\?q=user/register"],
        allow_when_framework_unknown=True,
    ),
    "django-cve-2017-12794": DetectionRule(
        plugin_id="django-cve-2017-12794",
        expected_frameworks=[FrameworkType.DJANGO],
        validation_level=ValidationLevel.MODERATE,
        min_confidence=0.30,
        required_evidence_count=2,
        exclusion_rules=["response_has_thinkphp_exclusive_sig", "response_has_drupal_exclusive_sig"],
        required_path_patterns=[r"/create_user/", r"username="],
        allow_when_framework_unknown=True,
    ),
}

HIGH_SPECIFICITY_SQLI_KEYWORDS = [
    "XPATH syntax error",
    "extractvalue()",
    "updatexml()",
    "SQLSTATE[42",
    "SQLSTATE[HY000]",
    "Think\\Db\\Exception",
    "SQLSTATE[08001",
    "SQLSTATE[28000",
    "ORA-01756",
    "ORA-00933",
    "ORA-00942",
    "Microsoft OLE DB Provider",
    "Unclosed quotation mark",
    "SQLSERVER_ERROR",
]

THINKPHP_EXCLUSIVE_SQLI_KEYWORDS = [
    "Think\\Db\\Exception",
    "Think\\Exception",
    "thinkphp_show_page_trace",
]

GENERIC_SQL_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_error",
    "mysql_num_rows",
    "syntax error",
    "ora-01756",
    "unclosed quotation mark",
    "sqlstate",
    "sqlite_error",
    "sqlite3.operationalerror",
    "integrityerror",
    "operationalerror",
    "programmingerror",
    "postgresql query failed",
    "pg_query",
    "pg_exec",
    "odbc sql server driver",
    "sqlexception",
    "valid mysql result",
    "check the manual that corresponds to your mysql",
    "you have an error in your sql syntax",
    "warning: mysql_",
    "sqlalchemy.exc",
]


class RuleEngine:
    def __init__(self, config_path: Optional[str] = None):
        self._framework_signatures = copy.deepcopy(FRAMEWORK_SIGNATURES)
        self._exclusion_rules = copy.deepcopy(EXCLUSION_RULES)
        self._detection_rules = copy.deepcopy(DETECTION_RULES)
        
        # 确定配置文件路径
        self._config_path = config_path or self._default_config_path()
        self._load_external_config(self._config_path)

    def _default_config_path(self) -> str:
        """
        查找默认配置文件路径，按以下顺序尝试：
        1. 与当前脚本同级目录的 rules_config.yaml
        2. scanner/engine/rules_config.yaml (项目根目录相对路径)
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        path1 = os.path.join(script_dir, "rules_config.yaml")
        if os.path.exists(path1):
            return path1
            
        # 尝试相对于工作目录的路径（支持 BE/ 目录结构）
        path2 = os.path.join(os.getcwd(), "BE", "scanner", "engine", "rules_config.yaml")
        if not os.path.exists(path2):
            path2 = os.path.join(os.getcwd(), "scanner", "engine", "rules_config.yaml")
        return path2

    def _load_external_config(self, config_path: Optional[str]) -> None:
        if not config_path or not os.path.exists(config_path):
            logger.warning(" 规则配置文件不存在: %s", config_path)
            return

        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                if config_path.lower().endswith(".json"):
                    raw = json.load(fh)
                else:
                    raw = yaml.safe_load(fh) or {}
        except Exception as exc:
            logger.warning(" 规则配置加载失败 %s: %s", config_path, exc)
            return

        # 重新初始化以完全由配置文件驱动，而不是合并（除非配置文件中缺失）
        if "framework_signatures" in raw:
            self._framework_signatures = {}
            self._merge_framework_signatures(raw["framework_signatures"])
            
        if "exclusion_rules" in raw:
            self._exclusion_rules = {}
            self._merge_exclusion_rules(raw["exclusion_rules"])
            
        if "detection_rules" in raw:
            self._detection_rules = {}
            self._merge_detection_rules(raw["detection_rules"])
            
        logger.info(" 已成功加载外部规则配置: %s (框架数=%d, 排除规则数=%d, 检测规则数=%d)", 
                    config_path, len(self._framework_signatures), len(self._exclusion_rules), len(self._detection_rules))

    def _merge_framework_signatures(self, raw_signatures: Dict[str, Any]) -> None:
        for name, data in raw_signatures.items():
            fw = self._to_framework(name)
            if not fw:
                continue
            if not isinstance(data, dict):
                continue
            self._framework_signatures[fw] = FrameworkSignature(
                framework=fw,
                headers=data.get("headers", {}),
                body_patterns=data.get("body_patterns", []),
                url_patterns=data.get("url_patterns", []),
                exclusive_signatures=data.get("exclusive_signatures", []),
                version_patterns=data.get("version_patterns", []),
            )

    def _merge_exclusion_rules(self, raw_rules: Dict[str, Any]) -> None:
        for rule_id, data in raw_rules.items():
            if not isinstance(data, dict):
                continue
            self._exclusion_rules[rule_id] = ExclusionRule(
                rule_id=rule_id,
                condition=str(data.get("condition", "framework_mismatch")),
                exclusion_patterns=[str(x) for x in data.get("exclusion_patterns", [])],
                description=str(data.get("description", "")),
            )

    def _merge_detection_rules(self, raw_rules: Dict[str, Any]) -> None:
        for plugin_id, data in raw_rules.items():
            if not isinstance(data, dict):
                continue
            self._detection_rules[plugin_id] = DetectionRule(
                plugin_id=plugin_id,
                expected_frameworks=self._framework_list(data.get("expected_frameworks", [])),
                validation_level=self._to_validation_level(data.get("validation_level", "moderate")),
                min_confidence=float(data.get("min_confidence", 0.3)),
                required_evidence_count=int(data.get("required_evidence_count", 1)),
                exclusion_rules=[str(x) for x in data.get("exclusion_rules", [])],
                confidence_adjustments=self._parse_confidence_adjustments(data.get("confidence_adjustments", [])),
                required_path_patterns=[str(x) for x in data.get("required_path_patterns", [])],
                allow_when_framework_unknown=bool(data.get("allow_when_framework_unknown", True)),
                version_constraints=self._parse_version_constraints(data.get("version_constraints", [])),
            )

    def _parse_confidence_adjustments(self, items: List[Any]) -> List[ConfidenceAdjustment]:
        result: List[ConfidenceAdjustment] = []
        for item in items or []:
            if isinstance(item, ConfidenceAdjustment):
                result.append(item)
                continue
            if not isinstance(item, dict):
                continue
            result.append(
                ConfidenceAdjustment(
                    factor_name=str(item.get("factor_name", "custom")),
                    condition=str(item.get("condition", "")),
                    adjustment=float(item.get("adjustment", 0.0)),
                    description=str(item.get("description", "")),
                )
            )
        return result

    def _parse_version_constraints(self, items: List[Any]) -> List[VersionConstraint]:
        result: List[VersionConstraint] = []
        for item in items or []:
            if isinstance(item, VersionConstraint):
                result.append(item)
                continue
            if not isinstance(item, dict):
                continue
            result.append(
                VersionConstraint(
                    min_inclusive=item.get("min_inclusive"),
                    min_exclusive=item.get("min_exclusive"),
                    max_inclusive=item.get("max_inclusive"),
                    max_exclusive=item.get("max_exclusive"),
                )
            )
        return result

    def _to_framework(self, value: Any) -> Optional[FrameworkType]:
        if isinstance(value, FrameworkType):
            return value
        if value is None:
            return None
        value_str = str(value).strip().lower()
        for item in FrameworkType:
            if item.value == value_str:
                return item
        return None

    def _framework_list(self, values: List[Any]) -> List[FrameworkType]:
        result: List[FrameworkType] = []
        for value in values or []:
            fw = self._to_framework(value)
            if fw:
                result.append(fw)
        return result

    def _to_validation_level(self, value: Any) -> ValidationLevel:
        if isinstance(value, ValidationLevel):
            return value
        try:
            if isinstance(value, int):
                return ValidationLevel(value)
            value_str = str(value).strip().lower()
            if value_str == "loose":
                return ValidationLevel.LOOSE
            if value_str == "strict":
                return ValidationLevel.STRICT
        except Exception:
            pass
        return ValidationLevel.MODERATE

    def get_detection_rule(self, plugin_id: str) -> Optional[DetectionRule]:
        return self._detection_rules.get(plugin_id)

    def detect_framework(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str,
        response_status: int = 200,
    ) -> Tuple[List[FrameworkType], Dict[FrameworkType, float]]:
        """
        检测目标框架及其置信度。
        
        采用多维度评分机制：
        1. 响应头匹配 (权重: 0.45)
        2. 响应体通用模式匹配 (权重: 0.18)
        3. URL路径模式匹配 (权重: 0.16) — 仅在响应成功时计分
        4. 独有特征硬标记匹配 (权重: 0.55)
        """
        detected: List[FrameworkType] = []
        confidences: Dict[FrameworkType, float] = {}
        body_lower = response_body.lower()
        header_text = str(response_headers).lower()
        is_success_response = 200 <= response_status < 400

        for fw_type, sig in self._framework_signatures.items():
            score = 0.0
            # 1. 响应头匹配
            for header_name, pattern in sig.headers.items():
                header_value = response_headers.get(header_name)
                if header_value and re.search(pattern, str(header_value), re.I):
                    score += 0.45
            
            # 2. 响应体模式匹配
            for pattern in sig.body_patterns:
                if re.search(pattern, response_body, re.I):
                    score += 0.18
            
            # 3. URL模式匹配 — 仅在响应成功(2xx/3xx)时计分，避免404页面误判
            if is_success_response:
                for pattern in sig.url_patterns:
                    if re.search(pattern, request_url, re.I):
                        score += 0.16
            
            # 4. 独有特征标记匹配（最强证据）
            for marker in sig.exclusive_signatures:
                if marker.lower() in body_lower or marker.lower() in header_text:
                    score += 0.55

            if score >= 0.35:
                detected.append(fw_type)
                confidences[fw_type] = min(score, 1.0)

        if not detected:
            return [FrameworkType.UNKNOWN], {FrameworkType.UNKNOWN: 1.0}

        # 按置信度排序
        detected.sort(key=lambda item: confidences.get(item, 0.0), reverse=True)
        return detected, confidences

    def detect_version(
        self,
        framework: FrameworkType,
        response_body: str,
        response_headers: Dict[str, str],
    ) -> Optional[str]:
        """从响应中提取框架版本号"""
        sig = self._framework_signatures.get(framework)
        if not sig:
            return None
        combined = response_body + "\n" + str(response_headers)
        for pattern in sig.version_patterns:
            match = re.search(pattern, combined, re.I)
            if match:
                return match.group(1)
        return None

    def should_execute_plugin(
        self,
        plugin_id: str,
        detected_frameworks: List[FrameworkType],
        request_paths: List[str],
    ) -> Tuple[bool, str]:
        """
        判定插件是否应该在当前目标上执行。
        实现插件隔离，避免无关插件产生噪声。

        增强版逻辑（2026-04-19优化）：
        1. 未定义框架约束 → 允许执行
        2. 框架明确匹配 → 允许执行
        3. 框架不匹配 但 路径匹配 → 允许执行（标记为探测模式）
        4. 框架未知 且 allow_when_framework_unknown=True 且 路径匹配 → 允许
        5. 其他情况 → 拒绝
        """
        rule = self._detection_rules.get(plugin_id)
        if not rule or not rule.expected_frameworks:
            return True, "未定义框架约束，允许执行"

        target_frameworks = [fw for fw in detected_frameworks if fw != FrameworkType.UNKNOWN]
        expected_set = set(rule.expected_frameworks)

        if target_frameworks:
            # 如果识别到了明确的框架
            if any(fw in expected_set for fw in target_frameworks):
                return True, "目标框架与插件期望匹配"

            # 【关键修复】框架不匹配时，检查路径是否匹配
            # 如果路径匹配，仍然允许执行（作为探测），后续由matchers和置信度机制过滤
            if self._paths_match_rule(request_paths, rule.required_path_patterns):
                current = ",".join(fw.value for fw in target_frameworks)
                expected = ",".join(fw.value for fw in rule.expected_frameworks)
                return True, f"目标框架为[{current}]，与期望[{expected}]不匹配，但路径符合特征(探测模式)"

            current = ",".join(fw.value for fw in target_frameworks)
            expected = ",".join(fw.value for fw in rule.expected_frameworks)
            return False, f"目标框架为 [{current}]，与插件期望 [{expected}] 不匹配，且路径不符合"

        # 如果框架未知
        if not rule.allow_when_framework_unknown:
            return False, "目标框架未知，且插件禁止在未知框架下执行"

        # 检查请求路径是否符合该框架的典型路径
        if self._paths_match_rule(request_paths, rule.required_path_patterns):
            return True, "目标框架未知，但请求路径符合插件特征"

        return False, "目标框架未知，且请求路径不符合插件特征"

    def _paths_match_rule(self, request_paths: List[str], required_patterns: List[str]) -> bool:
        if not required_patterns:
            return True
        for path in request_paths:
            for pattern in required_patterns:
                if re.search(pattern, path, re.I):
                    return True
        return False

    def _response_framework_context(
        self,
        detected_frameworks: List[FrameworkType],
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str,
    ) -> Tuple[List[FrameworkType], Dict[FrameworkType, float]]:
        """获取响应中的框架上下文，结合初始探测结果"""
        response_frameworks, response_confidence = self.detect_framework(
            response_body=response_body,
            response_headers=response_headers,
            request_url=request_url,
        )
        # 合并已检测到的和响应中再次发现的
        merged: List[FrameworkType] = []
        for fw in list(detected_frameworks) + list(response_frameworks):
            if fw not in merged:
                merged.append(fw)
        return merged, response_confidence

    def validate_vulnerability(
        self,
        plugin_id: str,
        detected_frameworks: List[FrameworkType],
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str,
        matched_keywords: Optional[List[str]] = None,
        framework_versions: Optional[Dict[FrameworkType, Optional[str]]] = None,
        request_payload: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        多重验证漏洞判定逻辑：
        1. 排除规则检查 (Exclusion Rules) - 彻底解决循环误报的关键
        2. 框架严格性校验 (Validation Level)
        3. 路径特征验证
        4. 版本比对确认
        5. 证据强度校验
        """
        rule = self._detection_rules.get(plugin_id)
        if not rule:
            return True, "未定义检测规则，默认通过"

        matched_keywords = matched_keywords or []
        combined_frameworks, _ = self._response_framework_context(
            detected_frameworks=detected_frameworks,
            response_body=response_body,
            response_headers=response_headers,
            request_url=request_url,
        )

        body_lower = response_body.lower()
        header_text = str(response_headers).lower()
        expected_set = set(rule.expected_frameworks)
        known_combined = {fw for fw in combined_frameworks if fw != FrameworkType.UNKNOWN}

        # 1. 排除规则检查 (最核心的防误报机制)
        for ex_id in rule.exclusion_rules:
            ex_rule = self._exclusion_rules.get(ex_id)
            if not ex_rule: continue
            
            if ex_rule.condition == "framework_mismatch":
                # 如果响应中出现了其他框架的独有特征，且该插件不是针对那个框架的，则判定为误报
                triggered = any(re.search(pattern, body_lower + "\n" + header_text, re.I) for pattern in ex_rule.exclusion_patterns)
                if triggered and not any(fw in expected_set for fw in known_combined):
                    return False, f"触发排除规则: {ex_rule.description}"

        # 2. 框架匹配校验
        if rule.validation_level == ValidationLevel.STRICT and rule.expected_frameworks:
            if not any(fw in expected_set for fw in known_combined):
                current = ",".join(fw.value for fw in known_combined) if known_combined else "unknown"
                expected = ",".join(fw.value for fw in rule.expected_frameworks)
                return False, f"框架不匹配 (当前: {current}, 期望: {expected})"

        # 3. 路径验证
        if rule.required_path_patterns:
            if not self._paths_match_rule([request_url], rule.required_path_patterns):
                return False, "请求路径未通过插件路径指纹验证"

        # 4. 版本比对
        version_reason = self._validate_version(rule, combined_frameworks, response_body, response_headers, framework_versions)
        if version_reason is not None:
            return False, version_reason

        # 5. 证据强度 (LOOSE 级别除外)
        # 如果 matched_keywords 为空,自动从响应体中提取漏洞特征
        if not matched_keywords:
            matched_keywords = self._auto_extract_vuln_keywords(plugin_id, body_lower, response_body)
        
        if rule.validation_level != ValidationLevel.LOOSE and not matched_keywords:
            return False, "未提取到有效的漏洞特征证据"

        plugin_specific_reason = self._validate_plugin_specific_signal(
            plugin_id=plugin_id,
            response_body=response_body,
            response_headers=response_headers,
            request_url=request_url,
            request_payload=request_payload,
            matched_keywords=matched_keywords,
        )
        if plugin_specific_reason is not None:
            return False, plugin_specific_reason

        return True, "验证通过"

    def _auto_extract_vuln_keywords(self, plugin_id: str, body_lower: str, response_body: str) -> List[str]:
        """自动从响应体中提取漏洞特征关键词"""
        keywords = []
        
        # ThinkPHP SQL 注入特征
        if plugin_id == "thinkphp-sqli":
            sqli_markers = [
                "call stack", "connection.php", "query.php", "pdoexception",
                "x-powered-by: php", "sqlstate", "syntax error",
                "updatexml", "extractvalue", "concat(0xa",
                "think\\db\\exception", "thinkexception",
                "where_id_in_", "->query(", "pdostatement",
                "mysql_fetch", "sql syntax", "etc/passwd",
                "environment variables", "get data", "post data",
            ]
            keywords = [m for m in sqli_markers if m in body_lower]
        
        # Git 配置泄露特征
        elif plugin_id == "git-config-leak":
            git_markers = ["[core]", "repositoryformatversion", "bare = false", "dirc"]
            keywords = [m for m in git_markers if m in body_lower]
        
        # SSRF 特征
        elif plugin_id == "ssrf-probe":
            ssrf_markers = ["ami-id", "instance-id", "metadata-flavor", "ssh-2.0-"]
            keywords = [m for m in ssrf_markers if m in body_lower]
        
        # 通用 SQL 注入特征
        elif plugin_id.endswith("sqli") or "sql" in plugin_id.lower():
            general_sqli = [
                "sql syntax", "mysql_fetch", "sqlstate", "syntax error",
                "pdoexception", "updatexml", "extractvalue",
                "error in your sql syntax", "sql error", "database error",
                "call stack", "connection.php", "query.php",
            ]
            keywords = [m for m in general_sqli if m in body_lower]
        
        return keywords

    def _validate_plugin_specific_signal(
        self,
        plugin_id: str,
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str,
        request_payload: Optional[str],
        matched_keywords: List[str],
    ) -> Optional[str]:
        body = response_body or ""
        body_lower = body.lower()
        url_lower = request_url.lower()

        if plugin_id == "git-config-leak":
            strong_git_markers = [
                "[core]",
                "repositoryformatversion",
                "bare = false",
                "logallrefupdates",
                "[remote \"origin\"]",
                "[branch \"",
                "ref: refs/heads/",
                "dirc",
                "index of",
            ]
            if not any(marker in body_lower for marker in strong_git_markers):
                return "响应缺少强 Git 仓库特征，疑似错误页或占位响应"

            if "/.git/objects/" in url_lower or "/.git/refs/" in url_lower:
                if "index of" not in body_lower and "<title>index of" not in body_lower and "dirc" not in body_lower:
                    return "目录路径仅出现弱关键词，未发现可证实的 Git 目录索引或索引文件特征"

            forbidden_markers = [
                "forbidden",
                "you don't have permission",
                "access denied",
                "403 forbidden",
                "permission denied",
            ]
            if any(marker in body_lower for marker in forbidden_markers) and "index of" not in body_lower:
                return "响应更像访问被拒绝页面，而非 Git 文件泄露"

        if plugin_id == "ssrf-probe":
            canonical_payload = (request_payload or "").strip().lower()
            sanitized_body = body_lower
            if canonical_payload:
                sanitized_body = sanitized_body.replace(canonical_payload, "")
                sanitized_body = sanitized_body.replace(canonical_payload.rstrip("/"), "")

            reflected_only_markers = [
                "169.254.169.254/latest/meta-data/",
                "169.254.169.254/latest/user-data/",
                "metadata.google.internal/computeMetadata/v1/".lower(),
            ]
            for marker in reflected_only_markers:
                sanitized_body = sanitized_body.replace(marker, "")

            strong_ssrf_markers = [
                "ami-id",
                "instance-id",
                "reservation-id",
                "ami-launch-index",
                "local-ipv4",
                "public-ipv4",
                "ssh-2.0-",
                "mysql_native_password",
                "metadata-flavor",
            ]
            if not any(marker in sanitized_body for marker in strong_ssrf_markers):
                if re.search(r"\bami-[a-z0-9]+\b", sanitized_body) or re.search(r"\bi-[a-f0-9]+\b", sanitized_body):
                    return None
                return "响应更像是 payload 回显，未发现来自内网资源的独立内容"

        return None

    def _validate_version(
        self,
        rule: DetectionRule,
        frameworks: List[FrameworkType],
        response_body: str,
        response_headers: Dict[str, str],
        framework_versions: Optional[Dict[FrameworkType, Optional[str]]],
    ) -> Optional[str]:
        """验证提取到的版本号是否在漏洞受影响范围内"""
        if not rule.version_constraints or not rule.expected_frameworks:
            return None

        version_map = framework_versions or {}
        for framework in rule.expected_frameworks:
            # 优先使用已探测到的版本，否则实时检测
            version = version_map.get(framework) or self.detect_version(framework, response_body, response_headers)
            if not version: continue
            
            # 如果命中任何一个约束，则认为在影响范围内
            match_any = False
            for constraint in rule.version_constraints:
                if self._version_matches(version, constraint):
                    match_any = True
                    break
            
            if not match_any:
                return f"版本比对未通过: {framework.value} v{version} 不在受影响范围内"
        
        return None

    def _version_matches(self, version: str, constraint: VersionConstraint) -> bool:
        """检查单个版本号是否符合约束"""
        normalized = self._normalize_version(version)
        if normalized is None: return False

        def cmp(other: Optional[str]) -> Optional[int]:
            other_normalized = self._normalize_version(other) if other else None
            if other_normalized is None: return None
            
            # 补齐长度进行比较 (例如 5.0 和 5.0.24)
            max_len = max(len(normalized), len(other_normalized))
            left = normalized + (0,) * (max_len - len(normalized))
            right = other_normalized + (0,) * (max_len - len(other_normalized))
            
            if left < right: return -1
            if left > right: return 1
            return 0

        # 检查所有边界
        checks = [
            (constraint.min_inclusive, lambda v: v is None or v >= 0),
            (constraint.min_exclusive, lambda v: v is None or v > 0),
            (constraint.max_inclusive, lambda v: v is None or v <= 0),
            (constraint.max_exclusive, lambda v: v is None or v < 0),
        ]
        
        for boundary, predicate in checks:
            if boundary and not predicate(cmp(boundary)):
                return False
        return True

    def _normalize_version(self, value: Optional[str]) -> Optional[Tuple[int, ...]]:
        if not value: return None
        parts = re.findall(r"\d+", str(value))
        if not parts: return None
        return tuple(int(part) for part in parts)

    def adjust_confidence(
        self,
        plugin_id: str,
        base_confidence: float,
        detected_frameworks: List[FrameworkType],
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str,
        matched_keywords: Optional[List[str]] = None,
        request_payload: Optional[str] = None,
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        动态调整置信度评分。
        根据目标上下文（框架、路径、响应特征）进行加权或惩罚。
        """
        rule = self._detection_rules.get(plugin_id)
        if not rule:
            return base_confidence, []

        matched_keywords = matched_keywords or []
        confidence = base_confidence
        details: List[Dict[str, Any]] = []
        body_lower = response_body.lower()
        header_text = str(response_headers).lower()
        
        combined_frameworks, response_confidence = self._response_framework_context(
            detected_frameworks=detected_frameworks,
            response_body=response_body,
            response_headers=response_headers,
            request_url=request_url,
        )
        expected_set = set(rule.expected_frameworks)

        for adj in rule.confidence_adjustments:
            triggered = False
            # 条件判断逻辑
            if adj.condition == "target_is_thinkphp":
                triggered = FrameworkType.THINKPHP in detected_frameworks
            elif adj.condition == "target_is_not_thinkphp":
                triggered = FrameworkType.THINKPHP not in detected_frameworks
            elif adj.condition == "target_is_drupal":
                triggered = FrameworkType.DRUPAL in detected_frameworks
            elif adj.condition == "target_is_django":
                triggered = FrameworkType.DJANGO in detected_frameworks
            elif adj.condition == "response_is_expected_framework":
                triggered = any(fw in expected_set for fw in combined_frameworks if fw != FrameworkType.UNKNOWN)
            elif adj.condition == "response_has_thinkphp_exclusive_sig":
                triggered = self._has_exclusive_signature(FrameworkType.THINKPHP, body_lower, header_text)
            elif adj.condition == "response_has_drupal_exclusive_sig":
                triggered = self._has_exclusive_signature(FrameworkType.DRUPAL, body_lower, header_text)
            elif adj.condition == "response_has_django_exclusive_sig":
                triggered = self._has_exclusive_signature(FrameworkType.DJANGO, body_lower, header_text)
            elif adj.condition == "response_has_sql_error":
                triggered = any(err.lower() in body_lower for err in GENERIC_SQL_ERRORS)
            elif adj.condition == "response_has_xss_payload":
                xss_markers = ["<script", "<svg", "onerror=", "onload=", "javascript:", "alert("]
                triggered = any(marker in body_lower for marker in xss_markers)
            elif adj.condition == "response_has_git_config":
                git_markers = ["[core]", "repositoryformatversion", "bare = false", "ref: refs/heads/"]
                triggered = any(marker in body_lower for marker in git_markers)
            elif adj.condition == "response_has_file_content":
                file_markers = ["root:x:0:0:", "[extensions]", "[fonts]", "[boot]", "for 16-bit app support"]
                triggered = any(marker in body_lower for marker in file_markers)
            elif adj.condition == "response_has_internal_data":
                internal_markers = ["ami-id", "instance-id", "meta-data", "computeMetadata", "SSH-2.0-", "mysql_native_password"]
                triggered = any(marker in body_lower for marker in internal_markers)
            elif adj.condition == "response_has_command_output":
                cmd_markers = ["uid=", "gid=", "groups=", "www-data", "NT AUTHORITY"]
                triggered = any(marker in body_lower for marker in cmd_markers)
            elif adj.condition == "response_has_other_framework_sig":
                triggered = any(fw not in expected_set and fw != FrameworkType.UNKNOWN for fw in combined_frameworks)
            elif adj.condition == "response_has_thinkphp_debug_page":
                thinkphp_debug_markers = [
                    "call stack",
                    "connection.php",
                    "query.php line",
                    "->query(",
                    "where_id_in_",
                    "environment variables",
                    "get data",
                    "post data",
                    "thinkphp_show_page_trace",
                ]
                triggered = sum(1 for m in thinkphp_debug_markers if m in body_lower) >= 2

            if triggered:
                confidence += adj.adjustment
                details.append({
                    "factor_name": adj.factor_name,
                    "adjustment": adj.adjustment,
                    "description": adj.description,
                    "triggered": True
                })

        # 基础校验加分
        if rule.required_path_patterns and self._paths_match_rule([request_url], rule.required_path_patterns):
            confidence += 0.08
            details.append({"factor_name": "path_validation", "adjustment": 0.08, "description": "请求路径符合插件路径特征", "triggered": True})

        if matched_keywords and any(kw.lower() in body_lower for kw in matched_keywords):
            confidence += 0.05
            details.append({"factor_name": "payload_response_match", "adjustment": 0.05, "description": "响应中包含命中的关键特征", "triggered": True})

        # 响应框架加分
        for fw, val in response_confidence.items():
            if fw in expected_set and val >= 0.6:
                confidence += 0.05
                details.append({"factor_name": "response_framework_confidence", "adjustment": 0.05, "description": f"响应框架识别置信度较高: {fw.value}={val:.2f}", "triggered": True})
                break

        if plugin_id == "git-config-leak":
            forbidden_markers = ["forbidden", "you don't have permission", "access denied", "403 forbidden"]
            if any(marker in body_lower for marker in forbidden_markers) and "index of" not in body_lower:
                confidence -= 0.35
                details.append({
                    "factor_name": "forbidden_page_penalty",
                    "adjustment": -0.35,
                    "description": "响应疑似访问被拒绝页面，降低 Git 泄露置信度",
                    "triggered": True,
                })

        if plugin_id == "ssrf-probe":
            canonical_payload = (request_payload or "").strip().lower()
            sanitized_body = body_lower
            if canonical_payload:
                sanitized_body = sanitized_body.replace(canonical_payload, "")
                sanitized_body = sanitized_body.replace(canonical_payload.rstrip("/"), "")
            if "meta-data" in body_lower and "meta-data" not in sanitized_body:
                confidence -= 0.30
                details.append({
                    "factor_name": "payload_reflection_penalty",
                    "adjustment": -0.30,
                    "description": "元数据关键词仅出现在回显的 payload URL 中，降低 SSRF 置信度",
                    "triggered": True,
                })

        return max(0.0, min(1.0, confidence)), details

    def _has_exclusive_signature(self, framework: FrameworkType, body_lower: str, header_text: str) -> bool:
        sig = self._framework_signatures.get(framework)
        if not sig: return False
        return any(marker.lower() in body_lower or marker.lower() in header_text for marker in sig.exclusive_signatures)

    def get_min_confidence(self, plugin_id: str) -> float:
        rule = self._detection_rules.get(plugin_id)
        return rule.min_confidence if rule else 0.3

    def get_required_evidence_count(self, plugin_id: str) -> int:
        rule = self._detection_rules.get(plugin_id)
        return rule.required_evidence_count if rule else 1
