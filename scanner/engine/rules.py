"""
scanner.engine.rules
--------------------
可配置规则引擎：管理漏洞检测的判定规则、框架排除策略和置信度调整。

核心功能：
1. 框架特征验证规则 - 确保漏洞检测结果与目标框架一致
2. 跨框架排除规则 - 防止A框架的检测逻辑误报B框架的漏洞
3. 可配置检测策略 - 支持动态调整检测阈值和规则
4. 置信度调整规则 - 基于多重验证因子动态调整置信度
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    STRICT = "strict"
    MODERATE = "moderate"
    RELAXED = "relaxed"


class FrameworkType(Enum):
    DRUPAL = "drupal"
    THINKPHP = "thinkphp"
    DJANGO = "django"
    LARAVEL = "laravel"
    SPRING = "spring"
    EXPRESS = "express"
    RAILS = "rails"
    ASPNET = "aspnet"
    GENERIC_PHP = "php"
    UNKNOWN = "unknown"


@dataclass
class FrameworkSignature:
    framework: FrameworkType
    header_signatures: List[str]
    body_signatures: List[str]
    url_patterns: List[str]
    exclusive_signatures: List[str]
    version_patterns: List[Dict[str, str]]


@dataclass
class ExclusionRule:
    source_framework: FrameworkType
    target_framework: FrameworkType
    exclusion_keywords: List[str]
    exclusion_patterns: List[str]
    description: str


@dataclass
class ConfidenceAdjustment:
    factor_name: str
    condition: str
    adjustment: float
    description: str


@dataclass
class DetectionRule:
    plugin_id: str
    expected_frameworks: List[FrameworkType]
    validation_level: ValidationLevel
    min_confidence: float
    required_evidence_count: int
    exclusion_rules: List[str]
    confidence_adjustments: List[ConfidenceAdjustment]


FRAMEWORK_SIGNATURES: Dict[FrameworkType, FrameworkSignature] = {
    FrameworkType.DRUPAL: FrameworkSignature(
        framework=FrameworkType.DRUPAL,
        header_signatures=[
            "X-Generator: Drupal",
            "X-Drupal-Cache",
        ],
        body_signatures=[
            "Drupal.settings",
            "drupal.js",
            'name="form_build_id"',
            'name="form_token"',
            "sites/default/files",
            "/misc/drupal.js",
            "/core/misc/drupal.js",
            "Drupal.ajax",
            "drupal-ajax",
            "_drupal_ajax",
            "user_register_form",
        ],
        url_patterns=[
            r"/user/(login|register|password)",
            r"/node/\d+",
            r"/admin/(config|structure|content|appearance)",
            r"/sites/default/files/",
            r"/\?q=user",
            r"/misc/drupal\.js",
        ],
        exclusive_signatures=[
            "X-Generator: Drupal",
            "Drupal.settings",
            "form_build_id",
            "_drupal_ajax",
            "user_register_form",
        ],
        version_patterns=[
            {"pattern": r"Drupal\s+(\d+\.\d+)", "group": "1"},
            {"pattern": r"X-Generator:\s*Drupal\s+(\d+)", "group": "1"},
            {"pattern": r'drupalVersion\s*=\s*["\'](\d+\.\d+)', "group": "1"},
        ],
    ),
    FrameworkType.THINKPHP: FrameworkSignature(
        framework=FrameworkType.THINKPHP,
        header_signatures=[
            "X-Powered-By: ThinkPHP",
        ],
        body_signatures=[
            "ThinkPHP",
            "thinkphp",
            "think_session",
            "think_path",
            "Var_Pathinfo",
            "thinkphp_show_page_trace",
            "Think\\Db\\",
            "Think\\Exception",
            "Think\\Log",
        ],
        url_patterns=[
            r"/index\.php\?s=",
            r"/index\.php/index/",
            r"/index/index/",
        ],
        exclusive_signatures=[
            "X-Powered-By: ThinkPHP",
            "Think\\Db\\Exception",
            "Think\\Exception",
            "thinkphp_show_page_trace",
            "Var_Pathinfo",
        ],
        version_patterns=[
            {"pattern": r"ThinkPHP\s*V?(\d+\.\d+)", "group": "1"},
            {"pattern": r"X-Powered-By:\s*ThinkPHP/?V?(\d+\.\d+)", "group": "1"},
            {"pattern": r"THINK_VERSION\s*=\s*['\"](\d+\.\d+)", "group": "1"},
        ],
    ),
    FrameworkType.DJANGO: FrameworkSignature(
        framework=FrameworkType.DJANGO,
        header_signatures=[
            "X-Frame-Options: DENY",
        ],
        body_signatures=[
            "csrfmiddlewaretoken",
            "Django",
            "django",
        ],
        url_patterns=[
            r"/admin/login/",
            r"/static/admin/",
        ],
        exclusive_signatures=[
            "csrfmiddlewaretoken",
        ],
        version_patterns=[],
    ),
    FrameworkType.LARAVEL: FrameworkSignature(
        framework=FrameworkType.LARAVEL,
        header_signatures=[
            "X-Powered-By: PHP",
        ],
        body_signatures=[
            "laravel_session",
            "csrf-token",
            "Laravel",
        ],
        url_patterns=[],
        exclusive_signatures=[
            "laravel_session",
        ],
        version_patterns=[],
    ),
    FrameworkType.GENERIC_PHP: FrameworkSignature(
        framework=FrameworkType.GENERIC_PHP,
        header_signatures=[
            "X-Powered-By: PHP",
        ],
        body_signatures=[
            ".php",
        ],
        url_patterns=[
            r"\.php$",
            r"\.php\?",
        ],
        exclusive_signatures=[],
        version_patterns=[],
    ),
}


CROSS_FRAMEWORK_EXCLUSIONS: Dict[str, ExclusionRule] = {
    "thinkphp_on_drupal": ExclusionRule(
        source_framework=FrameworkType.THINKPHP,
        target_framework=FrameworkType.DRUPAL,
        exclusion_keywords=[
            "Drupal.settings",
            "form_build_id",
            "_drupal_ajax",
            "drupal.js",
            "sites/default/files",
            "user_register_form",
        ],
        exclusion_patterns=[
            r"X-Generator:\s*Drupal",
            r'name="form_build_id"',
            r"Drupal\.settings",
        ],
        description="当目标被识别为Drupal时，排除ThinkPHP SQL注入误报",
    ),
    "drupal_on_thinkphp": ExclusionRule(
        source_framework=FrameworkType.DRUPAL,
        target_framework=FrameworkType.THINKPHP,
        exclusion_keywords=[
            "ThinkPHP",
            "thinkphp",
            "Think\\Db\\",
            "Var_Pathinfo",
            "thinkphp_show_page_trace",
        ],
        exclusion_patterns=[
            r"X-Powered-By:\s*ThinkPHP",
            r"Think\\Db\\Exception",
            r"Var_Pathinfo",
        ],
        description="当目标被识别为ThinkPHP时，排除Drupal漏洞误报",
    ),
}


DETECTION_RULES: Dict[str, DetectionRule] = {
    "thinkphp-sqli": DetectionRule(
        plugin_id="thinkphp-sqli",
        expected_frameworks=[FrameworkType.THINKPHP, FrameworkType.GENERIC_PHP],
        validation_level=ValidationLevel.MODERATE,
        min_confidence=0.25,
        required_evidence_count=1,
        exclusion_rules=["thinkphp_on_drupal"],
        confidence_adjustments=[
            ConfidenceAdjustment(
                factor_name="framework_match",
                condition="target_is_thinkphp",
                adjustment=0.15,
                description="目标确认是ThinkPHP框架，提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="framework_mismatch",
                condition="target_is_not_thinkphp",
                adjustment=-0.20,
                description="目标不是ThinkPHP框架，降低置信度",
            ),
            ConfidenceAdjustment(
                factor_name="exclusive_signature_hit",
                condition="response_has_thinkphp_exclusive_sig",
                adjustment=0.25,
                description="响应包含ThinkPHP独有特征，大幅提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="cross_framework_exclusion",
                condition="response_has_other_framework_sig",
                adjustment=-0.40,
                description="响应包含其他框架独有特征，大幅降低置信度",
            ),
            ConfidenceAdjustment(
                factor_name="generic_error_only",
                condition="only_generic_error_keywords",
                adjustment=-0.15,
                description="仅匹配通用错误关键词，降低置信度",
            ),
            ConfidenceAdjustment(
                factor_name="path_validation",
                condition="thinkphp_path_matched",
                adjustment=0.10,
                description="请求路径匹配ThinkPHP典型路由模式",
            ),
        ],
    ),
    "drupal-cve-2019-6341": DetectionRule(
        plugin_id="drupal-cve-2019-6341",
        expected_frameworks=[FrameworkType.DRUPAL],
        validation_level=ValidationLevel.STRICT,
        min_confidence=0.30,
        required_evidence_count=1,
        exclusion_rules=["drupal_on_thinkphp"],
        confidence_adjustments=[
            ConfidenceAdjustment(
                factor_name="framework_match",
                condition="target_is_drupal",
                adjustment=0.20,
                description="目标确认是Drupal框架，提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="framework_mismatch",
                condition="target_is_not_drupal",
                adjustment=-0.30,
                description="目标不是Drupal框架，大幅降低置信度",
            ),
            ConfidenceAdjustment(
                factor_name="drupal_exclusive_hit",
                condition="response_has_drupal_exclusive_sig",
                adjustment=0.25,
                description="响应包含Drupal独有特征，大幅提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="cross_framework_exclusion",
                condition="response_has_other_framework_sig",
                adjustment=-0.40,
                description="响应包含其他框架独有特征，大幅降低置信度",
            ),
        ],
    ),
    "xss-reflected": DetectionRule(
        plugin_id="xss-reflected",
        expected_frameworks=[],
        validation_level=ValidationLevel.RELAXED,
        min_confidence=0.20,
        required_evidence_count=1,
        exclusion_rules=[],
        confidence_adjustments=[],
    ),
    "sqli-probe": DetectionRule(
        plugin_id="sqli-probe",
        expected_frameworks=[],
        validation_level=ValidationLevel.RELAXED,
        min_confidence=0.20,
        required_evidence_count=1,
        exclusion_rules=[],
        confidence_adjustments=[],
    ),
    "git-config-leak": DetectionRule(
        plugin_id="git-config-leak",
        expected_frameworks=[],
        validation_level=ValidationLevel.RELAXED,
        min_confidence=0.15,
        required_evidence_count=1,
        exclusion_rules=[],
        confidence_adjustments=[],
    ),
    "django-cve-2017-12794": DetectionRule(
        plugin_id="django-cve-2017-12794",
        expected_frameworks=[FrameworkType.DJANGO],
        validation_level=ValidationLevel.MODERATE,
        min_confidence=0.25,
        required_evidence_count=1,
        exclusion_rules=[],
        confidence_adjustments=[],
    ),
}


THINKPHP_EXCLUSIVE_SQLI_KEYWORDS = [
    "Think\\Db\\Exception",
    "Think\\Exception",
    "ThinkPHP",
    "thinkphp",
    "Var_Pathinfo",
]

GENERIC_SQL_ERROR_KEYWORDS = [
    "SQLSTATE",
    "SQL syntax",
    "mysql_",
    "Database Error",
    "SQL Error",
    "error",
    "Error",
    "exception",
    "Exception",
    "fatal",
    "Fatal",
]

HIGH_SPECIFICITY_SQLI_KEYWORDS = [
    "XPATH syntax error",
    "extractvalue()",
    "updatexml()",
    "SQLSTATE[42",
    "SQLSTATE[HY000]: General error",
    "SQLSTATE[42000]",
    "SQLSTATE[42S22]",
    "SQLSTATE[21S01]",
    "SQLSTATE[23000]",
    "You have an error in your SQL syntax",
    "check the manual that corresponds to your MySQL",
    "PDO::prepare()",
    "PDOException",
]


class RuleEngine:
    """
    可配置规则引擎。

    管理漏洞检测的判定规则、框架排除策略和置信度调整。
    支持从JSON配置文件动态加载规则，也支持运行时修改。
    """

    def __init__(self, config_path: Optional[str] = None):
        self._framework_signatures = dict(FRAMEWORK_SIGNATURES)
        self._exclusion_rules = dict(CROSS_FRAMEWORK_EXCLUSIONS)
        self._detection_rules = dict(DETECTION_RULES)
        self._custom_rules: Dict[str, Any] = {}

        if config_path and os.path.exists(config_path):
            self._load_config(config_path)

    def _load_config(self, config_path: str) -> None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            if "detection_rules" in config:
                for rule_data in config["detection_rules"]:
                    rule = self._parse_detection_rule(rule_data)
                    if rule:
                        self._detection_rules[rule.plugin_id] = rule
            if "exclusion_rules" in config:
                for rule_data in config["exclusion_rules"]:
                    rule = self._parse_exclusion_rule(rule_data)
                    if rule:
                        self._exclusion_rules[rule["id"]] = rule["rule"]
            logger.info(f"📋 从 {config_path} 加载了自定义规则配置")
        except Exception as e:
            logger.warning(f"⚠️ 加载规则配置失败: {e}")

    def _parse_detection_rule(self, data: Dict[str, Any]) -> Optional[DetectionRule]:
        try:
            return DetectionRule(
                plugin_id=data["plugin_id"],
                expected_frameworks=[FrameworkType(f) for f in data.get("expected_frameworks", [])],
                validation_level=ValidationLevel(data.get("validation_level", "moderate")),
                min_confidence=data.get("min_confidence", 0.35),
                required_evidence_count=data.get("required_evidence_count", 2),
                exclusion_rules=data.get("exclusion_rules", []),
                confidence_adjustments=[
                    ConfidenceAdjustment(
                        factor_name=adj["factor_name"],
                        condition=adj["condition"],
                        adjustment=adj["adjustment"],
                        description=adj.get("description", ""),
                    )
                    for adj in data.get("confidence_adjustments", [])
                ],
            )
        except Exception as e:
            logger.warning(f"⚠️ 解析检测规则失败: {e}")
            return None

    def _parse_exclusion_rule(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            rule = ExclusionRule(
                source_framework=FrameworkType(data["source_framework"]),
                target_framework=FrameworkType(data["target_framework"]),
                exclusion_keywords=data.get("exclusion_keywords", []),
                exclusion_patterns=data.get("exclusion_patterns", []),
                description=data.get("description", ""),
            )
            return {"id": data["id"], "rule": rule}
        except Exception as e:
            logger.warning(f"⚠️ 解析排除规则失败: {e}")
            return None

    def detect_framework(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str = "",
    ) -> Tuple[List[FrameworkType], Dict[FrameworkType, float]]:
        """
        多维度框架检测，返回检测到的框架列表和各框架的置信度。

        检测维度：
        1. 响应头特征
        2. 响应体特征
        3. URL路径模式
        4. 独有特征（高权重）
        """
        detected: List[FrameworkType] = []
        confidence_map: Dict[FrameworkType, float] = {}

        header_text = " ".join(f"{k}: {v}" for k, v in response_headers.items()).lower()
        body_lower = response_body.lower() if response_body else ""

        for fw_type, sig in self._framework_signatures.items():
            score = 0.0

            for hs in sig.header_signatures:
                if hs.lower() in header_text:
                    score += 0.35
                    break

            body_hit_count = 0
            for bs in sig.body_signatures:
                if bs.lower() in body_lower:
                    body_hit_count += 1
            if body_hit_count > 0:
                score += min(0.15 * body_hit_count, 0.30)

            exclusive_hit = False
            for es in sig.exclusive_signatures:
                if es.lower() in body_lower or es.lower() in header_text:
                    exclusive_hit = True
                    score += 0.40
                    break

            if request_url:
                for up in sig.url_patterns:
                    if re.search(up, request_url, re.IGNORECASE):
                        score += 0.10
                        break

            if score > 0.15:
                detected.append(fw_type)
                confidence_map[fw_type] = min(score, 1.0)

        detected.sort(key=lambda fw: confidence_map.get(fw, 0.0), reverse=True)
        return detected, confidence_map

    def detect_version(
        self,
        framework: FrameworkType,
        response_body: str,
        response_headers: Dict[str, str],
    ) -> Optional[str]:
        """检测框架版本号"""
        sig = self._framework_signatures.get(framework)
        if not sig:
            return None

        combined = response_body + " ".join(str(v) for v in response_headers.values())

        for vp in sig.version_patterns:
            pattern = vp["pattern"]
            group = int(vp.get("group", "1"))
            try:
                match = re.search(pattern, combined, re.IGNORECASE)
                if match and len(match.groups()) >= group:
                    return match.group(group)
            except (re.error, IndexError):
                continue

        return None

    def should_exclude(
        self,
        plugin_id: str,
        detected_frameworks: List[FrameworkType],
        response_body: str,
        response_headers: Dict[str, str],
    ) -> Tuple[bool, str]:
        """
        检查是否应该排除当前检测结果（跨框架误报防护）。

        Returns:
            (should_exclude, reason)
        """
        rule = self._detection_rules.get(plugin_id)
        if not rule:
            return False, ""

        body_lower = response_body.lower() if response_body else ""
        header_text = " ".join(f"{k}: {v}" for k, v in response_headers.items()).lower()

        for exclusion_rule_id in rule.exclusion_rules:
            excl_rule = self._exclusion_rules.get(exclusion_rule_id)
            if not excl_rule:
                continue

            if excl_rule.target_framework in detected_frameworks:
                for kw in excl_rule.exclusion_keywords:
                    if kw.lower() in body_lower or kw.lower() in header_text:
                        return True, (
                            f"跨框架排除: 插件[{plugin_id}]针对"
                            f"{excl_rule.source_framework.value}，"
                            f"但目标为{excl_rule.target_framework.value}，"
                            f"且响应包含{excl_rule.target_framework.value}独有特征'{kw}'"
                        )

                for pat in excl_rule.exclusion_patterns:
                    try:
                        if re.search(pat, body_lower) or re.search(pat, header_text):
                            return True, (
                                f"跨框架排除: 插件[{plugin_id}]针对"
                                f"{excl_rule.source_framework.value}，"
                                f"但目标响应匹配{excl_rule.target_framework.value}模式'{pat}'"
                            )
                    except re.error:
                        continue

        return False, ""

    def adjust_confidence(
        self,
        plugin_id: str,
        base_confidence: float,
        detected_frameworks: List[FrameworkType],
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str = "",
        matched_keywords: Optional[List[str]] = None,
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        基于多重验证因子调整置信度。

        Returns:
            (adjusted_confidence, adjustment_details)
        """
        rule = self._detection_rules.get(plugin_id)
        if not rule:
            return base_confidence, []

        confidence = base_confidence
        adjustments: List[Dict[str, Any]] = []

        body_lower = response_body.lower() if response_body else ""
        header_text = " ".join(f"{k}: {v}" for k, v in response_headers.items()).lower()

        for adj in rule.confidence_adjustments:
            triggered = False

            if adj.condition == "target_is_thinkphp":
                triggered = FrameworkType.THINKPHP in detected_frameworks
            elif adj.condition == "target_is_not_thinkphp":
                triggered = FrameworkType.THINKPHP not in detected_frameworks
            elif adj.condition == "target_is_drupal":
                triggered = FrameworkType.DRUPAL in detected_frameworks
            elif adj.condition == "target_is_not_drupal":
                triggered = FrameworkType.DRUPAL not in detected_frameworks
            elif adj.condition == "response_has_thinkphp_exclusive_sig":
                thinkphp_sig = self._framework_signatures.get(FrameworkType.THINKPHP)
                if thinkphp_sig:
                    triggered = any(
                        es.lower() in body_lower or es.lower() in header_text
                        for es in thinkphp_sig.exclusive_signatures
                    )
            elif adj.condition == "response_has_drupal_exclusive_sig":
                drupal_sig = self._framework_signatures.get(FrameworkType.DRUPAL)
                if drupal_sig:
                    triggered = any(
                        es.lower() in body_lower or es.lower() in header_text
                        for es in drupal_sig.exclusive_signatures
                    )
            elif adj.condition == "response_has_other_framework_sig":
                expected = set(rule.expected_frameworks)
                for fw in detected_frameworks:
                    if fw not in expected and fw != FrameworkType.UNKNOWN:
                        fw_sig = self._framework_signatures.get(fw)
                        if fw_sig:
                            triggered = any(
                                es.lower() in body_lower or es.lower() in header_text
                                for es in fw_sig.exclusive_signatures
                            )
                            if triggered:
                                break
            elif adj.condition == "only_generic_error_keywords":
                if matched_keywords:
                    has_specific = any(
                        kw.lower() in [k.lower() for k in HIGH_SPECIFICITY_SQLI_KEYWORDS + THINKPHP_EXCLUSIVE_SQLI_KEYWORDS]
                        for kw in matched_keywords
                    )
                    has_generic = any(
                        kw.lower() in [k.lower() for k in GENERIC_SQL_ERROR_KEYWORDS]
                        for kw in matched_keywords
                    )
                    triggered = has_generic and not has_specific
            elif adj.condition == "thinkphp_path_matched":
                if request_url:
                    triggered = any(
                        re.search(pat, request_url, re.IGNORECASE)
                        for pat in self._framework_signatures.get(FrameworkType.THINKPHP, FrameworkSignature(
                            framework=FrameworkType.THINKPHP,
                            header_signatures=[], body_signatures=[],
                            url_patterns=[], exclusive_signatures=[], version_patterns=[],
                        )).url_patterns
                    )

            if triggered:
                confidence += adj.adjustment
                adjustments.append({
                    "factor": adj.factor_name,
                    "adjustment": adj.adjustment,
                    "description": adj.description,
                    "triggered": True,
                })
            else:
                adjustments.append({
                    "factor": adj.factor_name,
                    "adjustment": 0.0,
                    "description": adj.description,
                    "triggered": False,
                })

        confidence = max(0.0, min(1.0, confidence))
        return confidence, adjustments

    def get_min_confidence(self, plugin_id: str) -> float:
        rule = self._detection_rules.get(plugin_id)
        return rule.min_confidence if rule else 0.15

    def get_required_evidence_count(self, plugin_id: str) -> int:
        rule = self._detection_rules.get(plugin_id)
        return rule.required_evidence_count if rule else 1

    def get_validation_level(self, plugin_id: str) -> ValidationLevel:
        rule = self._detection_rules.get(plugin_id)
        return rule.validation_level if rule else ValidationLevel.MODERATE

    def get_expected_frameworks(self, plugin_id: str) -> List[FrameworkType]:
        rule = self._detection_rules.get(plugin_id)
        return rule.expected_frameworks if rule else []

    def validate_vulnerability(
        self,
        plugin_id: str,
        detected_frameworks: List[FrameworkType],
        response_body: str,
        response_headers: Dict[str, str],
        request_url: str,
        matched_keywords: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """
        综合验证漏洞检测结果是否可信。

        Returns:
            (is_valid, reason)
        """
        rule = self._detection_rules.get(plugin_id)
        if not rule:
            return True, "无特定规则，默认通过"

        excluded, exclude_reason = self.should_exclude(
            plugin_id, detected_frameworks, response_body, response_headers
        )
        if excluded:
            return False, exclude_reason

        if rule.validation_level == ValidationLevel.STRICT:
            expected_fw_set = set(rule.expected_frameworks)
            if expected_fw_set and not any(fw in expected_fw_set for fw in detected_frameworks):
                return False, (
                    f"严格模式: 插件[{plugin_id}]要求目标为"
                    f"{[fw.value for fw in rule.expected_frameworks]}，"
                    f"但检测到{[fw.value for fw in detected_frameworks]}"
                )

        return True, "验证通过"

    def add_detection_rule(self, rule: DetectionRule) -> None:
        self._detection_rules[rule.plugin_id] = rule
        logger.info(f"📋 添加检测规则: {rule.plugin_id}")

    def add_exclusion_rule(self, rule_id: str, rule: ExclusionRule) -> None:
        self._exclusion_rules[rule_id] = rule
        logger.info(f"📋 添加排除规则: {rule_id}")

    def export_config(self, output_path: str) -> None:
        config = {
            "detection_rules": [],
            "exclusion_rules": [],
        }
        for rule in self._detection_rules.values():
            config["detection_rules"].append({
                "plugin_id": rule.plugin_id,
                "expected_frameworks": [fw.value for fw in rule.expected_frameworks],
                "validation_level": rule.validation_level.value,
                "min_confidence": rule.min_confidence,
                "required_evidence_count": rule.required_evidence_count,
                "exclusion_rules": rule.exclusion_rules,
                "confidence_adjustments": [
                    {
                        "factor_name": adj.factor_name,
                        "condition": adj.condition,
                        "adjustment": adj.adjustment,
                        "description": adj.description,
                    }
                    for adj in rule.confidence_adjustments
                ],
            })
        for rule_id, rule in self._exclusion_rules.items():
            config["exclusion_rules"].append({
                "id": rule_id,
                "source_framework": rule.source_framework.value,
                "target_framework": rule.target_framework.value,
                "exclusion_keywords": rule.exclusion_keywords,
                "exclusion_patterns": rule.exclusion_patterns,
                "description": rule.description,
            })

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.info(f"📋 规则配置已导出到: {output_path}")
