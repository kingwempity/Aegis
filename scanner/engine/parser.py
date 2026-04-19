"""
scanner.engine.parser
---------------------
YAML 模板解析器。
"""

import os
import logging
from typing import List, Dict, Any, Optional

import yaml

logger = logging.getLogger(__name__)


class TemplateParser:
    @staticmethod
    def load_plugins(plugin_dir: str) -> List[Dict[str, Any]]:
        """加载目录下所有 YAML 插件并做基础校验。"""
        plugins: List[Dict[str, Any]] = []
        if not os.path.exists(plugin_dir):
            return []

        for root, _, files in os.walk(plugin_dir):
            for file in files:
                if not (file.endswith(".yaml") or file.endswith(".yml")):
                    continue
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)

                    if TemplateParser._is_valid_plugin(data):
                        plugins.append(data)
                    else:
                        logger.warning(f"跳过非法插件: {file}")
                except Exception as e:
                    logger.error(f"解析插件失败 {file}: {e}")
        return plugins

    @staticmethod
    def _is_valid_plugin(data: Optional[Dict[str, Any]]) -> bool:
        if not data or not isinstance(data, dict):
            return False
        if "requests" not in data or not isinstance(data["requests"], list):
            return False

        for req in data["requests"]:
            if not isinstance(req, dict):
                return False
            if "path" not in req or not isinstance(req["path"], list):
                return False
        return True
