"""
scanner.engine.parser
---------------------
YAML 模板解析器。
"""
import yaml
import os
from typing import List, Dict

class TemplateParser:
    @staticmethod
    def load_plugins(plugin_dir: str) -> List[Dict]:
        """加载目录下所有 YAML 插件"""
        plugins = []
        if not os.path.exists(plugin_dir):
            return []
            
        for root, _, files in os.walk(plugin_dir):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                            if data and 'requests' in data:
                                plugins.append(data)
                    except Exception as e:
                        print(f"❌ 解析插件失败 {file}: {e}")
        return plugins
