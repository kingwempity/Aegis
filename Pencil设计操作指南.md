# Pencil 设计操作指南 - Aegis 前端界面

## 使用说明
本文档说明如何使用 Pencil 工具在 `pencil-new.pen` 文件中设计 Aegis 前端界面。

## 设计步骤

### 步骤 1: 打开文件
使用 `open_document("pencil-new.pen")` 打开设计文件。

### 步骤 2: 获取设计指南
使用 `get_guidelines("tailwind")` 和 `get_guidelines("landing-page")` 获取设计规范。

### 步骤 3: 使用 batch_design 创建设计

## 设计操作列表

### 1. Layout 组件设计

#### 1.1 Sidebar（侧边栏）
```javascript
operations = [
  // 创建侧边栏容器
  I("root", {
    type: "container",
    name: "sidebar",
    style: {
      width: 200,
      height: "100%",
      backgroundColor: "#001529",
      position: "fixed",
      left: 0,
      top: 0
    }
  }),
  
  // Logo 区域
  I("sidebar", {
    type: "container",
    name: "logo-area",
    style: {
      height: 64,
      padding: "16px",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      borderBottom: "1px solid rgba(255,255,255,0.1)"
    },
    children: [
      {
        type: "text",
        content: "AEGIS",
        style: {
          color: "#ffffff",
          fontSize: 18,
          fontWeight: "bold"
        }
      }
    ]
  }),
  
  // 菜单项
  I("sidebar", {
    type: "menu",
    name: "nav-menu",
    items: [
      { key: "dashboard", label: "仪表盘", icon: "dashboard" },
      { key: "tasks", label: "任务管理", icon: "tasks" },
      { key: "vulnerabilities", label: "漏洞审计", icon: "bug" },
      { key: "reports", label: "报告中心", icon: "file" },
      { key: "settings", label: "设置", icon: "setting" }
    ],
    style: {
      backgroundColor: "transparent",
      color: "#ffffff"
    }
  })
]
```

#### 1.2 Header（顶部栏）
```javascript
operations = [
  I("root", {
    type: "container",
    name: "header",
    style: {
      height: 64,
      backgroundColor: "#ffffff",
      borderBottom: "1px solid #e8e8e8",
      padding: "0 24px",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      position: "fixed",
      top: 0,
      left: 200,
      right: 0
    },
    children: [
      {
        type: "breadcrumb",
        items: [
          { title: "首页" },
          { title: "仪表盘" }
        ]
      },
      {
        type: "container",
        style: {
          display: "flex",
          alignItems: "center",
          gap: 16
        },
        children: [
          {
            type: "input",
            placeholder: "搜索...",
            style: {
              width: 300,
              height: 32
            }
          },
          {
            type: "avatar",
            size: 32,
            style: {
              cursor: "pointer"
            }
          }
        ]
      }
    ]
  })
]
```

### 2. Dashboard 页面设计

```javascript
operations = [
  // 主容器
  I("root", {
    type: "container",
    name: "dashboard",
    style: {
      marginLeft: 200,
      marginTop: 64,
      padding: 24,
      backgroundColor: "#f5f5f5",
      minHeight: "calc(100vh - 64px)"
    }
  }),
  
  // 统计卡片区域
  I("dashboard", {
    type: "container",
    name: "stats-cards",
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(4, 1fr)",
      gap: 16,
      marginBottom: 24
    }
  }),
  
  // 统计卡片 1: 总任务数
  I("stats-cards", {
    type: "card",
    name: "card-total-tasks",
    style: {
      backgroundColor: "#ffffff",
      padding: 24,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)"
    },
    children: [
      {
        type: "text",
        content: "总任务数",
        style: {
          fontSize: 14,
          color: "#595959",
          marginBottom: 8
        }
      },
      {
        type: "text",
        content: "128",
        style: {
          fontSize: 24,
          fontWeight: "bold",
          color: "#262626"
        }
      }
    ]
  }),
  
  // 统计卡片 2-4: 类似结构
  // ...
  
  // 图表区域
  I("dashboard", {
    type: "container",
    name: "charts-area",
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 16,
      marginBottom: 24
    }
  }),
  
  // 漏洞分布饼图
  I("charts-area", {
    type: "card",
    name: "chart-vuln-distribution",
    style: {
      backgroundColor: "#ffffff",
      padding: 24,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)"
    },
    children: [
      {
        type: "text",
        content: "漏洞分布",
        style: {
          fontSize: 16,
          fontWeight: "bold",
          color: "#262626",
          marginBottom: 16
        }
      },
      {
        type: "chart",
        chartType: "pie",
        data: [
          { name: "高危", value: 12, color: "#ff4d4f" },
          { name: "中危", value: 28, color: "#faad14" },
          { name: "低危", value: 45, color: "#1677ff" }
        ]
      }
    ]
  }),
  
  // 扫描趋势折线图
  I("charts-area", {
    type: "card",
    name: "chart-scan-trend",
    style: {
      backgroundColor: "#ffffff",
      padding: 24,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)"
    },
    children: [
      {
        type: "text",
        content: "扫描趋势",
        style: {
          fontSize: 16,
          fontWeight: "bold",
          color: "#262626",
          marginBottom: 16
        }
      },
      {
        type: "chart",
        chartType: "line",
        data: [
          { date: "01-20", value: 5 },
          { date: "01-21", value: 8 },
          { date: "01-22", value: 12 },
          // ...
        ]
      }
    ]
  }),
  
  // 最近任务列表
  I("dashboard", {
    type: "card",
    name: "recent-tasks",
    style: {
      backgroundColor: "#ffffff",
      padding: 24,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)"
    },
    children: [
      {
        type: "text",
        content: "最近任务",
        style: {
          fontSize: 16,
          fontWeight: "bold",
          color: "#262626",
          marginBottom: 16
        }
      },
      {
        type: "table",
        columns: [
          { title: "ID", key: "id" },
          { title: "目标URL", key: "url" },
          { title: "状态", key: "status" },
          { title: "创建时间", key: "created_at" }
        ],
        data: [
          { id: 1, url: "https://example.com", status: "运行中", created_at: "2026-01-26 10:00" },
          // ...
        ]
      }
    ]
  })
]
```

### 3. TaskList 页面设计

```javascript
operations = [
  I("root", {
    type: "container",
    name: "task-list",
    style: {
      marginLeft: 200,
      marginTop: 64,
      padding: 24,
      backgroundColor: "#f5f5f5",
      minHeight: "calc(100vh - 64px)"
    }
  }),
  
  // 操作栏
  I("task-list", {
    type: "container",
    name: "action-bar",
    style: {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      marginBottom: 16
    },
    children: [
      {
        type: "text",
        content: "任务管理",
        style: {
          fontSize: 18,
          fontWeight: "bold",
          color: "#262626"
        }
      },
      {
        type: "container",
        style: {
          display: "flex",
          gap: 8
        },
        children: [
          {
            type: "button",
            label: "刷新",
            style: {
              height: 32
            }
          },
          {
            type: "button",
            label: "新建扫描",
            primary: true,
            style: {
              height: 32
            }
          }
        ]
      }
    ]
  }),
  
  // 筛选栏
  I("task-list", {
    type: "container",
    name: "filter-bar",
    style: {
      display: "flex",
      gap: 16,
      marginBottom: 16,
      padding: 16,
      backgroundColor: "#ffffff",
      borderRadius: 4
    },
    children: [
      {
        type: "select",
        placeholder: "状态",
        options: ["全部", "运行中", "已完成", "失败"],
        style: {
          width: 120
        }
      },
      {
        type: "date-picker",
        placeholder: "时间范围",
        style: {
          width: 240
        }
      },
      {
        type: "input",
        placeholder: "搜索URL...",
        style: {
          width: 300
        }
      }
    ]
  }),
  
  // 任务表格
  I("task-list", {
    type: "card",
    name: "task-table",
    style: {
      backgroundColor: "#ffffff",
      padding: 24,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)"
    },
    children: [
      {
        type: "table",
        columns: [
          { title: "ID", key: "id", width: 80 },
          { title: "目标URL", key: "url" },
          { title: "扫描策略", key: "strategy", width: 120 },
          { 
            title: "状态", 
            key: "status", 
            width: 120,
            render: (status) => ({
              type: "tag",
              color: status === "运行中" ? "blue" : status === "已完成" ? "green" : "red",
              content: status
            })
          },
          { title: "创建时间", key: "created_at", width: 180 },
          { 
            title: "操作", 
            key: "action", 
            width: 120,
            render: () => ({
              type: "container",
              children: [
                { type: "button", label: "查看", link: true },
                { type: "button", label: "停止", link: true, danger: true }
              ]
            })
          }
        ],
        data: [
          {
            id: 1,
            url: "https://example.com",
            strategy: "标准",
            status: "运行中",
            created_at: "2026-01-26 10:00:00"
          },
          // ...
        ],
        pagination: {
          pageSize: 10,
          current: 1,
          total: 50
        }
      }
    ]
  })
]
```

### 4. TaskDetail 页面设计

```javascript
operations = [
  I("root", {
    type: "container",
    name: "task-detail",
    style: {
      marginLeft: 200,
      marginTop: 64,
      padding: 24,
      backgroundColor: "#f5f5f5",
      minHeight: "calc(100vh - 64px)"
    }
  }),
  
  // 任务信息卡片
  I("task-detail", {
    type: "card",
    name: "task-info",
    style: {
      backgroundColor: "#ffffff",
      padding: 24,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)",
      marginBottom: 16
    },
    children: [
      {
        type: "text",
        content: "https://example.com",
        style: {
          fontSize: 18,
          fontWeight: "bold",
          color: "#262626",
          marginBottom: 16
        }
      },
      {
        type: "container",
        style: {
          display: "flex",
          gap: 24,
          marginBottom: 16
        },
        children: [
          {
            type: "tag",
            content: "运行中",
            color: "blue"
          },
          {
            type: "progress",
            percent: 65,
            style: {
              width: 300
            }
          }
        ]
      },
      {
        type: "container",
        style: {
          display: "flex",
          gap: 16
        },
        children: [
          { type: "button", label: "暂停" },
          { type: "button", label: "停止", danger: true },
          { type: "button", label: "删除", danger: true }
        ]
      }
    ]
  }),
  
  // 标签页
  I("task-detail", {
    type: "tabs",
    name: "detail-tabs",
    items: [
      {
        key: "logs",
        label: "实时日志",
        content: {
          type: "container",
          name: "log-console",
          style: {
            backgroundColor: "#1e1e1e",
            padding: 16,
            borderRadius: 4,
            fontFamily: "Monaco, Consolas, monospace",
            fontSize: 13,
            color: "#ffffff",
            height: 400,
            overflow: "auto"
          },
          children: [
            {
              type: "text",
              content: "[2026-01-26 10:00:00] [INFO] 开始扫描 https://example.com",
              style: {
                color: "#ffffff",
                marginBottom: 4
              }
            },
            {
              type: "text",
              content: "[2026-01-26 10:00:05] [INFO] 发现链接: /login",
              style: {
                color: "#ffffff",
                marginBottom: 4
              }
            },
            {
              type: "text",
              content: "[2026-01-26 10:00:10] [WARN] 检测到潜在漏洞",
              style: {
                color: "#faad14",
                marginBottom: 4
              }
            }
          ]
        }
      },
      {
        key: "vulnerabilities",
        label: "已发现漏洞",
        content: {
          type: "table",
          columns: [
            { title: "漏洞名称", key: "name" },
            { title: "严重程度", key: "severity" },
            { title: "发现时间", key: "found_at" },
            { title: "操作", key: "action" }
          ],
          data: []
        }
      }
    ]
  })
]
```

### 5. VulnAudit 页面设计

```javascript
operations = [
  I("root", {
    type: "container",
    name: "vuln-audit",
    style: {
      marginLeft: 200,
      marginTop: 64,
      padding: 24,
      backgroundColor: "#f5f5f5",
      minHeight: "calc(100vh - 64px)",
      display: "flex",
      gap: 16
    }
  }),
  
  // 左侧漏洞列表
  I("vuln-audit", {
    type: "card",
    name: "vuln-list",
    style: {
      width: 300,
      backgroundColor: "#ffffff",
      padding: 16,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)"
    },
    children: [
      {
        type: "input",
        placeholder: "搜索漏洞...",
        style: {
          width: "100%",
          marginBottom: 16
        }
      },
      {
        type: "select",
        placeholder: "严重程度",
        options: ["全部", "高危", "中危", "低危"],
        style: {
          width: "100%",
          marginBottom: 16
        }
      },
      {
        type: "list",
        items: [
          {
            title: "SQL注入漏洞",
            description: "高危",
            extra: "2026-01-26",
            onClick: () => {}
          },
          // ...
        ]
      }
    ]
  }),
  
  // 右侧漏洞详情
  I("vuln-audit", {
    type: "card",
    name: "vuln-detail",
    style: {
      flex: 1,
      backgroundColor: "#ffffff",
      padding: 24,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.06)"
    },
    children: [
      {
        type: "container",
        style: {
          display: "flex",
          alignItems: "center",
          gap: 16,
          marginBottom: 24
        },
        children: [
          {
            type: "text",
            content: "SQL注入漏洞",
            style: {
              fontSize: 18,
              fontWeight: "bold",
              color: "#262626"
            }
          },
          {
            type: "tag",
            content: "高危",
            color: "red"
          }
        ]
      },
      
      // 基本信息
      {
        type: "card",
        style: {
          padding: 16,
          marginBottom: 16,
          backgroundColor: "#fafafa"
        },
        children: [
          {
            type: "text",
            content: "描述：在登录接口发现SQL注入漏洞",
            style: {
              marginBottom: 8
            }
          },
          {
            type: "text",
            content: "影响URL：https://example.com/login",
            style: {
              marginBottom: 8
            }
          },
          {
            type: "text",
            content: "发现时间：2026-01-26 10:00:00"
          }
        ]
      },
      
      // HTTP报文查看器
      {
        type: "container",
        name: "traffic-viewer",
        style: {
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 16,
          marginBottom: 16
        },
        children: [
          {
            type: "card",
            style: {
              padding: 16,
              backgroundColor: "#fafafa"
            },
            children: [
              {
                type: "text",
                content: "Request",
                style: {
                  fontWeight: "bold",
                  marginBottom: 8
                }
              },
              {
                type: "code-block",
                language: "http",
                content: `GET /login?username=admin' OR '1'='1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0...`
              }
            ]
          },
          {
            type: "card",
            style: {
              padding: 16,
              backgroundColor: "#fafafa"
            },
            children: [
              {
                type: "text",
                content: "Response",
                style: {
                  fontWeight: "bold",
                  marginBottom: 8
                }
              },
              {
                type: "code-block",
                language: "http",
                content: `HTTP/1.1 200 OK
Content-Type: text/html

<html>...</html>`
              }
            ]
          }
        ]
      },
      
      // 修复建议
      {
        type: "card",
        style: {
          padding: 16,
          backgroundColor: "#fafafa"
        },
        children: [
          {
            type: "text",
            content: "修复建议",
            style: {
              fontSize: 16,
              fontWeight: "bold",
              marginBottom: 12
            }
          },
          {
            type: "markdown",
            content: `## 修复方案

1. 使用参数化查询
2. 输入验证和过滤
3. 最小权限原则

\`\`\`python
# 示例代码
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
\`\`\``
          }
        ]
      }
    ]
  })
]
```

## 使用 batch_design 执行设计

将所有操作组合在一起，使用 `batch_design` 工具执行：

```javascript
batch_design({
  operations: [
    // 将所有上述操作组合在一起
    // ...
  ]
})
```

## 注意事项

1. 所有颜色值使用设计规范中定义的颜色
2. 保持简约风格，避免过度装饰
3. 使用合适的间距和布局
4. 确保响应式设计
5. 遵循 AWVS 的简约风格，避免科技风格元素
