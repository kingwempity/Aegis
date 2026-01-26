/**
 * 漏洞审计页面
 * 显示漏洞列表和详情，包括 HTTP 报文和修复建议
 */
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  Card,
  List,
  Input,
  Select,
  Tag,
  Descriptions,
  Typography,
  Space,
  message,
} from 'antd';
import { BugOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';
import SeverityBadge from '../components/Vuln/SeverityBadge';
import TrafficViewer from '../components/Vuln/TrafficViewer';
import ReactMarkdown from 'react-markdown';

const API_BASE = '/api/v1';
const { Option } = Select;
const { Title, Paragraph } = Typography;

interface Vulnerability {
  id: number;
  name: string;
  severity: string;
  description: string;
  url: string;
  found_at: string;
  request?: string;
  response?: string;
  payload?: string;
  fix_suggestion?: string;
}

const VulnAudit: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [loading, setLoading] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  useEffect(() => {
    fetchVulnerabilities();
  }, []);

  useEffect(() => {
    // 如果有 ID 参数，选中对应的漏洞
    if (id && vulnerabilities.length > 0) {
      const vuln = vulnerabilities.find((v) => v.id === parseInt(id));
      if (vuln) {
        setSelectedVuln(vuln);
      }
    } else if (vulnerabilities.length > 0 && !selectedVuln) {
      // 默认选中第一个
      setSelectedVuln(vulnerabilities[0]);
    }
  }, [id, vulnerabilities]);

  const fetchVulnerabilities = async () => {
    setLoading(true);
    try {
      // TODO: 实现获取漏洞列表 API
      // const res = await axios.get(`${API_BASE}/vulnerabilities`);
      // setVulnerabilities(res.data);
      
      // 模拟数据
      const mockData: Vulnerability[] = [
        {
          id: 1,
          name: 'SQL注入漏洞',
          severity: 'high',
          description: '在登录接口发现SQL注入漏洞，攻击者可以通过构造恶意SQL语句获取数据库信息。',
          url: 'https://example.com/login',
          found_at: '2026-01-26T10:00:00',
          request: `GET /login?username=admin' OR '1'='1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`,
          response: `HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
  <h1>Welcome, admin</h1>
  <p>User ID: 1</p>
</body>
</html>`,
          payload: "admin' OR '1'='1",
          fix_suggestion: `## 修复方案

1. **使用参数化查询**
   - 使用预编译语句，避免直接拼接SQL
   - 示例代码：
   \`\`\`python
   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
   \`\`\`

2. **输入验证和过滤**
   - 对用户输入进行严格验证
   - 过滤特殊字符和SQL关键字

3. **最小权限原则**
   - 数据库用户使用最小权限
   - 避免使用管理员账户连接数据库`,
        },
      ];
      setVulnerabilities(mockData);
      if (mockData.length > 0) {
        setSelectedVuln(mockData[0]);
      }
    } catch (err) {
      message.error('获取漏洞列表失败');
    } finally {
      setLoading(false);
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter((vuln) => {
    const matchSearch = !searchText || vuln.name.toLowerCase().includes(searchText.toLowerCase());
    const matchSeverity = !severityFilter || vuln.severity === severityFilter;
    return matchSearch && matchSeverity;
  });

  return (
    <div style={{ padding: 24, backgroundColor: '#f5f5f5', minHeight: 'calc(100vh - 64px)' }}>
      <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 112px)' }}>
        {/* 左侧漏洞列表 */}
        <Card
          style={{
            width: 300,
            backgroundColor: '#ffffff',
            borderRadius: 4,
            boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            display: 'flex',
            flexDirection: 'column',
          }}
          bodyStyle={{ padding: 16, height: '100%', display: 'flex', flexDirection: 'column' }}
        >
          <div style={{ marginBottom: 16 }}>
            <Input
              placeholder="搜索漏洞..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              style={{ marginBottom: 12 }}
              allowClear
            />
            <Select
              placeholder="严重程度"
              value={severityFilter}
              onChange={setSeverityFilter}
              style={{ width: '100%' }}
              allowClear
            >
              <Option value="critical">严重</Option>
              <Option value="high">高危</Option>
              <Option value="medium">中危</Option>
              <Option value="low">低危</Option>
              <Option value="info">信息</Option>
            </Select>
          </div>

          <List
            dataSource={filteredVulnerabilities}
            loading={loading}
            style={{ flex: 1, overflow: 'auto' }}
            renderItem={(item) => (
              <List.Item
                style={{
                  cursor: 'pointer',
                  backgroundColor: selectedVuln?.id === item.id ? '#e6f7ff' : 'transparent',
                  padding: '12px',
                  borderRadius: 4,
                  marginBottom: 8,
                  border: selectedVuln?.id === item.id ? '1px solid #1677ff' : '1px solid transparent',
                }}
                onClick={() => setSelectedVuln(item)}
              >
                <List.Item.Meta
                  title={
                    <Space>
                      <BugOutlined style={{ color: '#ff4d4f' }} />
                      <span style={{ fontSize: 14, fontWeight: 500 }}>{item.name}</span>
                    </Space>
                  }
                  description={
                    <div>
                      <div style={{ marginTop: 4 }}>
                        <SeverityBadge severity={item.severity} size="small" />
                      </div>
                      <div style={{ marginTop: 4, color: '#8c8c8c', fontSize: 12 }}>
                        {dayjs(item.found_at).format('YYYY-MM-DD HH:mm')}
                      </div>
                    </div>
                  }
                />
              </List.Item>
            )}
          />
        </Card>

        {/* 右侧漏洞详情 */}
        <Card
          style={{
            flex: 1,
            backgroundColor: '#ffffff',
            borderRadius: 4,
            boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            overflow: 'auto',
          }}
        >
          {selectedVuln ? (
            <div>
              {/* 漏洞标题 */}
              <div style={{ marginBottom: 24 }}>
                <Space align="center" style={{ marginBottom: 8 }}>
                  <Title level={3} style={{ margin: 0 }}>
                    {selectedVuln.name}
                  </Title>
                  <SeverityBadge severity={selectedVuln.severity} />
                </Space>
              </div>

              {/* 基本信息 */}
              <Card
                title="基本信息"
                style={{
                  marginBottom: 16,
                  backgroundColor: '#fafafa',
                }}
              >
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="描述">
                    <Paragraph>{selectedVuln.description}</Paragraph>
                  </Descriptions.Item>
                  <Descriptions.Item label="影响URL">
                    <a href={selectedVuln.url} target="_blank" rel="noopener noreferrer">
                      {selectedVuln.url}
                    </a>
                  </Descriptions.Item>
                  <Descriptions.Item label="发现时间">
                    {dayjs(selectedVuln.found_at).format('YYYY-MM-DD HH:mm:ss')}
                  </Descriptions.Item>
                </Descriptions>
              </Card>

              {/* HTTP报文查看器 */}
              <div style={{ marginBottom: 16 }}>
                <TrafficViewer
                  request={selectedVuln.request}
                  response={selectedVuln.response}
                  payload={selectedVuln.payload}
                />
              </div>

              {/* 修复建议 */}
              {selectedVuln.fix_suggestion && (
                <Card title="修复建议" style={{ backgroundColor: '#fafafa' }}>
                  <div style={{ fontSize: 14, lineHeight: 1.8 }}>
                    <ReactMarkdown>
                      {selectedVuln.fix_suggestion}
                    </ReactMarkdown>
                  </div>
                </Card>
              )}
            </div>
          ) : (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: '#8c8c8c',
              }}
            >
              请从左侧选择一个漏洞查看详情
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

export default VulnAudit;
