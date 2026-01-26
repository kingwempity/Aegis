/**
 * HTTP 报文查看器组件
 * 左右分栏显示 Request 和 Response
 */
import React from 'react';
import { Card, Tabs } from 'antd';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface TrafficViewerProps {
  request?: string;
  response?: string;
  payload?: string; // 需要高亮的 Payload
}

const TrafficViewer: React.FC<TrafficViewerProps> = ({
  request = '',
  response = '',
  payload = '',
}) => {
  // 高亮 Payload
  const highlightPayload = (text: string, payload: string) => {
    if (!payload) return text;
    const regex = new RegExp(`(${payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return text.replace(regex, '<mark style="background-color: #fffb00; padding: 2px 4px;">$1</mark>');
  };

  const requestWithHighlight = payload ? highlightPayload(request, payload) : request;
  const responseWithHighlight = payload ? highlightPayload(response, payload) : response;

  const tabItems = [
    {
      key: 'request',
      label: 'Request',
      children: (
        <div style={{ maxHeight: '500px', overflow: 'auto' }}>
          {request ? (
            <SyntaxHighlighter
              language="http"
              style={vscDarkPlus}
              customStyle={{ margin: 0, borderRadius: 4 }}
            >
              {request}
            </SyntaxHighlighter>
          ) : (
            <div style={{ padding: 16, color: '#8c8c8c', textAlign: 'center' }}>
              暂无请求数据
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'response',
      label: 'Response',
      children: (
        <div style={{ maxHeight: '500px', overflow: 'auto' }}>
          {response ? (
            <SyntaxHighlighter
              language="http"
              style={vscDarkPlus}
              customStyle={{ margin: 0, borderRadius: 4 }}
            >
              {response}
            </SyntaxHighlighter>
          ) : (
            <div style={{ padding: 16, color: '#8c8c8c', textAlign: 'center' }}>
              暂无响应数据
            </div>
          )}
        </div>
      ),
    },
  ];

  return (
    <Card
      title="HTTP 报文"
      style={{
        backgroundColor: '#ffffff',
        borderRadius: 4,
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
      }}
    >
      <Tabs items={tabItems} />
      {payload && (
        <div style={{ marginTop: 16, padding: 8, backgroundColor: '#fffbe6', borderRadius: 4 }}>
          <strong>触发 Payload:</strong> <code>{payload}</code>
        </div>
      )}
    </Card>
  );
};

export default TrafficViewer;
