/**
 * 响应模拟器组件
 * 
 * 以终端样式展示 HTTP 请求/响应，提供视觉反馈。
 */

import React, { useState, useEffect } from 'react';

interface ResponseSimulatorProps {
  method: string;
  url: string;
  payload: string;
  response: {
    status_code?: number;
    body_snippet?: string;
    [key: string]: unknown;
  } | null;
  isProcessing: boolean;
  isValid: boolean | null;
  feedback: string;
  detectedPatterns: string[];
}

export const ResponseSimulator: React.FC<ResponseSimulatorProps> = ({
  method,
  url,
  payload,
  response,
  isProcessing,
  isValid,
  feedback,
  detectedPatterns,
}) => {
  const [showResponse, setShowResponse] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (isProcessing) {
      setProgress(0);
      setShowResponse(false);
      
      const interval = setInterval(() => {
        setProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            setShowResponse(true);
            return 100;
          }
          return prev + 10;
        });
      }, 80);
      
      return () => clearInterval(interval);
    } else if (response) {
      setShowResponse(true);
      setProgress(100);
    }
  }, [isProcessing, response]);

  if (!payload && !isProcessing && !response) {
    return (
      <div className="bg-gray-900 rounded-lg p-6 border border-gray-700">
        <div className="text-center">
          <div className="text-gray-500 text-4xl mb-3">📡</div>
          <p className="text-gray-400 text-sm">输入 Payload 并点击"发送请求"</p>
          <p className="text-gray-500 text-xs mt-2">模拟真实 HTTP 请求并查看响应</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
      {/* 请求头 */}
      <div className="bg-gray-800 px-4 py-3 border-b border-gray-700">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-green-400 font-bold">{method}</span>
          <span className="text-gray-300 text-sm truncate flex-1">{url}</span>
        </div>
        {payload && (
          <div className="bg-gray-900 rounded px-3 py-2">
            <span className="text-gray-500 text-xs">Payload: </span>
            <code className="text-yellow-400 text-xs font-mono">{payload}</code>
          </div>
        )}
      </div>

      {/* 处理进度 */}
      {isProcessing && (
        <div className="px-4 py-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-5 h-5 border-2 border-awvs-primary/30 border-t-awvs-primary rounded-full animate-spin"></div>
            <span className="text-awvs-primary text-sm">发送请求中...</span>
          </div>
          <div className="bg-gray-800 rounded-full h-2">
            <div
              className="bg-awvs-primary h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <div className="text-gray-500 text-xs mt-2 text-center">{progress}%</div>
        </div>
      )}

      {/* 响应展示 */}
      {showResponse && response && (
        <div className="border-t border-gray-700">
          {/* 状态码 */}
          <div className="px-4 py-3 bg-gray-800">
            <div className="flex items-center gap-2">
              <span className={`text-lg font-bold ${
                response.status_code === 200
                  ? 'text-green-400'
                  : response.status_code && response.status_code >= 400
                  ? 'text-red-400'
                  : 'text-yellow-400'
              }`}>
                HTTP {response.status_code || 200}
              </span>
              {isValid !== null && (
                <span className={`ml-auto px-2 py-1 rounded text-xs font-medium ${
                  isValid
                    ? 'bg-green-900/30 text-green-400 border border-green-700'
                    : 'bg-red-900/30 text-red-400 border border-red-700'
                }`}>
                  {isValid ? '✅ 漏洞触发成功' : '⚠️ 未检测到漏洞'}
                </span>
              )}
            </div>
          </div>

          {/* 响应体 */}
          {response.body_snippet && (
            <div className="px-4 py-4">
              <div className="text-gray-500 text-xs mb-2">响应内容:</div>
              <pre className="bg-gray-950 rounded-lg p-4 overflow-x-auto border border-gray-800">
                <code className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
                  {response.body_snippet}
                </code>
              </pre>
            </div>
          )}

          {/* 检测结果 */}
          {detectedPatterns.length > 0 && (
            <div className="px-4 py-3 bg-gray-800/50 border-t border-gray-700">
              <div className="text-gray-500 text-xs mb-2">检测到的特征:</div>
              <div className="flex flex-wrap gap-2">
                {detectedPatterns.map((pattern, index) => (
                  <span
                    key={index}
                    className="px-2 py-1 bg-awvs-primary/20 text-awvs-primary rounded text-xs border border-awvs-primary/30"
                  >
                    {pattern}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* 反馈信息 */}
          {feedback && (
            <div className={`px-4 py-3 border-t ${
              isValid
                ? 'bg-green-900/20 border-green-800'
                : 'bg-yellow-900/20 border-yellow-800'
            }`}>
              <p className={`text-sm ${
                isValid ? 'text-green-400' : 'text-yellow-400'
              }`}>
                {feedback}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
