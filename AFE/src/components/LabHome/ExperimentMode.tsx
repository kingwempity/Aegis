/**
 * 实验模式组件
 * 
 * 交互式模拟验证实验，让用户动手操作输入 Payload 并查看响应。
 * 利用现有场景的 attack_steps 数据，无需数据库变更。
 */

import React, { useState } from 'react';
import { ResponseSimulator } from './ResponseSimulator';
import { validatePayload } from './payloadValidators';
import { useExperimentState } from './useExperimentState';
import { AttackStep, LabScenario, VULN_TYPE_NAMES } from '../LabHome';

interface ExperimentModeProps {
  scenario: LabScenario;
}

export const ExperimentMode: React.FC<ExperimentModeProps> = ({ scenario }) => {
  const experiment = useExperimentState();
  const [showHints, setShowHints] = useState(false);

  const currentStep = scenario.attack_steps[experiment.currentStepIndex];
  const totalSteps = scenario.attack_steps.length;
  const vulnTypeName = VULN_TYPE_NAMES[scenario.vuln_type] || scenario.vuln_type;

  // 处理提交
  const handleSubmit = () => {
    if (!experiment.userInput.trim()) return;

    experiment.submitPayload();

    setTimeout(() => {
      const result = validatePayload(
        scenario.vuln_type,
        experiment.userInput,
        currentStep.payload
      );
      experiment.setValidationResult(result);
    }, 1000);
  };

  // 使用场景中的 response 作为模拟响应
  const simulateResponse = () => {
    if (!experiment.lastResponse?.isValid || !currentStep.response) {
      return null;
    }
    return currentStep.response;
  };

  // 获取提示
  const getHints = (): string[] => {
    const hints: string[] = [];
    
    if (currentStep.payload) {
      hints.push('参考答案: ' + currentStep.payload);
    }
    if (currentStep.payload_explanation) {
      hints.push('Payload 说明: ' + currentStep.payload_explanation);
    }
    if (scenario.learning.principle) {
      hints.push('原理提示: ' + scenario.learning.principle.substring(0, 100) + '...');
    }

    return hints;
  };

  // 实验完成
  if (experiment.experimentCompleted) {
    return (
      <div className="bg-white rounded-xl p-8 border border-awvs-border shadow-sm">
        <div className="text-center mb-6">
          <div className="text-6xl mb-4">🎉</div>
          <h2 className="text-2xl font-bold text-awvs-text-primary mb-2">
            实验完成！
          </h2>
          <p className="text-awvs-text-secondary">
            你已成功完成「{scenario.name}」的所有实验步骤
          </p>
        </div>

        <div className="bg-awvs-bg-light rounded-lg p-6 mb-6 border border-awvs-border">
          <h3 className="text-lg font-medium text-awvs-text-primary mb-4">📊 实验统计</h3>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-2xl font-bold text-awvs-primary">{totalSteps}</div>
              <div className="text-sm text-awvs-text-muted">实验步骤</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-awvs-primary">
                {Object.values(experiment.attempts).reduce((a, b) => a + b, 0)}
              </div>
              <div className="text-sm text-awvs-text-muted">总尝试次数</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-awvs-primary">
                {experiment.hintsUsed.length}
              </div>
              <div className="text-sm text-awvs-text-muted">使用提示</div>
            </div>
          </div>
        </div>

        {scenario.learning.principle && (
          <div className="bg-awvs-bg-light rounded-lg p-6 mb-6 border border-awvs-border">
            <h3 className="text-lg font-medium text-awvs-text-primary mb-3">📚 漏洞原理</h3>
            <p className="text-awvs-text-secondary whitespace-pre-wrap">
              {scenario.learning.principle}
            </p>
          </div>
        )}

        <div className="bg-green-50 border border-green-200 rounded-lg p-6 mb-6">
          <h3 className="text-lg font-medium text-green-700 mb-3">✅ 安全影响</h3>
          <p className="text-green-600">
            {scenario.learning.impact || '该漏洞可能导致数据泄露、权限绕过等安全问题。'}
          </p>
        </div>

        <div className="flex gap-3">
          <button
            onClick={experiment.resetExperiment}
            className="flex-1 px-6 py-3 bg-awvs-primary text-white rounded-lg hover:bg-awvs-primary-hover transition-colors font-medium"
          >
            🔄 重新实验
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 实验目标 */}
      <div className="bg-awvs-bg-light rounded-xl p-6 border border-awvs-border">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold text-awvs-text-primary mb-2">
              实验目标
            </h2>
            <p className="text-awvs-text-secondary">
              当前漏洞类型：<span className="text-awvs-primary font-medium">{vulnTypeName}</span>
              {' • '}
              难度：<span className="text-awvs-primary font-medium">{scenario.difficulty}</span>
            </p>
          </div>
          <div className="text-right">
            <div className="text-sm text-awvs-text-muted">
              步骤 {experiment.currentStepIndex + 1} / {totalSteps}
            </div>
          </div>
        </div>

        {scenario.description && (
          <p className="text-awvs-text-secondary">{scenario.description}</p>
        )}

        {/* 进度条 */}
        <div className="mt-4 bg-gray-200 rounded-full h-2">
          <div
            className="bg-awvs-primary h-2 rounded-full transition-all duration-500"
            style={{ width: `${((experiment.currentStepIndex + 1) / totalSteps) * 100}%` }}
          ></div>
        </div>
      </div>

      {/* 步骤说明 */}
      {currentStep && (
        <div className="bg-white rounded-xl p-6 border border-awvs-border shadow-sm">
          <h3 className="text-lg font-medium text-awvs-text-primary mb-3">
            步骤 {currentStep.step}: {currentStep.title}
          </h3>
          {currentStep.description && (
            <p className="text-awvs-text-secondary mb-4">{currentStep.description}</p>
          )}

          {/* 请求信息 */}
          {currentStep.request && (
            <div className="bg-awvs-bg-light rounded-lg p-4 mb-4 border border-awvs-border">
              <div className="text-sm text-awvs-text-muted mb-2">目标请求:</div>
              <code className="text-sm text-green-600 font-mono">
                {currentStep.request.method || 'GET'} {currentStep.request.url || 'N/A'}
              </code>
            </div>
          )}

          {/* Payload 输入框 */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-awvs-text-secondary mb-2">
              输入你的 Payload:
            </label>
            <textarea
              value={experiment.userInput}
              onChange={(e) => experiment.setUserInput(e.target.value)}
              placeholder="在此输入你的攻击 Payload..."
              className="w-full bg-awvs-bg-light border border-awvs-border rounded-lg p-4 text-awvs-text-primary font-mono text-sm placeholder-awvs-text-muted focus:outline-none focus:border-awvs-primary focus:ring-2 focus:ring-awvs-primary/20 transition-all"
              rows={4}
              disabled={experiment.isProcessing}
            />
          </div>

          {/* 操作按钮 */}
          <div className="flex gap-3 mb-4">
            <button
              onClick={handleSubmit}
              disabled={experiment.isProcessing || !experiment.userInput.trim()}
              className="flex-1 px-6 py-3 bg-awvs-primary text-white rounded-lg hover:bg-awvs-primary-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {experiment.isProcessing ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                  发送中...
                </span>
              ) : (
                '🚀 发送请求'
              )}
            </button>
            <button
              onClick={() => setShowHints(!showHints)}
              className="px-4 py-3 bg-awvs-bg-light text-awvs-text-secondary rounded-lg hover:bg-awvs-border transition-colors border border-awvs-border"
            >
              💡 提示
            </button>
            <button
              onClick={experiment.revealAnswer}
              className="px-4 py-3 bg-yellow-50 text-yellow-700 rounded-lg hover:bg-yellow-100 transition-colors border border-yellow-200"
            >
              👁 查看答案
            </button>
          </div>

          {/* 提示区域 */}
          {showHints && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
              <h4 className="text-sm font-medium text-blue-700 mb-2">💡 提示:</h4>
              <ul className="space-y-2">
                {getHints().slice(0, 2).map((hint, index) => (
                  <li key={index} className="text-sm text-blue-600">
                    • {hint}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* 答案区域 */}
          {experiment.showAnswer && currentStep.payload && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
              <h4 className="text-sm font-medium text-yellow-700 mb-2">📝 参考答案:</h4>
              <code className="block bg-white p-3 rounded border border-yellow-200 text-sm text-red-600 font-mono">
                {currentStep.payload}
              </code>
              {currentStep.payload_explanation && (
                <p className="text-sm text-yellow-600 mt-2">
                  {currentStep.payload_explanation}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* 响应模拟器 */}
      {currentStep && (
        <ResponseSimulator
          method={currentStep.request?.method || 'GET'}
          url={currentStep.request?.url || 'N/A'}
          payload={experiment.userInput}
          response={simulateResponse()}
          isProcessing={experiment.isProcessing}
          isValid={experiment.lastResponse?.isValid ?? null}
          feedback={experiment.lastResponse?.feedback || ''}
          detectedPatterns={experiment.lastResponse?.detectedPatterns || []}
        />
      )}

      {/* 步骤导航 */}
      <div className="flex justify-between">
        <button
          onClick={() => experiment.prevStep()}
          disabled={experiment.currentStepIndex === 0}
          className="px-4 py-2 bg-awvs-bg-light text-awvs-text-secondary rounded-lg hover:bg-awvs-border disabled:opacity-50 disabled:cursor-not-allowed transition-colors border border-awvs-border"
        >
          ← 上一步
        </button>
        <button
          onClick={() => experiment.nextStep(totalSteps)}
          disabled={!experiment.isStepCompleted || experiment.currentStepIndex >= totalSteps - 1}
          className="px-4 py-2 bg-awvs-primary text-white rounded-lg hover:bg-awvs-primary-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          下一步 →
        </button>
      </div>
    </div>
  );
};
