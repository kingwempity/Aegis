/**
 * 实验状态管理 Hook
 * 
 * 管理模拟实验的用户交互状态，仅使用 React 状态，不存储到数据库。
 */

import { useState, useCallback } from 'react';

interface ExperimentState {
  currentStepIndex: number;
  userInput: string;
  isProcessing: boolean;
  lastResponse: {
    isValid: boolean;
    feedback: string;
    score: number;
    showAnswer: boolean;
    detectedPatterns: string[];
  } | null;
  attempts: Record<number, number>;
  userInputs: Record<number, string>;
  isStepCompleted: boolean;
  showAnswer: boolean;
  hintsUsed: number[];
  experimentCompleted: boolean;
}

export function useExperimentState() {
  const [state, setState] = useState<ExperimentState>({
    currentStepIndex: 0,
    userInput: '',
    isProcessing: false,
    lastResponse: null,
    attempts: {},
    userInputs: {},
    isStepCompleted: false,
    showAnswer: false,
    hintsUsed: [],
    experimentCompleted: false,
  });

  // 更新用户输入
  const setUserInput = useCallback((input: string) => {
    setState(prev => ({
      ...prev,
      userInput: input,
      showAnswer: false,
      lastResponse: null,
    }));
  }, []);

  // 提交 Payload
  const submitPayload = useCallback(() => {
    setState(prev => ({
      ...prev,
      isProcessing: true,
    }));

    // 模拟网络延迟
    setTimeout(() => {
      setState(prev => {
        const currentAttempts = prev.attempts[prev.currentStepIndex] || 0;
        return {
          ...prev,
          isProcessing: false,
          attempts: {
            ...prev.attempts,
            [prev.currentStepIndex]: currentAttempts + 1,
          },
          userInputs: {
            ...prev.userInputs,
            [prev.currentStepIndex]: prev.userInput,
          },
        };
      });
    }, 800);
  }, []);

  // 设置验证结果
  const setValidationResult = useCallback((result: {
    isValid: boolean;
    feedback: string;
    score: number;
    detectedPatterns: string[];
  }) => {
    setState(prev => ({
      ...prev,
      lastResponse: {
        ...result,
        showAnswer: prev.showAnswer,
        detectedPatterns: result.detectedPatterns || [],
      },
      isStepCompleted: result.isValid,
    }));
  }, []);

  // 下一步
  const nextStep = useCallback((totalSteps: number) => {
    setState(prev => {
      const nextIndex = Math.min(prev.currentStepIndex + 1, totalSteps - 1);
      const isCompleted = nextIndex >= totalSteps - 1 && prev.isStepCompleted;
      
      return {
        ...prev,
        currentStepIndex: nextIndex,
        userInput: '',
        lastResponse: null,
        isStepCompleted: false,
        showAnswer: false,
        experimentCompleted: isCompleted,
      };
    });
  }, []);

  // 上一步
  const prevStep = useCallback(() => {
    setState(prev => ({
      ...prev,
      currentStepIndex: Math.max(0, prev.currentStepIndex - 1),
      userInput: '',
      lastResponse: null,
      isStepCompleted: false,
      showAnswer: false,
    }));
  }, []);

  // 显示答案
  const revealAnswer = useCallback(() => {
    setState(prev => ({
      ...prev,
      showAnswer: true,
    }));
  }, []);

  // 使用提示
  const useHint = useCallback((hintIndex: number) => {
    setState(prev => ({
      ...prev,
      hintsUsed: [...prev.hintsUsed, hintIndex],
    }));
  }, []);

  // 重置实验
  const resetExperiment = useCallback(() => {
    setState({
      currentStepIndex: 0,
      userInput: '',
      isProcessing: false,
      lastResponse: null,
      attempts: {},
      userInputs: {},
      isStepCompleted: false,
      showAnswer: false,
      hintsUsed: [],
      experimentCompleted: false,
    });
  }, []);

  return {
    ...state,
    setUserInput,
    submitPayload,
    setValidationResult,
    nextStep,
    prevStep,
    revealAnswer,
    useHint,
    resetExperiment,
  };
}
