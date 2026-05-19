import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api, AttackStep, ScanExecutionEvent, ScanTask } from '../api';
import AttackChainTimeline from './AttackChainTimeline';
import { RequestResponseViewer } from './AttackChainTimeline';
import { X, Activity } from './Icons';
import { getScanStrategyMeta } from '../utils/scanStrategy';

interface ScanExecutionConsoleProps {
  taskId: number;
  onClose: () => void;
}

interface JudgmentItem {
  seq: number;
  plugin_id?: string;
  url?: string;
  adjusted_confidence?: number;
  final_decision?: string;
  final_reason?: string;
  evidence_count?: number;
}

function foldEvents(
  steps: AttackStep[],
  judgments: JudgmentItem[],
  events: ScanExecutionEvent[],
): { steps: AttackStep[]; judgments: JudgmentItem[] } {
  let s = steps;
  let j = judgments;
  for (const ev of events) {
    const payload = ev.payload || {};
    if (ev.event_type === 'stage_recorded') {
      const step = payload.step as AttackStep | undefined;
      if (step) {
        const idx = s.findIndex(
          (x) => x.step === step.step && x.stage_name === step.stage_name,
        );
        if (idx >= 0) {
          const next = [...s];
          next[idx] = { ...next[idx], ...step };
          s = next;
        } else {
          s = [...s, step];
        }
      }
    } else if (ev.event_type === 'judgment') {
      j = [
        ...j,
        {
          seq: ev.seq,
          plugin_id: payload.plugin_id as string | undefined,
          url: payload.url as string | undefined,
          adjusted_confidence: payload.adjusted_confidence as number | undefined,
          final_decision: payload.final_decision as string | undefined,
          final_reason: payload.final_reason as string | undefined,
          evidence_count: payload.evidence_count as number | undefined,
        },
      ];
    }
  }
  return { steps: s, judgments: j };
}

const ScanExecutionConsole: React.FC<ScanExecutionConsoleProps> = ({ taskId, onClose }) => {
  const [task, setTask] = useState<ScanTask | null>(null);
  const [steps, setSteps] = useState<AttackStep[]>([]);
  const [judgments, setJudgments] = useState<JudgmentItem[]>([]);
  const [stats, setStats] = useState({ requests: 0, judgments: 0, confirmed: 0 });
  const [loading, setLoading] = useState(true);
  const afterSeqRef = useRef(0);
  const timelineRef = useRef({ steps: [] as AttackStep[], judgments: [] as JudgmentItem[] });

  useEffect(() => {
    timelineRef.current = { steps, judgments };
  }, [steps, judgments]);

  const mergeEvents = useCallback((events: ScanExecutionEvent[]) => {
    if (!events.length) return;
    const folded = foldEvents(
      timelineRef.current.steps,
      timelineRef.current.judgments,
      events,
    );
    timelineRef.current = folded;
    setSteps(folded.steps);
    setJudgments(folded.judgments);
    afterSeqRef.current = events[events.length - 1].seq;
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const [taskData, eventData] = await Promise.all([
        api.getTask(taskId),
        api.getTaskExecutionEvents(taskId, afterSeqRef.current),
      ]);
      setTask(taskData);
      if (eventData.events.length) {
        mergeEvents(eventData.events);
        const last = eventData.events[eventData.events.length - 1];
        const st = last.payload?.stats as
          | { requests?: number; judgments?: number; confirmed?: number }
          | undefined;
        if (st) {
          setStats({
            requests: st.requests ?? 0,
            judgments: st.judgments ?? 0,
            confirmed: st.confirmed ?? 0,
          });
        }
      }
    } catch (e) {
      console.error('Failed to load execution console:', e);
    } finally {
      setLoading(false);
    }
  }, [taskId, mergeEvents]);

  useEffect(() => {
    setLoading(true);
    setSteps([]);
    setJudgments([]);
    timelineRef.current = { steps: [], judgments: [] };
    afterSeqRef.current = 0;
    fetchData();
  }, [taskId]);

  useEffect(() => {
    const pollMs = task?.status === 'RUNNING' ? 2000 : 8000;
    const interval = setInterval(fetchData, pollMs);
    return () => clearInterval(interval);
  }, [fetchData, task?.status]);

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail as {
        task_id?: number;
        seq?: number;
        event_type?: string;
        payload?: Record<string, unknown>;
        stats?: { requests?: number; judgments?: number; confirmed?: number };
      };
      if (detail?.task_id !== taskId || !detail.seq || detail.seq <= afterSeqRef.current) return;
      mergeEvents([
        {
          id: 0,
          task_id: taskId,
          seq: detail.seq,
          event_type: detail.event_type || 'unknown',
          payload: detail.payload || {},
          created_at: new Date().toISOString(),
        },
      ]);
      if (detail.stats) {
        setStats({
          requests: detail.stats.requests ?? 0,
          judgments: detail.stats.judgments ?? 0,
          confirmed: detail.stats.confirmed ?? 0,
        });
      }
    };
    window.addEventListener('aegis:scan-event', handler);
    return () => window.removeEventListener('aegis:scan-event', handler);
  }, [taskId, mergeEvents]);

  const selectedStep = steps.length > 0 ? steps[steps.length - 1] : undefined;
  const strategyMeta = task ? getScanStrategyMeta(task.scan_strategy) : null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="flex h-[92vh] w-full max-w-[1400px] flex-col overflow-hidden rounded-2xl border border-[#e2e8f0] bg-[#f8fafc] shadow-2xl">
        <div className="flex items-start justify-between border-b border-[#e2e8f0] bg-white px-6 py-4">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#ff6b00]">
                <Activity size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-[#1e293b]">
                  模拟攻击执行
                  {task ? ` · 任务 #${task.display_id}` : ''}
                </h2>
                <p className="font-mono text-xs text-[#64748b]">{task?.target_url || '加载�?..'}</p>
              </div>
              {task?.status === 'RUNNING' && (
                <span className="rounded-md bg-blue-100 px-2 py-0.5 text-[10px] font-bold text-blue-600">
                  验证�?                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-4 text-xs text-[#64748b]">
              {strategyMeta && (
                <span className="rounded-md bg-orange-50 px-2 py-1 font-semibold text-[#c25b00]">
                  {strategyMeta.label}
                </span>
              )}
              <span>请求 {stats.requests}</span>
              <span>初判 {stats.judgments}</span>
              <span>确认 {stats.confirmed}</span>
              <span>{task?.current_stage || '等待事件...'}</span>
            </div>
            <div className="flex h-2 w-full max-w-md items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[#e2e8f0]">
                <div
                  className="h-full bg-[#ff6b00] transition-all duration-500"
                  style={{ width: `${task?.progress ?? 0}%` }}
                />
              </div>
              <span className="text-xs font-semibold text-[#64748b]">{task?.progress ?? 0}%</span>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-[#64748b] hover:bg-[#f1f5f9]"
            title="关闭"
          >
            <X size={20} />
          </button>
        </div>

        {loading && steps.length === 0 ? (
          <div className="flex flex-1 items-center justify-center text-[#94a3b8]">加载执行数据...</div>
        ) : (
          <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-hidden p-4 lg:grid-cols-12">
            <div className="min-h-0 overflow-auto lg:col-span-4">
              <AttackChainTimeline steps={steps} title="攻击链时间线" />
            </div>
            <div className="flex min-h-0 flex-col overflow-auto lg:col-span-5">
              <div className="rounded-2xl border border-[#e2e8f0] bg-white p-4">
                <h3 className="mb-3 text-sm font-bold text-[#2d3343]">HTTP 详情</h3>
                {selectedStep ? (
                  <RequestResponseViewer
                    request={selectedStep.request}
                    response={selectedStep.response}
                    evidence={selectedStep.evidence}
                    payload={selectedStep.payload}
                  />
                ) : (
                  <p className="py-8 text-center text-sm text-[#94a3b8]">等待攻击步骤数据...</p>
                )}
              </div>
            </div>
            <div className="min-h-0 overflow-auto lg:col-span-3">
              <div className="rounded-2xl border border-[#e2e8f0] bg-white p-4">
                <h3 className="mb-3 text-sm font-bold text-[#2d3343]">初步漏洞判断</h3>
                {judgments.length === 0 ? (
                  <p className="py-6 text-center text-xs text-[#94a3b8]">暂无初判记录</p>
                ) : (
                  <div className="space-y-3">
                    {[...judgments].reverse().map((j) => (
                      <div
                        key={j.seq}
                        className={`rounded-xl border p-3 text-xs ${
                          j.final_decision === 'report'
                            ? 'border-emerald-200 bg-emerald-50'
                            : 'border-red-200 bg-red-50/60'
                        }`}
                      >
                        <p className="font-semibold text-[#2d3343]">{j.plugin_id || '未知插件'}</p>
                        {j.url && (
                          <p className="mt-1 truncate font-mono text-[#64748b]" title={j.url}>
                            {j.url}
                          </p>
                        )}
                        <p className="mt-2">
                          置信度{' '}
                          <strong>
                            {j.adjusted_confidence != null
                              ? `${(j.adjusted_confidence * 100).toFixed(1)}%`
                              : '�?}
                          </strong>
                          {' · '}
                          证据 {j.evidence_count ?? 0}
                        </p>
                        <p
                          className={`mt-1 font-bold uppercase ${
                            j.final_decision === 'report' ? 'text-emerald-600' : 'text-red-600'
                          }`}
                        >
                          {j.final_decision === 'report' ? 'REPORT' : 'SUPPRESS'}
                        </p>
                        <p className="mt-1 text-[#64748b]">{j.final_reason || '�?}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanExecutionConsole;
