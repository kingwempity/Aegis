import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api';
import type { AttackStep, ScanExecutionEvent, ScanTask } from '../api';
import AttackChainTimeline from './AttackChainTimeline';
import { RequestResponseViewer } from './AttackChainTimeline';
import { X, Activity } from './Icons';
import { getScanStrategyMeta } from '../utils/scanStrategy';

/** UI labels (Unicode escapes avoid encoding corruption in CI/Docker builds) */
const UI = {
  title: '\u6A21\u62DF\u653B\u51FB\u6267\u884C',
  taskPrefix: ' \u00B7 \u4EFB\u52A1 #',
  loading: '\u52A0\u8F7D\u4E2D...',
  validating: '\u9A8C\u8BC1\u4E2D',
  requests: '\u8BF7\u6C42',
  judgments: '\u521D\u5224',
  confirmed: '\u786E\u8BA4',
  waitingEvents: '\u7B49\u5F85\u4E8B\u4EF6...',
  close: '\u5173\u95ED',
  loadingData: '\u52A0\u8F7D\u6267\u884C\u6570\u636E...',
  timeline: '\u653B\u51FB\u94FE\u65F6\u95F4\u7EBF',
  httpDetail: 'HTTP \u8BE6\u60C5',
  waitingSteps: '\u7B49\u5F85\u653B\u51FB\u6B65\u9AA4\u6570\u636E...',
  vulnJudgment: '\u521D\u6B65\u6F0F\u6D1E\u5224\u65AD',
  noJudgments: '\u6682\u65E0\u521D\u5224\u8BB0\u5F55',
  unknownPlugin: '\u672A\u77E5\u63D2\u4EF6',
  confidence: '\u7F6E\u4FE1\u5EA6',
  evidence: '\u8BC1\u636E',
  sep: '\u00B7',
} as const;

/** Console replays these only; skips bulky request_completed payloads. */
const CONSOLE_EVENT_TYPES = [
  'stage_recorded',
  'judgment',
  'vulnerability_confirmed',
  'scan_progress',
  'phase_started',
];

const INITIAL_EVENT_PAGE = 80;
const EVENT_PAGE_SIZE = 120;

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

type ExecutionStats = { requests?: number; judgments?: number; confirmed?: number };

function extractStats(
  source: { stats?: ExecutionStats; payload?: Record<string, unknown> },
): ExecutionStats | undefined {
  if (source.stats) return source.stats;
  const nested = source.payload?.stats;
  if (nested && typeof nested === 'object') {
    return nested as ExecutionStats;
  }
  return undefined;
}

function applyStats(
  stats: ExecutionStats,
  setStats: React.Dispatch<
    React.SetStateAction<{ requests: number; judgments: number; confirmed: number }>
  >,
) {
  setStats({
    requests: stats.requests ?? 0,
    judgments: stats.judgments ?? 0,
    confirmed: stats.confirmed ?? 0,
  });
}

function applyStatsFromEvents(
  events: ScanExecutionEvent[],
  setStats: React.Dispatch<
    React.SetStateAction<{ requests: number; judgments: number; confirmed: number }>
  >,
) {
  const st = extractStats(events[events.length - 1]);
  if (st) applyStats(st, setStats);
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
  const [eventsLoading, setEventsLoading] = useState(true);
  const afterSeqRef = useRef(0);
  const timelineRef = useRef({ steps: [] as AttackStep[], judgments: [] as JudgmentItem[] });
  const backfillRunningRef = useRef(false);

  const advanceAfterSeq = useCallback((seq: number) => {
    if (seq > afterSeqRef.current) {
      afterSeqRef.current = seq;
    }
  }, []);

  useEffect(() => {
    timelineRef.current = { steps, judgments };
  }, [steps, judgments]);

  const mergeEvents = useCallback(
    (events: ScanExecutionEvent[]) => {
      if (!events.length) return;
      const folded = foldEvents(
        timelineRef.current.steps,
        timelineRef.current.judgments,
        events,
      );
      timelineRef.current = folded;
      setSteps(folded.steps);
      setJudgments(folded.judgments);
      advanceAfterSeq(events[events.length - 1].seq);
      applyStatsFromEvents(events, setStats);
    },
    [advanceAfterSeq],
  );

  const fetchEventsPage = useCallback(
    async (afterSeq: number, limit: number) =>
      api.getTaskExecutionEvents(taskId, afterSeq, limit, CONSOLE_EVENT_TYPES),
    [taskId],
  );

  const backfillRemainingEvents = useCallback(async () => {
    if (backfillRunningRef.current) return;
    backfillRunningRef.current = true;
    try {
      let hasMore = true;
      while (hasMore) {
        const page = await fetchEventsPage(afterSeqRef.current, EVENT_PAGE_SIZE);
        if (page.events.length) {
          mergeEvents(page.events);
        }
        advanceAfterSeq(page.next_after_seq);
        hasMore = page.has_more;
        if (!hasMore) break;
        await new Promise<void>((resolve) => {
          requestAnimationFrame(() => resolve());
        });
      }
    } catch (e) {
      console.error('Failed to backfill execution events:', e);
    } finally {
      backfillRunningRef.current = false;
    }
  }, [fetchEventsPage, mergeEvents, advanceAfterSeq]);

  const pollEvents = useCallback(async () => {
    try {
      const eventData = await fetchEventsPage(afterSeqRef.current, EVENT_PAGE_SIZE);
      if (eventData.events.length) {
        mergeEvents(eventData.events);
      }
    } catch (e) {
      console.error('Failed to poll execution events:', e);
    }
  }, [fetchEventsPage, mergeEvents]);

  const refreshTask = useCallback(async () => {
    try {
      const taskData = await api.getTask(taskId);
      setTask(taskData);
    } catch (e) {
      console.error('Failed to refresh task:', e);
    }
  }, [taskId]);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setEventsLoading(true);
      setTask(null);
      setSteps([]);
      setJudgments([]);
      setStats({ requests: 0, judgments: 0, confirmed: 0 });
      timelineRef.current = { steps: [], judgments: [] };
      afterSeqRef.current = 0;
      backfillRunningRef.current = false;

      try {
        const taskData = await api.getTask(taskId);
        if (cancelled) return;
        setTask(taskData);

        const firstPage = await fetchEventsPage(0, INITIAL_EVENT_PAGE);
        if (cancelled) return;
        if (firstPage.events.length) {
          mergeEvents(firstPage.events);
        }
        advanceAfterSeq(firstPage.next_after_seq);
        setEventsLoading(false);

        if (firstPage.has_more) {
          void backfillRemainingEvents();
        }
      } catch (e) {
        console.error('Failed to load execution console:', e);
        if (!cancelled) {
          setEventsLoading(false);
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [taskId, fetchEventsPage, mergeEvents, backfillRemainingEvents, advanceAfterSeq]);

  useEffect(() => {
    if (!task) return;
    const pollMs = task.status === 'RUNNING' ? 2000 : 12000;
    const interval = setInterval(() => {
      void pollEvents();
    }, pollMs);
    return () => clearInterval(interval);
  }, [pollEvents, task?.status]);

  useEffect(() => {
    if (!task) return;
    const taskPollMs = task.status === 'RUNNING' ? 10000 : 15000;
    const interval = setInterval(() => {
      void refreshTask();
    }, taskPollMs);
    return () => clearInterval(interval);
  }, [refreshTask, task?.status]);

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail as {
        task_id?: number;
        seq?: number;
        event_type?: string;
        payload?: Record<string, unknown>;
        stats?: ExecutionStats;
        progress?: number;
        current_stage?: string;
      };
      if (detail?.task_id !== taskId || !detail.seq || detail.seq <= afterSeqRef.current) return;

      const eventType = detail.event_type || 'unknown';
      if (eventType !== 'request_completed' && CONSOLE_EVENT_TYPES.includes(eventType)) {
        mergeEvents([
          {
            id: 0,
            task_id: taskId,
            seq: detail.seq,
            event_type: eventType,
            payload: detail.payload || {},
            created_at: new Date().toISOString(),
          },
        ]);
      }

      const stats = extractStats(detail);
      if (stats) {
        applyStats(stats, setStats);
      }

      if (detail.progress != null || detail.current_stage != null) {
        setTask((prev) =>
          prev
            ? {
                ...prev,
                progress: detail.progress ?? prev.progress,
                current_stage:
                  detail.current_stage != null ? detail.current_stage : prev.current_stage,
              }
            : prev,
        );
      }

      // Advance for every WS event (including skipped request_completed) so polling stays in sync.
      advanceAfterSeq(detail.seq);
    };
    window.addEventListener('aegis:scan-event', handler);
    return () => window.removeEventListener('aegis:scan-event', handler);
  }, [taskId, mergeEvents, advanceAfterSeq]);

  const selectedStep = useMemo(
    () => (steps.length > 0 ? steps[steps.length - 1] : undefined),
    [steps],
  );
  const judgmentsReversed = useMemo(() => [...judgments].reverse(), [judgments]);
  const strategyMeta = task ? getScanStrategyMeta(task.scan_strategy) : null;
  const showContentSkeleton = eventsLoading && steps.length === 0;

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
                  {UI.title}
                  {task ? `${UI.taskPrefix}${task.display_id}` : ''}
                </h2>
                <p className="font-mono text-xs text-[#64748b]">{task?.target_url || UI.loading}</p>
              </div>
              {task?.status === 'RUNNING' && (
                <span className="rounded-md bg-blue-100 px-2 py-0.5 text-[10px] font-bold text-blue-600">
                  {UI.validating}
                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-4 text-xs text-[#64748b]">
              {strategyMeta && (
                <span className="rounded-md bg-orange-50 px-2 py-1 font-semibold text-[#c25b00]">
                  {strategyMeta.label}
                </span>
              )}
              <span>{UI.requests} {stats.requests}</span>
              <span>{UI.judgments} {stats.judgments}</span>
              <span>{UI.confirmed} {stats.confirmed}</span>
              <span>{task?.current_stage || UI.waitingEvents}</span>
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
            title={UI.close}
          >
            <X size={20} />
          </button>
        </div>

        {showContentSkeleton ? (
          <div className="flex flex-1 items-center justify-center text-[#94a3b8]">
            {UI.loadingData}
          </div>
        ) : (
          <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-hidden p-4 lg:grid-cols-12">
            <div className="min-h-0 overflow-auto lg:col-span-4">
              <AttackChainTimeline steps={steps} title={UI.timeline} />
            </div>
            <div className="flex min-h-0 flex-col overflow-auto lg:col-span-5">
              <div className="rounded-2xl border border-[#e2e8f0] bg-white p-4">
                <h3 className="mb-3 text-sm font-bold text-[#2d3343]">{UI.httpDetail}</h3>
                {selectedStep ? (
                  <RequestResponseViewer
                    request={selectedStep.request}
                    response={selectedStep.response}
                    evidence={selectedStep.evidence}
                    payload={selectedStep.payload}
                  />
                ) : (
                  <p className="py-8 text-center text-sm text-[#94a3b8]">{UI.waitingSteps}</p>
                )}
              </div>
            </div>
            <div className="min-h-0 overflow-auto lg:col-span-3">
              <div className="rounded-2xl border border-[#e2e8f0] bg-white p-4">
                <h3 className="mb-3 text-sm font-bold text-[#2d3343]">{UI.vulnJudgment}</h3>
                {judgments.length === 0 ? (
                  <p className="py-6 text-center text-xs text-[#94a3b8]">{UI.noJudgments}</p>
                ) : (
                  <div className="space-y-3">
                    {judgmentsReversed.map((j) => (
                      <div
                        key={j.seq}
                        className={`rounded-xl border p-3 text-xs ${
                          j.final_decision === 'report'
                            ? 'border-emerald-200 bg-emerald-50'
                            : 'border-red-200 bg-red-50/60'
                        }`}
                      >
                        <p className="font-semibold text-[#2d3343]">{j.plugin_id || UI.unknownPlugin}</p>
                        {j.url && (
                          <p className="mt-1 truncate font-mono text-[#64748b]" title={j.url}>
                            {j.url}
                          </p>
                        )}
                        <p className="mt-2">
                          {UI.confidence}{' '}
                          <strong>
                            {j.adjusted_confidence != null
                              ? `${(j.adjusted_confidence * 100).toFixed(1)}%`
                              : '-'}
                          </strong>
                          {` ${UI.sep} `}
                          {UI.evidence} {j.evidence_count ?? 0}
                        </p>
                        <p
                          className={`mt-1 font-bold uppercase ${
                            j.final_decision === 'report' ? 'text-emerald-600' : 'text-red-600'
                          }`}
                        >
                          {j.final_decision === 'report' ? 'REPORT' : 'SUPPRESS'}
                        </p>
                        <p className="mt-1 text-[#64748b]">{j.final_reason || '-'}</p>
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
