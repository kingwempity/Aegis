/**
 * 扫描任务状态管理
 * 使用 Zustand 管理全局状态
 */
import { create } from 'zustand';

interface ScanStore {
  activeTasks: string[];
  addTaskId: (id: string) => void;
  removeTaskId: (id: string) => void;
  clearActiveTasks: () => void;
}

export const useScanStore = create<ScanStore>((set) => ({
  activeTasks: [],
  addTaskId: (id: string) =>
    set((state) => ({
      activeTasks: state.activeTasks.includes(id)
        ? state.activeTasks
        : [...state.activeTasks, id],
    })),
  removeTaskId: (id: string) =>
    set((state) => ({
      activeTasks: state.activeTasks.filter((taskId) => taskId !== id),
    })),
  clearActiveTasks: () => set({ activeTasks: [] }),
}));
