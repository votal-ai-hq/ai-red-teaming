import { create } from "zustand";
import type { RiskAnalysisResult } from "@/api/types";

interface RiskState {
  // The report the Risk page is focused on. Persisted so returning to the page
  // reopens the same report instead of resetting to the first one.
  selectedFile: string;
  // Generated AI risk analyses, keyed by report filename. Kept in the store so a
  // completed analysis survives navigating away from the Risk page and back
  // within the same session — no need to regenerate it.
  analyses: Record<string, RiskAnalysisResult[]>;

  setSelectedFile: (file: string) => void;
  setAnalysis: (file: string, results: RiskAnalysisResult[]) => void;
}

export const useRiskStore = create<RiskState>((set) => ({
  selectedFile: "",
  analyses: {},

  setSelectedFile: (selectedFile) => set({ selectedFile }),
  setAnalysis: (file, results) =>
    set((state) => ({ analyses: { ...state.analyses, [file]: results } })),
}));
