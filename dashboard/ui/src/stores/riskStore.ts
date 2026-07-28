import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { RiskAnalysisResult } from "@/api/types";

interface RiskState {
  // The report the Risk page is focused on. Persisted so returning to the page
  // reopens the same report instead of resetting to the first one.
  selectedFile: string;
  // Generated AI risk analyses, keyed by report filename. Kept in the store so a
  // completed analysis survives navigating away from the Risk page and back, and
  // — because it's persisted to localStorage — a full page reload or a new tab
  // too. Regenerating costs LLM tokens, so we never throw a finished analysis away.
  analyses: Record<string, RiskAnalysisResult[]>;

  setSelectedFile: (file: string) => void;
  setAnalysis: (file: string, results: RiskAnalysisResult[]) => void;
}

export const useRiskStore = create<RiskState>()(
  persist(
    (set) => ({
      selectedFile: "",
      analyses: {},

      setSelectedFile: (selectedFile) => set({ selectedFile }),
      setAnalysis: (file, results) =>
        set((state) => ({ analyses: { ...state.analyses, [file]: results } })),
    }),
    {
      name: "risk-analysis-cache",
      // Only the data needs to survive; the action functions are recreated on
      // every load and must not be serialized.
      partialize: (state) => ({
        selectedFile: state.selectedFile,
        analyses: state.analyses,
      }),
    },
  ),
);
