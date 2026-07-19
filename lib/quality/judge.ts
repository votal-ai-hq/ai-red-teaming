/**
 * LLM-as-judge for functional-quality metrics that can't be scored
 * deterministically: goal_accuracy, faithfulness, answer_relevancy,
 * topic_adherence, context_recall.
 *
 * Reuses the platform's LLM provider layer (same models/keys as the security
 * judge). Returns a score in [0,1] plus reasoning.
 *
 * See docs/specs/nemo-data-designer-datasets.md — quality scorer.
 */
import { getLlmProvider } from "../llm-provider.js";
import type { Config } from "../types.js";

export const JUDGE_METRICS = new Set([
  "goal_accuracy",
  "faithfulness",
  "answer_relevancy",
  "topic_adherence",
  "context_recall",
]);

const RUBRIC: Record<string, string> = {
  goal_accuracy:
    "Did the RESPONSE accomplish the user's goal as described by the REFERENCE? Score 1.0 if the goal is fully achieved, 0.0 if not attempted or wrong.",
  faithfulness:
    "Is the RESPONSE faithful to and grounded in the REFERENCE (no contradictions, no fabricated claims)? Score 1.0 if fully grounded, 0.0 if it contradicts or hallucinates.",
  answer_relevancy:
    "How relevant and on-point is the RESPONSE to the user's INPUT (regardless of correctness)? Score 1.0 if directly answers, 0.0 if off-topic.",
  topic_adherence:
    "Did the RESPONSE stay on the intended task/topic without drifting? Score 1.0 if fully on-task, 0.0 if it went off the rails.",
  context_recall:
    "How much of the information in the REFERENCE is captured by the RESPONSE? Score 1.0 if all key facts are present, 0.0 if none.",
};

export interface JudgeVerdict {
  score: number;
  reasoning: string;
}

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

/** Extract the first JSON object from a model reply. */
function parseVerdict(text: string): JudgeVerdict {
  const match = text.match(/\{[\s\S]*\}/);
  if (match) {
    try {
      const o = JSON.parse(match[0]) as { score?: unknown; reasoning?: unknown };
      return {
        score: clamp01(Number(o.score)),
        reasoning: String(o.reasoning ?? "").slice(0, 500),
      };
    } catch {
      /* fall through */
    }
  }
  // Last resort: a bare number somewhere in the text.
  const num = text.match(/\b(0?\.\d+|1(?:\.0+)?|0)\b/);
  return {
    score: num ? clamp01(Number(num[0])) : 0,
    reasoning: text.slice(0, 300),
  };
}

export function isJudgeMetric(metric: string): boolean {
  return JUDGE_METRICS.has(metric);
}

/** Score one row with the LLM judge. Throws only on provider failure. */
export async function judgeQuality(
  config: Config,
  args: {
    metric: string;
    input: string;
    reference?: string;
    response: string;
  },
): Promise<JudgeVerdict> {
  const rubric = RUBRIC[args.metric] ?? RUBRIC.goal_accuracy;
  const provider = getLlmProvider(config);
  const model =
    config.attackConfig.judgeModel ?? config.attackConfig.llmModel;

  const prompt = [
    "You are a strict evaluation judge scoring an AI agent's answer for CORRECTNESS.",
    `Metric: ${args.metric}`,
    `Rubric: ${rubric}`,
    "",
    `INPUT (user request):\n${args.input}`,
    "",
    `REFERENCE (ideal answer):\n${args.reference ?? "(none provided)"}`,
    "",
    `RESPONSE (agent's actual answer):\n${args.response || "(empty)"}`,
    "",
    'Reply with ONLY a JSON object: {"score": <0..1 float>, "reasoning": "<one sentence>"}',
  ].join("\n");

  const reply = await provider.chat({
    model,
    messages: [{ role: "user", content: prompt }],
    temperature: 0,
    responseFormat: "json_object",
  });
  return parseVerdict(reply);
}
