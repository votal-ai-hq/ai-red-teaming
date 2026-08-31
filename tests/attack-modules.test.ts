import { describe, it, expect } from "vitest";

// Import all attack modules
import { authBypassModule } from "../attacks/auth-bypass.js";
import { rbacBypassModule } from "../attacks/rbac-bypass.js";
import { promptInjectionModule } from "../attacks/prompt-injection.js";
import { outputEvasionModule } from "../attacks/output-evasion.js";
import { dataExfiltrationModule } from "../attacks/data-exfiltration.js";
import { rateLimitModule } from "../attacks/rate-limit.js";
import { sensitiveDataModule } from "../attacks/sensitive-data.js";
import { indirectPromptInjectionModule } from "../attacks/indirect-prompt-injection.js";
import { steganographicExfiltrationModule } from "../attacks/steganographic-exfiltration.js";
import { outOfBandExfiltrationModule } from "../attacks/out-of-band-exfiltration.js";
import { trainingDataExtractionModule } from "../attacks/training-data-extraction.js";
import { sideChannelInferenceModule } from "../attacks/side-channel-inference.js";
import { modelExtractionModule } from "../attacks/model-extraction.js";
import { membershipInferenceModule } from "../attacks/membership-inference.js";
import { backdoorTriggerModule } from "../attacks/backdoor-trigger.js";
import { dataPoisoningModule } from "../attacks/data-poisoning.js";
import { gradientLeakageModule } from "../attacks/gradient-leakage.js";
import { modelInversionModule } from "../attacks/model-inversion.js";
import { ragCorpusPoisoningModule } from "../attacks/rag-corpus-poisoning.js";
import { retrievalRankingAttackModule } from "../attacks/retrieval-ranking-attack.js";
import { vectorStoreManipulationModule } from "../attacks/vector-store-manipulation.js";
import { chunkBoundaryInjectionModule } from "../attacks/chunk-boundary-injection.js";
import { embeddingInversionModule } from "../attacks/embedding-inversion.js";
import { structuredOutputInjectionModule } from "../attacks/structured-output-injection.js";
import { generatedCodeRceModule } from "../attacks/generated-code-rce.js";
import { markdownLinkInjectionModule } from "../attacks/markdown-link-injection.js";
import { sycophancyExploitationModule } from "../attacks/sycophancy-exploitation.js";
import { hallucinationInducementModule } from "../attacks/hallucination-inducement.js";
import { formatConfusionAttackModule } from "../attacks/format-confusion-attack.js";
import { modelDosModule } from "../attacks/model-dos.js";
import { tokenFloodingDosModule } from "../attacks/token-flooding-dos.js";
import { infiniteLoopAgentModule } from "../attacks/infinite-loop-agent.js";
import { quotaExhaustionAttackModule } from "../attacks/quota-exhaustion-attack.js";
import { inferenceAttackModule } from "../attacks/inference-attack.js";
import { reIdentificationModule } from "../attacks/re-identification.js";
import { linkageAttackModule } from "../attacks/linkage-attack.js";
import { differentialPrivacyViolationModule } from "../attacks/differential-privacy-violation.js";
import { logicBombConditionalModule } from "../attacks/logic-bomb-conditional.js";
import { agenticLegalCommitmentModule } from "../attacks/agentic-legal-commitment.js";
import { contextualIntegrityViolationModule } from "../attacks/contextual-integrity-violation.js";
import { financialFraudFacilitationModule } from "../attacks/financial-fraud-facilitation.js";
import { gdprErasureBypassModule } from "../attacks/gdpr-erasure-bypass.js";
import { mcpServerCompromiseModule } from "../attacks/mcp-server-compromise.js";
import { pluginManifestSpoofingModule } from "../attacks/plugin-manifest-spoofing.js";
import { sdkDependencyAttackModule } from "../attacks/sdk-dependency-attack.js";
import { fineTuningDataInjectionModule } from "../attacks/fine-tuning-data-injection.js";
import { promptTemplateInjectionModule } from "../attacks/prompt-template-injection.js";
import { systemPromptDisclosureModule } from "../attacks/system-prompt-disclosure.js";
import { toolInventoryDisclosureModule } from "../attacks/tool-inventory-disclosure.js";
import { agentConfigDisclosureModule } from "../attacks/agent-config-disclosure.js";
import { ragSourceDisclosureModule } from "../attacks/rag-source-disclosure.js";
import type { AttackModule, CodebaseAnalysis } from "../lib/types.js";

const ALL_MODULES: AttackModule[] = [
  authBypassModule,
  rbacBypassModule,
  promptInjectionModule,
  outputEvasionModule,
  dataExfiltrationModule,
  rateLimitModule,
  sensitiveDataModule,
  indirectPromptInjectionModule,
  steganographicExfiltrationModule,
  outOfBandExfiltrationModule,
  trainingDataExtractionModule,
  sideChannelInferenceModule,
  modelExtractionModule,
  membershipInferenceModule,
  backdoorTriggerModule,
  dataPoisoningModule,
  gradientLeakageModule,
  modelInversionModule,
  ragCorpusPoisoningModule,
  retrievalRankingAttackModule,
  vectorStoreManipulationModule,
  chunkBoundaryInjectionModule,
  embeddingInversionModule,
  structuredOutputInjectionModule,
  generatedCodeRceModule,
  markdownLinkInjectionModule,
  sycophancyExploitationModule,
  hallucinationInducementModule,
  formatConfusionAttackModule,
  modelDosModule,
  tokenFloodingDosModule,
  infiniteLoopAgentModule,
  quotaExhaustionAttackModule,
  inferenceAttackModule,
  reIdentificationModule,
  linkageAttackModule,
  differentialPrivacyViolationModule,
  logicBombConditionalModule,
  agenticLegalCommitmentModule,
  contextualIntegrityViolationModule,
  financialFraudFacilitationModule,
  gdprErasureBypassModule,
  mcpServerCompromiseModule,
  pluginManifestSpoofingModule,
  sdkDependencyAttackModule,
  fineTuningDataInjectionModule,
  promptTemplateInjectionModule,
  systemPromptDisclosureModule,
  toolInventoryDisclosureModule,
  agentConfigDisclosureModule,
  ragSourceDisclosureModule,
];

const mockAnalysis: CodebaseAnalysis = {
  tools: [
    {
      name: "read_file",
      description: "Read a file",
      parameters: "path: string",
    },
  ],
  roles: [{ name: "admin", permissions: ["*"] }],
  guardrailPatterns: [],
  sensitiveData: [{ type: "api_key", location: ".env", example: "sk-..." }],
  authMechanisms: ["jwt"],
  knownWeaknesses: [],
  systemPromptHints: [],
};

describe("Attack modules", () => {
  for (const mod of ALL_MODULES) {
    describe(mod.category, () => {
      it("has a valid category string", () => {
        expect(mod.category).toBeTruthy();
        expect(typeof mod.category).toBe("string");
      });

      it("returns at least 1 seed attack", () => {
        const seeds = mod.getSeedAttacks();
        expect(seeds.length).toBeGreaterThanOrEqual(1);
      });

      it("seed attacks have required fields", () => {
        const seeds = mod.getSeedAttacks();
        for (const attack of seeds) {
          expect(attack.id).toBeTruthy();
          expect(attack.category).toBe(mod.category);
          expect(attack.name).toBeTruthy();
          expect(attack.description).toBeTruthy();
          expect([
            "jwt",
            "api_key",
            "body_role",
            "none",
            "forged_jwt",
          ]).toContain(attack.authMethod);
          expect(attack.role).toBeTruthy();
          expect(attack.payload).toBeDefined();
          expect(
            attack.payload.message || attack.payload._rapidFire,
          ).toBeTruthy();
          expect(attack.expectation).toBeTruthy();
          expect(["critical", "high", "medium", "low"]).toContain(
            attack.severity,
          );
          expect(attack.isLlmGenerated).toBe(false);
        }
      });

      it("seed attacks have unique IDs", () => {
        const seeds = mod.getSeedAttacks();
        const ids = seeds.map((a) => a.id);
        expect(new Set(ids).size).toBe(ids.length);
      });

      it("returns a non-empty generation prompt", () => {
        const prompt = mod.getGenerationPrompt(mockAnalysis);
        expect(prompt).toBeTruthy();
        expect(prompt.length).toBeGreaterThan(50);
      });
    });
  }

  it("all modules have unique categories", () => {
    const categories = ALL_MODULES.map((m) => m.category);
    expect(new Set(categories).size).toBe(categories.length);
  });

  it("all seed attack IDs are globally unique", () => {
    const allIds = ALL_MODULES.flatMap((m) =>
      m.getSeedAttacks().map((a) => a.id),
    );
    expect(new Set(allIds).size).toBe(allIds.length);
  });
});
