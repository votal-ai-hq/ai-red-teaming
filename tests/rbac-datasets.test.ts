import { describe, it, expect } from "vitest";
import { checkPermission } from "../lib/rbac.js";

describe("RBAC for dataset/eval endpoints (regression: login-loop 403)", () => {
  it("allows viewer+admin to GET datasets and eval-runs", () => {
    expect(checkPermission("GET", "/api/datasets", "viewer")).toBe(true);
    expect(checkPermission("GET", "/api/datasets", "admin")).toBe(true);
    expect(checkPermission("GET", "/api/eval-runs", "viewer")).toBe(true);
  });
  it("allows viewer+admin to GET dataset rows", () => {
    expect(checkPermission("GET", "/api/datasets/rows", "viewer")).toBe(true);
    expect(checkPermission("GET", "/api/datasets/rows", "admin")).toBe(true);
  });
  it("allows viewer+admin to GET generation providers + engines", () => {
    expect(checkPermission("GET", "/api/datasets/providers", "viewer")).toBe(true);
    expect(checkPermission("GET", "/api/datasets/providers", "admin")).toBe(true);
    expect(checkPermission("GET", "/api/datasets/engines", "viewer")).toBe(true);
    expect(checkPermission("GET", "/api/datasets/engines", "admin")).toBe(true);
    expect(checkPermission("GET", "/api/datasets/taxonomy", "viewer")).toBe(true);
    expect(checkPermission("GET", "/api/datasets/taxonomy", "admin")).toBe(true);
  });
  it("allows viewer+admin to list profiles but restricts save/import to admin", () => {
    expect(checkPermission("GET", "/api/datasets/profiles", "viewer")).toBe(true);
    expect(checkPermission("GET", "/api/datasets/profiles", "admin")).toBe(true);
    expect(checkPermission("POST", "/api/datasets/profiles", "viewer")).toBe(false);
    expect(checkPermission("POST", "/api/datasets/profiles", "admin")).toBe(true);
    expect(checkPermission("POST", "/api/datasets/profiles/import", "viewer")).toBe(false);
    expect(checkPermission("POST", "/api/datasets/profiles/import", "admin")).toBe(true);
  });
  it("restricts dataset generation to admin", () => {
    expect(checkPermission("POST", "/api/datasets/generate", "admin")).toBe(true);
    expect(checkPermission("POST", "/api/datasets/generate", "viewer")).toBe(false);
  });
  it("GET /api/datasets pattern does not swallow the generate path", () => {
    // ensure the two rules stay distinct
    expect(checkPermission("GET", "/api/datasets/generate", "viewer")).toBe(false);
  });
});
