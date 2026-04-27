import { describe, it, expect } from "vitest";
import { filterPii } from "./index.js";

const SALT = "test-salt";

describe("redact mode", () => {
  it("redacts email in string", () => {
    expect(filterPii("contact me at user@example.com please", { mode: "redact" }))
      .toBe("contact me at [PRIVATE_EMAIL] please");
  });

  it("redacts email field by name", () => {
    const result = filterPii({ email: "user@example.com", name: "John" }, { mode: "redact" });
    expect(result).toEqual({ email: "[REDACTED]", name: "[REDACTED]" });
  });

  it("redacts CPF", () => {
    expect(filterPii("cpf: 123.456.789-09", { mode: "redact" }))
      .toContain("[ACCOUNT_NUMBER]");
  });

  it("redacts nested objects", () => {
    const result = filterPii({ user: { email: "a@b.com", age: 30 } }, { mode: "redact" });
    expect((result as any).user.email).toBe("[REDACTED]");
    expect((result as any).user.age).toBe(30);
  });

  it("redacts arrays", () => {
    const result = filterPii({ emails: ["a@b.com", "c@d.com"] }, { mode: "redact" });
    expect((result as any).emails[0]).toContain("[PRIVATE_EMAIL]");
  });
});

describe("pseudonymize mode", () => {
  it("produces deterministic hash", () => {
    const r1 = filterPii("user@example.com", { mode: "pseudonymize", salt: SALT });
    const r2 = filterPii("user@example.com", { mode: "pseudonymize", salt: SALT });
    expect(r1).toBe(r2);
  });

  it("different salts produce different hashes", () => {
    const r1 = filterPii({ email: "user@example.com" }, { mode: "pseudonymize", salt: "salt1" });
    const r2 = filterPii({ email: "user@example.com" }, { mode: "pseudonymize", salt: "salt2" });
    expect((r1 as any).email).not.toBe((r2 as any).email);
  });

  it("hash is not the raw value", () => {
    const result = filterPii({ email: "user@example.com" }, { mode: "pseudonymize", salt: SALT });
    expect((result as any).email).not.toContain("user@example.com");
  });
});
