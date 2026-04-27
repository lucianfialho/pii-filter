import { describe, it, expect } from "vitest";
import { filterPii, scanSchema } from "./index.js";

const SALT = "test-salt";

describe("redact mode", () => {
  it("redacts email in string", () => {
    expect(filterPii("contact me at user@example.com please", { mode: "redact" }))
      .toBe("contact me at [PRIVATE_EMAIL] please");
  });

  it("redacts email field by name", () => {
    const result = filterPii({ email: "user@example.com", age: 30 }, { mode: "redact" });
    expect(result).toEqual({ email: "[REDACTED]", age: 30 });
  });

  it("redacts CPF", () => {
    expect(filterPii("cpf: 123.456.789-09", { mode: "redact" })).toContain("[ACCOUNT_NUMBER]");
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

describe("knownPiiFields from scanSchema", () => {
  it("filters known field without regex scan", () => {
    const result = filterPii(
      { customer: { contact: "user@example.com", age: 30 } },
      { mode: "redact", knownPiiFields: ["customer.contact"] }
    );
    expect((result as any).customer.contact).toBe("[REDACTED]");
    expect((result as any).customer.age).toBe(30);
  });

  it("scanSchema detects email by field name", () => {
    const schema = {
      properties: {
        email: { type: "string" },
        age: { type: "integer" },
      },
    };
    expect(scanSchema(schema)).toContain("email");
    expect(scanSchema(schema)).not.toContain("age");
  });

  it("scanSchema detects by format", () => {
    const schema = {
      properties: {
        contact: { type: "string", format: "email" },
      },
    };
    expect(scanSchema(schema)).toContain("contact");
  });

  it("scanSchema detects nested paths", () => {
    const schema = {
      properties: {
        user: {
          properties: {
            email: { type: "string" },
          },
        },
      },
    };
    expect(scanSchema(schema)).toContain("user.email");
  });

  it("combined: scanSchema + filterPii", () => {
    const schema = { properties: { customer: { properties: { email: { type: "string" } } } } };
    const piiFields = scanSchema(schema);
    const result = filterPii(
      { customer: { email: "user@example.com", id: "123" } },
      { mode: "pseudonymize", salt: SALT, knownPiiFields: piiFields }
    );
    expect((result as any).customer.email).not.toContain("user@example.com");
    expect((result as any).customer.id).toBe("123");
  });
});
