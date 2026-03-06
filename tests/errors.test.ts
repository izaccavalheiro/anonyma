import { describe, it, expect } from "vitest";
import {
  AnonymaError,
  ValidationError,
  UnsupportedStrategyError,
  UnknownCategoryError,
  CryptoNotAvailableError,
  EncryptionError,
  PresetNotFoundError,
  AllowlistMatchError,
  BatchProcessingError,
} from "../src/errors.js";

describe("AnonymaError", () => {
  it("has a code property", () => {
    const err = new AnonymaError("test", "TEST_CODE");
    expect(err.code).toBe("TEST_CODE");
    expect(err.message).toBe("test");
  });

  it("is an instance of Error", () => {
    expect(new AnonymaError("m", "c")).toBeInstanceOf(Error);
  });

  it("has the correct name", () => {
    expect(new AnonymaError("m", "c").name).toBe("AnonymaError");
  });
});

describe("ValidationError", () => {
  it("contains field and reason in message", () => {
    const err = new ValidationError("myField", "is required");
    expect(err.message).toContain("myField");
    expect(err.message).toContain("is required");
    expect(err.field).toBe("myField");
  });

  it("has code VALIDATION_ERROR", () => {
    expect(new ValidationError("f", "r").code).toBe("VALIDATION_ERROR");
  });

  it("is an instance of AnonymaError", () => {
    expect(new ValidationError("f", "r")).toBeInstanceOf(AnonymaError);
  });
});

describe("UnsupportedStrategyError", () => {
  it("contains the strategy name in message", () => {
    const err = new UnsupportedStrategyError("foobar");
    expect(err.message).toContain("foobar");
    expect(err.strategy).toBe("foobar");
  });

  it("has code UNSUPPORTED_STRATEGY", () => {
    expect(new UnsupportedStrategyError("x").code).toBe("UNSUPPORTED_STRATEGY");
  });
});

describe("UnknownCategoryError", () => {
  it("contains the category name in message", () => {
    const err = new UnknownCategoryError("passport");
    expect(err.message).toContain("passport");
    expect(err.category).toBe("passport");
  });

  it("has code UNKNOWN_CATEGORY", () => {
    expect(new UnknownCategoryError("x").code).toBe("UNKNOWN_CATEGORY");
  });
});

describe("CryptoNotAvailableError", () => {
  it("has code CRYPTO_NOT_AVAILABLE", () => {
    expect(new CryptoNotAvailableError().code).toBe("CRYPTO_NOT_AVAILABLE");
  });

  it("is an instance of AnonymaError", () => {
    expect(new CryptoNotAvailableError()).toBeInstanceOf(AnonymaError);
  });
});

describe("EncryptionError — branch coverage", () => {
  it("omits cause clause in message when no cause is provided", () => {
    const e = new EncryptionError("encrypt");
    expect(e.message).toBe(`Encryption operation "encrypt" failed.`);
    // cause !== undefined → false branch: .cause should not be set
    expect((e as { cause?: unknown }).cause).toBeUndefined();
  });

  it("omits cause clause in message when cause is not an Error instance", () => {
    const e = new EncryptionError("decrypt", "plain string cause");
    // cause instanceof Error → false branch: no Cause: ... appended
    expect(e.message).toBe(`Encryption operation "decrypt" failed.`);
    // cause !== undefined → true branch: .cause should be set
    expect((e as { cause?: unknown }).cause).toBe("plain string cause");
  });
});

describe("PresetNotFoundError — additional coverage", () => {
  it("has code PRESET_NOT_FOUND", () => {
    expect(new PresetNotFoundError("x").code).toBe("PRESET_NOT_FOUND");
  });
});

describe("AllowlistMatchError — additional coverage", () => {
  it("has code ALLOWLIST_MATCH_ERROR", () => {
    expect(new AllowlistMatchError("field", "must be non-empty").code).toBe("ALLOWLIST_MATCH_ERROR");
  });

  it("includes both field and reason in message", () => {
    const e = new AllowlistMatchError("email", "must be non-empty");
    expect(e.message).toContain("email");
    expect(e.message).toContain("must be non-empty");
  });
});

describe("BatchProcessingError — additional coverage", () => {
  it("has code BATCH_PROCESSING_ERROR", () => {
    expect(new BatchProcessingError(5, 3, 8).code).toBe("BATCH_PROCESSING_ERROR");
  });

  it("includes counts in message", () => {
    const e = new BatchProcessingError(5, 3, 8);
    expect(e.message).toContain("5");
    expect(e.message).toContain("3");
    expect(e.message).toContain("8");
  });
});
