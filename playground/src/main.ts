/**
 * @module playground/main
 * @description The page: reads the settings, runs {@link processText} as the
 * text changes, and shows the output, the findings, the vault and a receipt.
 * Every value is put on the page as text, never as HTML.
 */

import { PRESET_REGISTRY, VERSION } from "../../src/index.js";
import type { CompliancePreset } from "../../src/index.js";
import { createReceiptIssuer } from "../../src/audit/index.js";
import { SAMPLE, processText } from "./process.js";
import type { Mode, Outcome, Settings } from "./process.js";

function element<T extends HTMLElement>(id: string, type: new () => T): T {
  const found = document.getElementById(id);
  if (!(found instanceof type)) throw new Error(`The page has no #${id}.`);
  return found;
}

const input = element("input", HTMLTextAreaElement);
const output = element("output", HTMLPreElement);
const presetList = element("presets", HTMLFieldSetElement);
const mode = element("mode", HTMLSelectElement);
const validating = element("validating", HTMLInputElement);
const status = element("status", HTMLParagraphElement);
const findingsBody = element("findings", HTMLTableSectionElement);
const countsList = element("counts", HTMLUListElement);
const vaultSection = element("vault-section", HTMLElement);
const vaultBody = element("vault", HTMLTableSectionElement);
const restored = element("restored", HTMLPreElement);
const receiptButton = element("receipt-button", HTMLButtonElement);
const receiptOutput = element("receipt", HTMLPreElement);
const copyButton = element("copy", HTMLButtonElement);
element("version", HTMLSpanElement).textContent = VERSION;

for (const [name, preset] of Object.entries(PRESET_REGISTRY)) {
  const label = document.createElement("label");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.value = name;
  box.addEventListener("change", schedule);
  label.title = preset.description;
  label.append(box, ` ${name.toUpperCase()}`);
  presetList.append(label);
}

function settings(): Settings {
  const presets = [...presetList.querySelectorAll<HTMLInputElement>("input:checked")].map(
    (box) => box.value as CompliancePreset,
  );
  return {
    presets,
    mode: mode.value as Mode,
    detection: validating.checked ? "precise" : "legacy",
  };
}

function cell(row: HTMLTableRowElement, text: string, className?: string): void {
  const td = row.insertCell();
  td.textContent = text;
  if (className !== undefined) td.className = className;
}

/** The output with every replacement marked. */
function renderOutput(outcome: Outcome): void {
  output.replaceChildren();
  let at = 0;
  for (const finding of outcome.findings) {
    output.append(outcome.text.slice(at, finding.outStart));
    const mark = document.createElement("mark");
    mark.textContent = outcome.text.slice(finding.outStart, finding.outEnd);
    mark.title = `${finding.category} (${finding.confidence.toFixed(2)})`;
    mark.dataset["category"] = finding.category;
    output.append(mark);
    at = finding.outEnd;
  }
  output.append(outcome.text.slice(at));
}

let last: Outcome | undefined;

function render(): void {
  receiptOutput.textContent = "";
  let outcome: Outcome;
  try {
    outcome = processText(input.value, settings(), () => performance.now());
  } catch (error) {
    status.textContent = `Error: ${(error as Error).message}`;
    return;
  }
  last = outcome;
  renderOutput(outcome);

  const total = outcome.findings.length;
  status.textContent =
    total === 0
      ? `No personal data found (${outcome.millis.toFixed(1)} ms).`
      : `${String(total)} value${total === 1 ? "" : "s"} replaced in ${outcome.millis.toFixed(1)} ms.`;

  countsList.replaceChildren(
    ...outcome.counts.map(([category, count]) => {
      const item = document.createElement("li");
      item.textContent = `${category} ${String(count)}`;
      item.dataset["category"] = category;
      return item;
    }),
  );

  findingsBody.replaceChildren();
  for (const finding of outcome.findings) {
    const row = findingsBody.insertRow();
    cell(row, finding.category);
    cell(row, finding.value, "value");
    cell(row, finding.replacement, "value");
    cell(row, finding.confidence.toFixed(2), "number");
  }

  vaultSection.hidden = outcome.vault === undefined;
  vaultBody.replaceChildren();
  for (const [token, value] of outcome.vault ?? []) {
    const row = vaultBody.insertRow();
    cell(row, token, "value");
    cell(row, value, "value");
  }
  restored.textContent = outcome.restored ?? "";
}

let timer: ReturnType<typeof setTimeout> | undefined;

/** Render after the typing pauses, so that a long text does not slow each keystroke. */
function schedule(): void {
  if (timer !== undefined) clearTimeout(timer);
  timer = setTimeout(render, 120);
}

/** A key for this page only: receipts here show the format, they prove nothing elsewhere. */
const receiptKey = Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) =>
  byte.toString(16).padStart(2, "0"),
).join("");

receiptButton.addEventListener("click", () => {
  const outcome = last;
  if (outcome === undefined) return;
  const { presets } = settings();
  createReceiptIssuer({ key: receiptKey, ...(presets.length > 0 ? { presets } : {}) })
    .issue({ text: outcome.text, spans: outcome.findings })
    .then((receipt) => {
      receiptOutput.textContent = JSON.stringify(receipt, null, 2);
    })
    .catch((error: unknown) => {
      receiptOutput.textContent = `Error: ${(error as Error).message}`;
    });
});

copyButton.addEventListener("click", () => {
  navigator.clipboard.writeText(last?.text ?? "").then(
    () => {
      copyButton.textContent = "Copied";
      setTimeout(() => (copyButton.textContent = "Copy output"), 1500);
    },
    () => {
      copyButton.textContent = "Copy failed";
    },
  );
});

input.addEventListener("input", schedule);
mode.addEventListener("change", schedule);
validating.addEventListener("change", schedule);
element("sample", HTMLButtonElement).addEventListener("click", () => {
  input.value = SAMPLE;
  render();
});
element("clear", HTMLButtonElement).addEventListener("click", () => {
  input.value = "";
  render();
  input.focus();
});

input.value = SAMPLE;
render();
