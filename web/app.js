"use strict";

const form = document.querySelector("#analyze");
const statusLine = document.querySelector("#status");
const filesInput = document.querySelector("#files");
const fileList = document.querySelector("#file-list");
const dropZone = document.querySelector("#drop-zone");
const mode = document.querySelector("#seconds");
const reportRoot = document.querySelector("#report");
const submit = document.querySelector("#submit");
const token = document.querySelector('meta[name="local-token"]').content;
const attached = [];
const sizeLimit = 64 * 1024 * 1024;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function setStatus(text, error = false) {
  statusLine.textContent = text;
  statusLine.classList.toggle("error", error);
}

function updateFileList() {
  fileList.hidden = attached.length === 0;
  fileList.replaceChildren();
  attached.forEach((file, index) => {
    const row = element("li");
    row.append(element("span", file.name));
    const button = element("button", "Odebrat");
    button.type = "button";
    button.setAttribute("aria-label", "Odebrat " + file.name);
    button.addEventListener("click", () => {
      attached.splice(index, 1);
      updateFileList();
    });
    row.append(button);
    fileList.append(row);
  });
}

function addFiles(files) {
  if (submit.disabled) return;
  const items = [...files];
  const total = [...attached, ...items].reduce((size, file) => size + file.size, 0);
  if (attached.length + items.length > 6 || total > sizeLimit) {
    setStatus("Přilož až 6 souborů o celkové velikosti do 64 MiB.", true);
    return;
  }
  attached.push(...items);
  updateFileList();
  setStatus("");
}

filesInput.addEventListener("change", () => {
  addFiles(filesInput.files);
  filesInput.value = "";
});
dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("active");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("active"));
dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("active");
  addFiles(event.dataTransfer.files);
});
mode.addEventListener("change", () => {
  document.querySelector("#mode-hint").textContent = mode.value === "0"
    ? "Zachytí síť při načtení a dalších 5 sekund."
    : "Otevře nové okno Chromia. Proveď v něm akci během zvoleného limitu.";
});

function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      const comma = reader.result.indexOf(",");
      resolve({ name: file.name, data: reader.result.slice(comma + 1) });
    });
    reader.addEventListener("error", () => reject(new Error("Soubor se nepodařilo načíst.")));
    reader.readAsDataURL(file);
  });
}

function download(content, name, type) {
  const address = URL.createObjectURL(new Blob([content], { type }));
  const link = element("a");
  link.href = address;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(address), 1000);
}

function reportButton(label, callback) {
  const button = element("button", label);
  button.type = "button";
  button.addEventListener("click", callback);
  return button;
}

function entryList(items) {
  const list = element("ul", undefined, "entries");
  for (const item of items) {
    const row = element("li");
    if (item.label) row.append(element("strong", item.label + " · "));
    row.append(document.createTextNode(item.detail));
    if (item.evidence?.length) row.append(element("span", item.evidence.join(" · "), "evidence"));
    list.append(row);
  }
  return list;
}

function detailsPart(title, items, open = false) {
  const root = element("details", undefined, "panel report-part");
  root.open = open;
  root.append(element("summary", title + " · " + items.length), entryList(items));
  return root;
}

function endpointTable(rows) {
  const part = element("section", undefined, "panel report-part");
  const head = element("div", undefined, "section-head");
  head.append(element("h3", "Pozorovaná síťová volání"), element("span", rows.length + " skupin podle metody a URL", "count"));
  part.append(head);
  if (!rows.length) {
    part.append(element("p", "Podklady neobsahují zachycené API volání.", "field-note"));
    return part;
  }
  const table = element("table");
  const heading = table.createTHead().insertRow();
  for (const label of ["Metoda a URL", "HTTP", "Počet"]) {
    const header = element("th", label);
    header.scope = "col";
    heading.append(header);
  }
  const body = table.createTBody();
  for (const item of rows) {
    const row = body.insertRow();
    const details = element("details");
    const summary = element("summary");
    summary.append(element("code", item.method), document.createTextNode(" " + item.url));
    details.append(summary);
    const values = element("div", undefined, "endpoint-data");
    const fields = [
      ["Přenos", item.transports], ["Operace", item.operations], ["Parametry URL", item.query_fields],
      ["Pole požadavku", item.request_fields], ["Pole odpovědi", item.response_fields],
      ["Síťová hlášení", item.failures], ["Důkaz", item.evidence],
    ];
    for (const [label, content] of fields) {
      if (content.length) {
        const line = element("p");
        line.append(element("strong", label + " · "), document.createTextNode(content.join(", ")));
        values.append(line);
      }
    }
    details.append(values);
    row.insertCell().append(details);
    const statuses = row.insertCell();
    statuses.textContent = item.statuses.join(", ") || "—";
    if (item.statuses.some((code) => [401, 402, 403, 429].includes(code))) statuses.className = "access-status";
    row.insertCell().textContent = item.count;
  }
  part.append(table);
  return part;
}

function render(result) {
  const data = result.report;
  const head = element("header", undefined, "panel report-head");
  head.append(element("h2", "Report"));
  const downloads = element("div", undefined, "report-actions");
  downloads.append(
    reportButton("Markdown", () => download(result.markdown, "report.md", "text/markdown;charset=utf-8")),
    reportButton("JSON", () => download(JSON.stringify(data, null, 2), "report.json", "application/json")),
  );
  if (result.archive) {
    downloads.append(reportButton("ZIP s kódem", () => {
      const content = Uint8Array.fromBase64 ? Uint8Array.fromBase64(result.archive)
        : Uint8Array.from(atob(result.archive), (char) => char.charCodeAt(0));
      download(content, "rozbor-s-kodem.zip", "application/zip");
    }));
  }
  head.append(downloads);
  reportRoot.replaceChildren(head);
  reportRoot.append(detailsPart("Pokrytí", data.sources.map((source) => ({
    label: source.id + " · " + source.kind,
    detail: source.label,
    evidence: source.details,
  })), true), endpointTable(data.observed));
  for (const [key, title] of [
    ["access", "Stavy přístupu a účtování"], ["features", "Stopy funkcí"],
    ["technologies", "Technologické stopy"], ["references", "Odkazy v kódu a dalších vstupech"],
  ]) {
    if (data[key].length) reportRoot.append(detailsPart(title, data[key], key === "access"));
  }
  if (data.client_files.length) reportRoot.append(detailsPart("Klientské soubory", data.client_files.map((file) => ({
    detail: file.name + " · " + file.bytes.toLocaleString("cs-CZ") + " B",
    evidence: [file.evidence, file.archive_path].filter(Boolean),
  }))));
  if (data.ocr.length) reportRoot.append(detailsPart("Text ze screenshotů", data.ocr.map((line) => ({
    detail: line.text, evidence: [line.evidence],
  }))));
  if (data.notes.length) reportRoot.append(detailsPart("Pokrytí a limity", data.notes.map((detail) => ({ detail }))));
  reportRoot.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (submit.disabled) return;
  const url = document.querySelector("#url").value.trim();
  const text = document.querySelector("#notes").value;
  const seconds = Number(mode.value);
  if (!url && !text.trim() && !attached.length) {
    setStatus("Přidej URL, text nebo soubor.", true);
    return;
  }
  const archive = document.querySelector("#archive").checked;
  submit.disabled = true;
  reportRoot.hidden = true;
  setStatus(seconds ? "Po otevření přepni do nového okna Chromia." : "Zpracovávám podklady…");
  try {
    const files = await Promise.all(attached.map(readFile));
    const response = await fetch("/analyze", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Local-Token": token },
      body: JSON.stringify({ url, text, seconds, archive, files }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    render(result);
    setStatus("Analýza hotová.");
    reportRoot.scrollIntoView({ block: "start" });
  } catch (error) {
    setStatus(error.message || "Analýzu se nepodařilo dokončit.", true);
  } finally {
    submit.disabled = false;
  }
});
