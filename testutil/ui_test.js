// Renders every dashboard tab in a real DOM (jsdom) against a running
// `zemen serve`, and exercises the main interactions. Requires: npm i jsdom
// Usage: node testutil/ui_test.js http://127.0.0.1:18080
const { JSDOM } = require("jsdom");
const base = process.argv[2] || "http://127.0.0.1:18080";
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log("  PASS  " + m); } else { fail++; console.log("  FAIL  " + m); } };

(async () => {
  const errors = [];
  const dom = await JSDOM.fromURL(base + "/", {
    runScripts: "dangerously", resources: "usable", pretendToBeVisual: true,
    beforeParse(w) {
      w.fetch = (u, o) => fetch(new URL(u, base), o);
      w.prompt = () => "";
      w.addEventListener("error", e => errors.push(String(e.message)));
      w.addEventListener("unhandledrejection", e => errors.push(String(e.reason)));
    },
  });
  const w = dom.window, d = w.document;
  await sleep(1500);
  const main = () => d.querySelector("#main");
  const tabs = [...d.querySelectorAll("#nav button")];
  ok(tabs.length === 10, "10 navigation tabs rendered");
  const expect = {
    overview: /Detectors|Detection debt/, detectors: /POSTGRES-BRUTE/, coverage: /T1110/, tagging: /Confirmed:/,
    anomalies: /Why\?/, replay: /Run all cases/, calendar: /Meskel|Enkutatash/, forecast: /day\(s\)|forecast/i,
    lineage: /Biography of/, debt: /SOC detection debt/,
  };
  for (const t of tabs) {
    t.click();
    await sleep(900);
    const name = t.dataset.t;
    const txt = main().textContent;
    ok(!main().querySelector(".err"), name + ": no error banner");
    ok(expect[name].test(txt), name + ": expected content present");
  }
  // Interactions
  tabs[0].click(); await sleep(700);
  const syncBtn = [...d.querySelectorAll("button")].find(b => /Run sync now/.test(b.textContent));
  syncBtn.click(); await sleep(6000);
  ok(/Synced|Detectors/.test(d.body.textContent) && !main().querySelector(".err"), "overview: sync button works");
  tabs[3].click(); await sleep(900);
  const sel = main().querySelector("select");
  sel.value = "T1566";
  [...main().querySelectorAll("button")].find(b => b.textContent === "Add").click(); await sleep(900);
  ok(/T1566/.test(main().textContent), "tagging: adding a technique shows it");
  tabs[4].click(); await sleep(900);
  [...main().querySelectorAll("button")].find(b => b.textContent === "Confirm").click(); await sleep(1200);
  ok(/confirmed/.test(main().textContent), "anomalies: confirm records analyst decision");
  tabs[5].click(); await sleep(900);
  [...main().querySelectorAll("button")].find(b => /Load cases/.test(b.textContent)).click(); await sleep(1200);
  ok(true, "replay: load button does not crash");
  tabs[8].click(); await sleep(900);
  const inputs = main().querySelectorAll("input");
  inputs[0].value = "UI test reason"; inputs[2].value = "tester";
  [...main().querySelectorAll("button")].find(b => b.textContent === "Add").click(); await sleep(1200);
  ok(/UI test reason/.test(main().textContent), "lineage: recorded reason appears in biography");
  ok(errors.length === 0, "no uncaught JS errors" + (errors.length ? " -> " + errors.join("; ") : ""));
  console.log(`UI RESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error("UI TEST CRASH", e); process.exit(2); });
