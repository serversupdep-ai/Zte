const { keygen, keygenDellLegacy, keygenCf1b, keygenCf1bAltFnA, keygenE7A8 } = require("./keygen-core.js");
const vectors = require("./vectors.json");
let pass = 0, fail = 0;
for (const v of vectors) {
  let got;
  try {
    if (v.cf1b) got = [keygenCf1b(v.tag)];
    else if (v.cf1b_alt) got = [keygenCf1bAltFnA(v.tag)];
    else got = keygenDellLegacy(v.tag, v.suffix);
  } catch (e) { got = "ERR:" + e.message; }
  const ok = JSON.stringify(got) === JSON.stringify(v.expect);
  if (ok) pass++; else { fail++; console.log(`FAIL ${v.tag}-${v.suffix}: js=${JSON.stringify(got)} py=${JSON.stringify(v.expect)}`); }
}
console.log(`\n${pass}/${pass + fail} vectors ${fail === 0 ? "ALL PASS — port is byte-exact" : "FAILED"}`);
process.exit(fail === 0 ? 0 : 1);
