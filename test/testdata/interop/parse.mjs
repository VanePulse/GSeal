// Prints VaneSecret's parse of each given ini file as JSON (for the parser
// interop test). Usage: node parse.mjs <VaneSecret src dir> <file>...
const [src, ...files] = process.argv.slice(2);
process.env.WITH_SECRETS_ROOT ??= '/nonexistent';
const { parseIni } = await import(`${src}/core.mjs`);
const { readFileSync } = await import('node:fs');
const out = {};
for (const f of files) {
  const p = parseIni(readFileSync(f, 'utf8'));
  const raw = Object.keys(p.raw).map(s => [s, Object.entries(p.raw[s])]);
  out[f] = { raw, desc: p.desc, secDesc: Object.keys(p.sections).map(s => [s, p.secDesc[s]]) };
}
process.stdout.write(JSON.stringify(out));
