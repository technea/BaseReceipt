import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const distDir = new URL('../dist/', import.meta.url);
const srcFile = new URL('../src/plugin.mjs', import.meta.url);
const destPluginMjs = new URL('../dist/plugin.mjs', import.meta.url);
const destIndexMjs = new URL('../dist/index.mjs', import.meta.url);
const destIndexJs = new URL('../dist/index.js', import.meta.url);
const destPluginJs = new URL('../dist/plugin.js', import.meta.url);
const destIndexCjs = new URL('../dist/index.cjs', import.meta.url);
const destPluginCjs = new URL('../dist/plugin.cjs', import.meta.url);
const destDts = new URL('../dist/index.d.ts', import.meta.url);
const rootIndexJs = new URL('../index.js', import.meta.url);
const rootIndexCjs = new URL('../index.cjs', import.meta.url);

await mkdir(distDir, { recursive: true });

// 1. Read source
const srcContent = await readFile(srcFile, 'utf8');

// Verify that the source is 100% self-contained with no external npm imports
const importMatches = [...srcContent.matchAll(/^(?:import|export)\s+.*?\s+from\s+['"]([^'"]+)['"]/gm)].map(m => m[1]);
const unbundledImports = importMatches.filter(spec => !spec.startsWith('.') && !spec.startsWith('/') && !spec.startsWith('node:'));

if (unbundledImports.length > 0) {
  console.error('Build verification failed! Found unbundled external dependencies:', unbundledImports);
  process.exit(1);
}

// 2. Write ESM bundles (plugin.mjs, index.mjs, index.js, plugin.js)
const esmShebangContent = srcContent.startsWith('#!') ? srcContent : `#!/usr/bin/env node\n${srcContent}`;
await writeFile(destPluginMjs, esmShebangContent, 'utf8');
await writeFile(destIndexMjs, esmShebangContent, 'utf8');
await writeFile(destIndexJs, esmShebangContent, 'utf8');
await writeFile(destPluginJs, esmShebangContent, 'utf8');

// 3. Generate CommonJS bundles (index.cjs, plugin.cjs)
function toCommonJS(esmCode) {
  let cjs = esmCode
    .replace(/^export\s+async\s+function\s+([a-zA-Z0-9_$]+)/gm, 'async function $1')
    .replace(/^export\s+function\s+([a-zA-Z0-9_$]+)/gm, 'function $1')
    .replace(/^export\s+const\s+([a-zA-Z0-9_$]+)/gm, 'const $1')
    .replace(/^export\s+default\s+([a-zA-Z0-9_$]+);?/gm, '');

  cjs = `#!/usr/bin/env node\n/**\n * PayGuard PayBox Plugin - Standalone CJS Bundle\n */\n` + cjs;
  cjs += `\n
const cjsExport = Object.assign({}, plugin, {
  default: plugin,
  plugin: plugin,
  tools: tools,
  payGuardTool: payGuardTool,
  payGuardUrlSentinelTool: payGuardUrlSentinelTool,
  payGuardThreatReportTool: payGuardThreatReportTool,
  evaluatePaymentIntent: evaluatePaymentIntent,
  analyzeUrlSecurity: analyzeUrlSecurity,
  prepareThreatReport: prepareThreatReport,
  startMcpServer: startMcpServer
});
module.exports = cjsExport;
`;
  return cjs;
}

const cjsContent = toCommonJS(srcContent);
await writeFile(destIndexCjs, cjsContent, 'utf8');
await writeFile(destPluginCjs, cjsContent, 'utf8');

// 4. Generate TypeScript declaration
const dtsContent = `export interface PayGuardPlugin {
  id: string;
  name: string;
  version: string;
  category: string;
  protocol: string;
  description: string;
  tools: readonly any[];
  invokeTool(name: string, input: any): Promise<any> | any;
  execute(name: string, input: any): Promise<any> | any;
  run(name: string, input: any): Promise<any> | any;
}
export declare const plugin: PayGuardPlugin;
export default plugin;
export declare const tools: readonly any[];
export declare const payGuardTool: any;
export declare const payGuardUrlSentinelTool: any;
export declare const payGuardThreatReportTool: any;
export declare function evaluatePaymentIntent(input: any): any;
export declare function analyzeUrlSecurity(input: any, options?: any): Promise<any>;
export declare function prepareThreatReport(input: any, options?: any): Promise<any>;
export declare function startMcpServer(targetPlugin?: any): void;
`;
await writeFile(destDts, dtsContent, 'utf8');

// 5. Generate root forwarders
await writeFile(rootIndexJs, `#!/usr/bin/env node\nexport * from "./dist/index.mjs";\nexport { default } from "./dist/index.mjs";\n`, 'utf8');
await writeFile(rootIndexCjs, `#!/usr/bin/env node\nmodule.exports = require("./dist/index.cjs");\n`, 'utf8');

// 6. Dynamic-import smoke test
try {
  const modEsm = await import(destPluginMjs.href);
  if (!modEsm.default || !Array.isArray(modEsm.default.tools)) {
    throw new Error("ESM default export is missing or does not contain a tools array.");
  }
  console.log(`Verified dist/plugin.mjs (${modEsm.default.tools.length} tools exposed).`);
} catch (err) {
  console.error('Dynamic import verification failed on dist/plugin.mjs:', err);
  process.exit(1);
}

console.log('Build completed successfully: bundled ESM, CJS, DTS, and stdio MCP server.');
