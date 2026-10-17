import { copyFile, mkdir } from 'node:fs/promises';
await mkdir(new URL('../dist/', import.meta.url), { recursive: true });
await copyFile(new URL('../src/plugin.mjs', import.meta.url), new URL('../dist/plugin.mjs', import.meta.url));
console.log('Built dist/plugin.mjs');
