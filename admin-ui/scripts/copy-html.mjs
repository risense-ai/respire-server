import { copyFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, '..', 'dist', 'index.html');
const dest = resolve(here, '..', '..', 'service', 'src', 'http', 'admin.html');
if (!existsSync(dirname(dest))) {
  console.log('skip embed: no', dirname(dest));
  process.exit(0);
}
copyFileSync(src, dest);
console.log('embedded', dest);
