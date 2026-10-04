import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  plugins: [viteSingleFile()],
  base: './',
  esbuild: { jsx: 'automatic' },
  build: {
    assetsInlineLimit: 100000,
    cssCodeSplit: false,
  },
});
