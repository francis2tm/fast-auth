import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  input: '../../docs/openapi.yml',
  output: {
    format: 'prettier',
    lint: 'eslint',
    path: 'src/generated'
  },
  plugins: ['@hey-api/client-fetch']
});
