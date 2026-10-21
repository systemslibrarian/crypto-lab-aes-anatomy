import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath: https://<user>.github.io/crypto-lab-aes-anatomy/
export default defineConfig({
  base: '/crypto-lab-aes-anatomy/',
  test: {
    // Colocated unit tests only; keep Playwright specs in e2e/ out of the Vitest run.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
