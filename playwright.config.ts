import {defineConfig,devices} from '@playwright/test';
const port=4746,base='/crypto-lab-aes-anatomy/';
export default defineConfig({testDir:'./e2e',timeout:120000,fullyParallel:true,forbidOnly:!!process.env.CI,retries:0,reporter:'list',use:{baseURL:`http://localhost:${port}${base}`,colorScheme:'dark',...devices['Desktop Chrome']},projects:[{name:'chromium',use:{...devices['Desktop Chrome']}}],webServer:{command:`npm run build && npm run preview -- --port ${port} --strictPort`,url:`http://localhost:${port}${base}`,reuseExistingServer:!process.env.CI,timeout:120000}});
