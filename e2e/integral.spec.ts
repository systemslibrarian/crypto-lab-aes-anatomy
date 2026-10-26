import { expect, test } from '@playwright/test';

test('integral exercise reports candidate filtering, separate verification and retires stale evidence', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-10').click();
  await expect(page.locator('#integral-verification')).toContainText('3/3 match');
  await expect(page.locator('#integral-query-count')).toContainText('disjoint sets of 256');
  const rows = page.getByRole('region', { name: 'Round-4 key candidate counts', exact: true }).locator('tbody tr');
  expect(await rows.count()).toBeGreaterThan(1);
  expect(await rows.count()).toBeLessThanOrEqual(6);
  const counts = await rows.last().locator('td').allTextContents();
  expect(counts.slice(1)).toEqual(Array(16).fill('1'));
  await page.locator('#key').fill('00'.repeat(16));
  await expect(page.locator('#result-10')).toBeEmpty();
  await page.locator('#compute-10').click();
  await expect(page.locator('#integral-verification')).toContainText('3/3 match');
  await page.locator('#tab-3').click();
  await expect(page.locator('[data-check=wide-trail-dispersion]')).toHaveAttribute('data-verdict', 'pass');
  await expect(page.locator('[data-check=weakened-dispersion]')).toHaveAttribute('data-verdict', 'pass');
});
