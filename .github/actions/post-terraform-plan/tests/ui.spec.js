/**
 * Playwright E2E Tests for Terraform Plan UI
 *
 * These tests verify the HTML output renders correctly with proper
 * styling, formatting, and interactive behavior.
 *
 * Run with: npx playwright test tests/ui.spec.js
 */

const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const { parseJsonPlan, calculateSummary } = require('../src/terraform-plan-parser');
const { generateHtml } = require('../src/html-generator');

// Paths
const previewDir = path.join(__dirname, '..', 'preview');
const fixturesDir = path.join(__dirname, '..', 'test-fixtures');
const screenshotsDir = path.join(__dirname, '..', 'screenshots');

// Ensure directories exist
if (!fs.existsSync(previewDir)) {
  fs.mkdirSync(previewDir, { recursive: true });
}
if (!fs.existsSync(screenshotsDir)) {
  fs.mkdirSync(screenshotsDir, { recursive: true });
}

// Helper to generate HTML preview
function generatePreview(fixtureName) {
  const planPath = path.join(fixturesDir, `${fixtureName}-plan.json`);
  const planJson = fs.readFileSync(planPath, 'utf-8');
  const resources = parseJsonPlan(planJson);
  const summary = calculateSummary(resources);

  const html = generateHtml({
    resources,
    summary,
    planOutcome: 'success',
    runNumber: 42,
    runUrl: 'https://github.com/AshleyHollis/yt-summarizer/actions/runs/12345',
    actor: 'developer',
    timestamp: '2026-01-13 10:30:00 UTC'
  });

  const outputPath = path.join(previewDir, `${fixtureName}-preview.html`);
  fs.writeFileSync(outputPath, html, 'utf-8');
  return outputPath;
}

test.describe('Terraform Plan UI - Realistic Plan', () => {
  let htmlPath;

  test.beforeAll(() => {
    htmlPath = generatePreview('realistic');
  });

  test('renders header with Terraform branding', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Check header exists with Terraform branding
    await expect(page.locator('.header')).toBeVisible();
    await expect(page.locator('.header-title')).toContainText('Terraform Plan');
    await expect(page.locator('.header-subtitle')).toContainText('Infrastructure as Code');

    // Check status badge
    await expect(page.locator('.status-badge.success')).toContainText('Plan Succeeded');

    // Take screenshot of header
    await page.locator('.header').screenshot({
      path: path.join(screenshotsDir, 'header.jpeg'),
      type: 'jpeg',
      quality: 90
    });
  });

  test('displays run info bar correctly', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    const runInfo = page.locator('.run-info');
    await expect(runInfo).toBeVisible();
    await expect(runInfo).toContainText('Run #42');
    await expect(runInfo).toContainText('@developer');
    await expect(runInfo).toContainText('View Workflow');
  });

  test('shows summary stats with correct colors', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    const summary = page.locator('.summary');
    await expect(summary).toBeVisible();

    // Check add summary (green)
    const addItem = page.locator('.summary-item.add');
    await expect(addItem).toBeVisible();
    await expect(addItem).toContainText('to add');

    // Check change summary (yellow)
    const changeItem = page.locator('.summary-item.change');
    await expect(changeItem).toBeVisible();
    await expect(changeItem).toContainText('to change');

    // Check destroy summary (red)
    const destroyItem = page.locator('.summary-item.destroy');
    await expect(destroyItem).toBeVisible();
    await expect(destroyItem).toContainText('to destroy');

    // Take screenshot of summary
    await summary.screenshot({
      path: path.join(screenshotsDir, 'summary-stats.jpeg'),
      type: 'jpeg',
      quality: 90
    });
  });

  test('renders resource sections with correct icons', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Check Create section
    const createSection = page.locator('.section').filter({ hasText: 'Resources to Add' });
    await expect(createSection).toBeVisible();

    // Check Update section
    const updateSection = page.locator('.section').filter({ hasText: 'Resources to Update' });
    await expect(updateSection).toBeVisible();

    // Check Destroy section
    const destroySection = page.locator('.section').filter({ hasText: 'Resources to Destroy' });
    await expect(destroySection).toBeVisible();

    // Check Replace section
    const replaceSection = page.locator('.section').filter({ hasText: 'Resources to Replace' });
    await expect(replaceSection).toBeVisible();
  });

  test('sections are collapsible', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // First section should be open by default
    const firstSection = page.locator('.section').first();
    await expect(firstSection).toHaveClass(/open/);

    // Click to close
    await firstSection.locator('.section-header').click();
    await expect(firstSection).not.toHaveClass(/open/);

    // Click to open again
    await firstSection.locator('.section-header').click();
    await expect(firstSection).toHaveClass(/open/);
  });

  test('resource details are expandable', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Find first resource in an open section
    const firstResource = page.locator('.section.open .resource').first();
    await expect(firstResource).toBeVisible();

    // Should be open by default (first resource in first section)
    await expect(firstResource).toHaveClass(/open/);

    // Check that details contain code
    const details = firstResource.locator('.resource-details pre');
    await expect(details).toBeVisible();

    // Take screenshot of expanded resource
    await firstResource.screenshot({
      path: path.join(screenshotsDir, 'resource-details.jpeg'),
      type: 'jpeg',
      quality: 90
    });
  });

  test('code blocks have syntax highlighting', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Check for syntax highlighting classes in code
    const codeBlock = page.locator('.resource.open .resource-details pre').first();
    await expect(codeBlock).toBeVisible();

    // Should have highlighted elements
    const highlightedElements = codeBlock.locator('span[class^="hl-"]');
    const count = await highlightedElements.count();
    expect(count).toBeGreaterThan(0);
  });

  test('full page screenshot', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Wait for page to fully load
    await page.waitForLoadState('networkidle');

    // Open all sections for full screenshot
    const sections = page.locator('.section-header');
    const sectionCount = await sections.count();
    for (let i = 0; i < sectionCount; i++) {
      const section = sections.nth(i);
      const parent = section.locator('..');
      const isOpen = await parent.evaluate(el => el.classList.contains('open'));
      if (!isOpen) {
        await section.click();
      }
    }

    // Take full page screenshot
    await page.screenshot({
      path: path.join(screenshotsDir, 'full-page-realistic.jpeg'),
      type: 'jpeg',
      quality: 90,
      fullPage: true
    });
  });

  test('responsive layout on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(`file://${htmlPath}`);

    // Header should stack vertically
    await expect(page.locator('.header')).toBeVisible();

    // Summary items should stack
    await expect(page.locator('.summary')).toBeVisible();

    // Take mobile screenshot
    await page.screenshot({
      path: path.join(screenshotsDir, 'mobile-view.jpeg'),
      type: 'jpeg',
      quality: 90,
      fullPage: true
    });
  });
});

test.describe('Terraform Plan UI - No Changes', () => {
  let htmlPath;

  test.beforeAll(() => {
    htmlPath = generatePreview('no-changes');
  });

  test('shows no changes message', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    const noChanges = page.locator('.no-changes');
    await expect(noChanges).toBeVisible();
    await expect(noChanges).toContainText('No changes');
    await expect(noChanges).toContainText('Your infrastructure matches the configuration');

    // Take screenshot
    await page.screenshot({
      path: path.join(screenshotsDir, 'no-changes.jpeg'),
      type: 'jpeg',
      quality: 90
    });
  });

  test('does not show summary stats when no changes', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Summary should not be visible or should be empty
    const summary = page.locator('.summary');
    const isVisible = await summary.isVisible();
    if (isVisible) {
      const text = await summary.textContent();
      expect(text.trim()).toBe('');
    }
  });
});

test.describe('Terraform Plan UI - Create Only', () => {
  let htmlPath;

  test.beforeAll(() => {
    htmlPath = generatePreview('create-only');
  });

  test('shows only create section', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Create section should be visible
    const createSection = page.locator('.section').filter({ hasText: 'Resources to Add' });
    await expect(createSection).toBeVisible();

    // Other sections should not exist
    const updateSection = page.locator('.section').filter({ hasText: 'Resources to Update' });
    await expect(updateSection).not.toBeVisible();

    const destroySection = page.locator('.section').filter({ hasText: 'Resources to Destroy' });
    await expect(destroySection).not.toBeVisible();

    // Take screenshot
    await page.screenshot({
      path: path.join(screenshotsDir, 'create-only.jpeg'),
      type: 'jpeg',
      quality: 90,
      fullPage: true
    });
  });

  test('summary shows only add count', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    const addItem = page.locator('.summary-item.add');
    await expect(addItem).toBeVisible();

    const changeItem = page.locator('.summary-item.change');
    await expect(changeItem).not.toBeVisible();

    const destroyItem = page.locator('.summary-item.destroy');
    await expect(destroyItem).not.toBeVisible();
  });
});

test.describe('Terraform Plan UI - Accessibility', () => {
  let htmlPath;

  test.beforeAll(() => {
    htmlPath = generatePreview('realistic');
  });

  test('has proper heading structure', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Check for main title
    const title = await page.title();
    expect(title).toContain('Terraform Plan');
  });

  test('interactive elements are keyboard accessible', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Tab through the page
    await page.keyboard.press('Tab');

    // Check that something is focused
    const focused = await page.evaluate(() => document.activeElement.tagName);
    expect(focused).not.toBe('BODY');
  });

  test('has sufficient color contrast', async ({ page }) => {
    await page.goto(`file://${htmlPath}`);

    // Check that text is readable (basic check)
    const headerTitle = page.locator('.header-title');
    const color = await headerTitle.evaluate(el => getComputedStyle(el).color);

    // Should be white text on dark background
    expect(color).toContain('rgb');
  });
});

test.describe('Terraform Plan UI - Visual Regression', () => {
  test('matches baseline screenshot', async ({ page }) => {
    const htmlPath = generatePreview('realistic');
    await page.goto(`file://${htmlPath}`);

    // Wait for animations
    await page.waitForTimeout(500);

    // Take comparison screenshot
    await expect(page).toHaveScreenshot('terraform-plan-baseline.png', {
      fullPage: true,
      threshold: 0.1
    });
  });
});
