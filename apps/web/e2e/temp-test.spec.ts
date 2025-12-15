import { test, expect } from '@playwright/test';

test('chat works on video detail page', async ({ page }) => {
  // Capture the actual request bodies sent to copilotkit
  page.on('request', async request => {
    if (request.url().includes('localhost:8000') && request.url().includes('copilotkit') && request.method() === 'POST') {
      const postData = request.postData();
      console.log('>> POST to copilotkit:');
      console.log('>> Body:', postData?.slice(0, 1000));
    }
  });
  
  page.on('response', async response => {
    if (response.url().includes('localhost:8000') && response.url().includes('copilotkit')) {
      const body = await response.text().catch(() => 'could not read');
      console.log('<< Response from', response.url());
      console.log('<< Status:', response.status());
      console.log('<< Body preview:', body.slice(0, 500));
    }
  });

  await page.goto('/library/4a7c6cb9-eccb-4841-8086-7a0f0f2cc22a');
  await page.waitForLoadState('networkidle');
  
  // Wait for initial requests
  await page.waitForTimeout(3000);
  
  // Find chat input
  const input = page.getByRole('textbox').first();
  const inputVisible = await input.isVisible({ timeout: 5000 }).catch(() => false);
  console.log('Chat input visible:', inputVisible);
  
  if (inputVisible) {
    console.log('Submitting question...');
    await input.fill('Hello, what is this video about?');
    await input.press('Enter');
    
    // Wait for request
    console.log('Waiting for response...');
    await page.waitForTimeout(10000);
    
    console.log('Done waiting');
  }
});
