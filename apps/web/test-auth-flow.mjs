import { chromium } from 'playwright';

const FRONTEND_URL = 'https://white-meadow-0b8e2e000-migrationphase6a.eastasia.6.azurestaticapps.net';
const API_BASE_URL = 'https://api.yt-summarizer.apps.ashleyhollis.com';
const TEST_EMAIL = process.env.TEST_EMAIL || 'user@test.yt-summarizer.internal';
const TEST_PASSWORD = process.env.TEST_PASSWORD || '';

async function testAuthFlow() {
  console.log('🚀 Starting Auth Flow E2E Test\n');
  
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Step 1: Visit frontend
    console.log('1️⃣  Navigating to frontend...');
    await page.goto(FRONTEND_URL, { waitUntil: 'networkidle' });
    console.log(`   ✅ Loaded: ${page.url()}\n`);

    // Step 2: Check initial session state
    console.log('2️⃣  Checking initial session state...');
    const sessionResponse = await page.evaluate(async (apiUrl) => {
      const res = await fetch(`${apiUrl}/api/auth/session`, { credentials: 'include' });
      return await res.json();
    }, API_BASE_URL);
    console.log(`   📊 Session: ${JSON.stringify(sessionResponse)}`);
    console.log(`   ✅ isAuthenticated: ${sessionResponse.isAuthenticated}\n`);

    // Step 3: Click login button
    console.log('3️⃣  Clicking login button...');
    const loginButton = page.locator('button:has-text("Login"), a:has-text("Login")').first();
    await loginButton.waitFor({ state: 'visible', timeout: 10000 });
    await loginButton.click();
    console.log('   ✅ Login button clicked\n');

    // Step 4: Wait for Auth0 redirect
    console.log('4️⃣  Waiting for Auth0 login page...');
    await page.waitForURL(/auth0\.com/, { timeout: 15000 });
    console.log(`   ✅ Redirected to: ${page.url()}\n`);

    // Step 5: Fill in credentials
    console.log('5️⃣  Entering credentials...');
    
    // Wait for and fill the username field
    const usernameField = page.locator('input[name="username"]');
    await usernameField.waitFor({ state: 'visible', timeout: 10000 });
    await usernameField.click();
    await usernameField.type(TEST_EMAIL, { delay: 50 });
    
    // Verify the username was entered
    const usernameValue = await usernameField.inputValue();
    console.log(`   Username entered: ${usernameValue}`);
    
    // Wait for and fill the password field
    const passwordField = page.locator('input[name="password"]');
    await passwordField.waitFor({ state: 'visible', timeout: 10000 });
    await passwordField.click();
    await passwordField.type(TEST_PASSWORD, { delay: 50 });
    
    // Verify the password was entered
    const passwordValue = await passwordField.inputValue();
    console.log(`   Password entered: ${passwordValue.length} characters`);
    
    console.log('   ✅ Credentials entered\n');

    // Step 6: Submit login form
    console.log('6️⃣  Submitting login form...');
    await page.click('button[type="submit"], button[name="submit"]');
    console.log('   ✅ Form submitted\n');

    // Wait a moment to see if there's an error
    await page.waitForTimeout(2000);
    
    // Check for error messages
    const errorElement = await page.locator('.error, .alert, [class*="error"], [class*="alert"]').first().textContent().catch(() => null);
    if (errorElement) {
      console.log(`   ⚠️  Error on page: ${errorElement}`);
    }

    // Step 7: Wait for redirect back to frontend
    console.log('7️⃣  Waiting for redirect back to frontend...');
    // Accept either the SWA preview URL or the production web URL
    await page.waitForURL(/yt-summarizer\.apps\.ashleyhollis\.com/, { timeout: 15000 });
    console.log(`   ✅ Redirected back to: ${page.url()}\n`);

    // Step 8: Verify authenticated session
    console.log('8️⃣  Verifying authenticated session...');
    await page.waitForTimeout(2000); // Wait for session to establish
    const authSessionResponse = await page.evaluate(async (apiUrl) => {
      const res = await fetch(`${apiUrl}/api/auth/session`, { credentials: 'include' });
      return await res.json();
    }, API_BASE_URL);
    console.log(`   📊 Session: ${JSON.stringify(authSessionResponse, null, 2)}`);
    
    if (authSessionResponse.isAuthenticated && authSessionResponse.user) {
      console.log(`   ✅ Authenticated as: ${authSessionResponse.user.email || authSessionResponse.user.name}\n`);
    } else {
      throw new Error('User is not authenticated after login');
    }

    // Step 9: Check for logout button
    console.log('9️⃣  Checking for logout button...');
    const logoutButton = page.locator('button:has-text("Logout"), a:has-text("Logout")').first();
    await logoutButton.waitFor({ state: 'visible', timeout: 10000 });
    console.log('   ✅ Logout button visible\n');

    // Step 10: Click logout
    console.log('🔟 Clicking logout button...');
    await logoutButton.click();
    await page.waitForTimeout(2000);
    console.log('   ✅ Logout button clicked\n');

    // Step 11: Verify session cleared
    console.log('1️⃣1️⃣  Verifying session cleared...');
    const loggedOutSessionResponse = await page.evaluate(async (apiUrl) => {
      const res = await fetch(`${apiUrl}/api/auth/session`, { credentials: 'include' });
      return await res.json();
    }, API_BASE_URL);
    console.log(`   📊 Session: ${JSON.stringify(loggedOutSessionResponse)}`);
    
    if (!loggedOutSessionResponse.isAuthenticated) {
      console.log('   ✅ Session successfully cleared\n');
    } else {
      throw new Error('Session was not cleared after logout');
    }

    console.log('✅ All auth flow tests passed!\n');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error('\nCurrent URL:', page.url());
    
    // Take screenshot on failure
    const screenshotPath = 'auth-test-failure.png';
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.error(`Screenshot saved to: ${screenshotPath}`);
    
    throw error;
  } finally {
    await browser.close();
  }
}

testAuthFlow()
  .then(() => {
    console.log('🎉 Test completed successfully!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Test failed:', error);
    process.exit(1);
  });
