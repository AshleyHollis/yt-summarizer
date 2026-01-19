/**
 * Azure Static Web Apps health check endpoint
 *
 * SWA requires /.swa/health.html to be accessible for deployment validation.
 * Next.js ignores files starting with '.' in the public folder, so we serve
 * the health check via an API route instead.
 *
 * @see https://learn.microsoft.com/en-us/azure/static-web-apps/deploy-nextjs-hybrid#health-check
 */
export async function GET() {
  return new Response(
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Health Check</title>
  </head>
  <body>
    <h1>OK</h1>
    <p>Azure Static Web Apps health check endpoint.</p>
  </body>
</html>`,
    {
      status: 200,
      headers: {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      },
    }
  );
}
