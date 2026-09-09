# Academy pages — Vercel deployment

## Included pages

- `https://YOUR-DOMAIN/APPX.html` (or root `/`)
- `https://YOUR-DOMAIN/DHYEY.html`
- `https://YOUR-DOMAIN/bhainsh.html`

The public directory is configured with all static pages, assets, and player icons (`/icons/backwards.svg`, `/icons/forward.svg`, etc.). `vercel.json` maps the public directory to `public` and rewrites `/proxy?url=...`, `/api/*`, and player routes to the Vercel function in `api/proxy.js`.

## Deploy

1. Extract the ZIP / push to GitHub.
2. Import the repository or folder into Vercel, or run:

   ```bash
   npx vercel
   ```

3. Deploy with default settings. The build command `npm run build` will generate the `public` directory automatically. No manual framework configuration is needed.
4. Open your deployment URL.

## Important

The proxy allowlist contains the player/API hosts used by these two pages.
It does not proxy arbitrary websites or manufacture `Referer`/`Origin`
headers. If the player provider returns a genuine 403 because the deployment
domain is not authorized, the provider/academy owner must allow that domain.

Vercel serverless functions are not ideal for very long-running or high-volume
video delivery. If HLS playback is unstable after deployment, use the
provider's official player URL or a video delivery service designed for
streaming.