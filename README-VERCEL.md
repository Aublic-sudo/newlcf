# Academy pages — Vercel deployment

## Included pages

- `https://YOUR-DOMAIN/DHYEY.html`
- `https://YOUR-DOMAIN/bhainshkipathshala.html`

The two original HTML files are kept under `attached_assets/`. `vercel.json`
maps the public URLs above to those files. `/proxy?url=...` is rewritten to
the Vercel function in `api/proxy.js`.

## Deploy

1. Extract the ZIP.
2. Import the extracted folder into Vercel, or run:

   ```bash
   npx vercel
   ```

3. Deploy with the default settings. No build command or environment variable
   is required.
4. Open one of the two page URLs above. Do not open the HTML with `file://`.

## Important

The proxy allowlist contains the player/API hosts used by these two pages.
It does not proxy arbitrary websites or manufacture `Referer`/`Origin`
headers. If the player provider returns a genuine 403 because the deployment
domain is not authorized, the provider/academy owner must allow that domain.

Vercel serverless functions are not ideal for very long-running or high-volume
video delivery. If HLS playback is unstable after deployment, use the
provider's official player URL or a video delivery service designed for
streaming.