// build.js - Prepares public output directory for Vercel and production builds
const fs = require('fs');
const path = require('path');

const rootDir = __dirname;
const publicDir = path.join(rootDir, 'public');
const publicIconsDir = path.join(publicDir, 'icons');
const sourceIconsDir = path.join(rootDir, 'icons');

// 1. Ensure public directories exist
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}
if (!fs.existsSync(publicIconsDir)) {
  fs.mkdirSync(publicIconsDir, { recursive: true });
}

// 2. Copy icons to public/icons
if (fs.existsSync(sourceIconsDir)) {
  const iconFiles = fs.readdirSync(sourceIconsDir);
  for (const file of iconFiles) {
    fs.copyFileSync(path.join(sourceIconsDir, file), path.join(publicIconsDir, file));
  }
  console.log(`[build] Synced ${iconFiles.length} icons to public/icons`);
}

// 3. Copy all HTML files to public directory
const rootFiles = fs.readdirSync(rootDir);
let htmlCount = 0;
for (const file of rootFiles) {
  if (file.toLowerCase().endsWith('.html')) {
    fs.copyFileSync(path.join(rootDir, file), path.join(publicDir, file));
    htmlCount++;
  }
}
console.log(`[build] Synced ${htmlCount} HTML pages to public/`);

// 4. Ensure index.html exists in public (fallback to APPX.html if missing)
if (!fs.existsSync(path.join(publicDir, 'index.html')) && fs.existsSync(path.join(publicDir, 'APPX.html'))) {
  fs.copyFileSync(path.join(publicDir, 'APPX.html'), path.join(publicDir, 'index.html'));
  console.log('[build] Generated public/index.html from APPX.html');
}

console.log('✅ [build] Output directory "public" successfully generated.');
