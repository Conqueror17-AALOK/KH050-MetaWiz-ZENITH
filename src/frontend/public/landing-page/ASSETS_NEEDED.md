# Assets needed

This template references two files that must be supplied by you (binary
brand assets can't be generated):

- `assets/logo.webp` — your circular logo mark, ideally square, at least
  104x104px so it stays sharp at 2x pixel density inside the 52x52 circle.
- `fonts/GeistPixel-Circle.woff2` — the Geist Pixel Circle font file,
  used only as a fallback if the BubbledotICG-FinePos CDN font fails to
  load.

Drop both into their matching folders (already created: `assets/`,
`fonts/`) and the page will pick them up automatically — no code changes
needed.

Everything else (Inter, BubbledotICG-FinePos, Font Awesome, the
background video) loads from the exact CDN/CloudFront URLs specified.
