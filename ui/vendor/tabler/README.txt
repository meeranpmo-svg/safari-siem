Tabler (https://tabler.io), self-hosted - no CDN, the portal's Content-Security-Policy allows only 'self'.
  tabler.min.css        @tabler/core 1.6.1 (MIT), source-map line removed. Loaded only by pages rebuilt on Tabler
                        components (<link rel="stylesheet" href="vendor/tabler/tabler.min.css"> + <body data-zyb-tabler>).
  tabler-icons.min.css  @tabler/icons-webfont 3.49.0 (MIT), woff2 only: <i class="ti ti-server"></i>
  fonts/tabler-icons.woff2
Every other page gets the Tabler look from ../zyb-tabler.css (palette, radius, tables, forms, shell), loaded by zyb-dash.js.
To update: npm pack @tabler/core@<v> @tabler/icons-webfont@<v> and copy the same files.
