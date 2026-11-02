# Offline cache
Open https://ibhamada0.github.io/14/raw13/offline.html on the PS4 while online.
Bookmark that exact URL. Wait for "Offline cache complete" before disconnecting.
Reopen the bookmark offline and select "Open the page".
The cache entry opens jb.html?log=1; it does not change jailbreak settings or scripts.

This uses legacy Application Cache for browsers that implement it. Modern browsers
that removed Application Cache display an unsupported message. This has not been
tested on physical PS4 hardware. Browser storage can be cleared or evicted.

All shipped raw13 HTML, JavaScript and binary assets are cached, including the exact
versioned JavaScript import URLs. Custom payload URLs that are not included in the
repository are not available offline. The cache does not guarantee jailbreak success.

The Refresh offline cache workflow validates that JavaScript files are not HTML,
regenerates the manifest fingerprint from the complete file contents, then requests
a GitHub Pages rebuild. It runs after pushes or a successful Sync upstream run.
A failed download preserves the previous complete cache. An available update requires
a reload before opening the page, so the current page is not switched mid-session.

Regenerate manually with: python3 .github/scripts/build-offline-cache.py
