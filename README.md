# Shinobi Online

Public website and current Windows distribution metadata for Shinobi Online.

Download the current build from [shinobionline.vercel.app](https://shinobionline.vercel.app/).

No license is granted for the code or artwork in this repository.

## Website access

The landing page is public and static. The download page requires a Shinobi
Online game account. The login form uses the same username and password as the
game. Once the Vercel account-snapshot decryption key is configured, Vercel
verifies credentials against a signed, encrypted snapshot that Production
refreshes from the canonical database mirror at startup; logins then remain
available while the game server is offline. Until that key is configured, the
site preserves its signed live-server login behavior. The public repository and
deployment contain only ciphertext, not readable account hashes or database
records. The session cookie is HTTP-only, secure, same-site, and expires after
12 hours. The existing GitHub Release files and game-launcher manifests remain
on their current distribution path.
