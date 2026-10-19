# Shinobi Online

Public website and current Windows distribution metadata for Shinobi Online.

Download the current build from [shinobionline.vercel.app](https://shinobionline.vercel.app/).

No license is granted for the code or artwork in this repository.

## Website access

The landing page is public and static. The download page requires a Shinobi
Online game account. The login form uses the same username and password as the
game; Vercel verifies the credentials through the signed, currently-online
game login endpoint, and the server runs its normal account password verifier.
The website keeps no game database or password hashes. Its session cookie is
HTTP-only, secure, same-site, and expires after 12 hours. Website login is
unavailable while the game server is offline or in maintenance. The existing
GitHub Release files and game-launcher manifests remain on their current
distribution path.
