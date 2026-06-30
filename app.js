async function loadLatestManifest() {
  const versionEl = document.querySelector("#release-version");
  const channelEl = document.querySelector("#release-channel");
  const installerEl = document.querySelector("#release-installer");
  const copyEl = document.querySelector("#download-copy");
  const metaEl = document.querySelector("#release-meta");
  const linkEl = document.querySelector("#download-link");

  try {
    const response = await fetch("/public/latest.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Manifest request failed: ${response.status}`);
    }

    const manifest = await response.json();
    const installer = manifest.installer;
    const hasInstaller = Boolean(
      manifest.status === "available" &&
      installer &&
      installer.url &&
      installer.sha256 &&
      installer.sizeBytes > 0
    );

    versionEl.textContent = manifest.version || "Unpublished";
    channelEl.textContent = manifest.channel || "production";
    installerEl.textContent = hasInstaller ? "Available" : "Pending";

    if (hasInstaller) {
      copyEl.textContent = `Shinobi Online ${manifest.version} is available.`;
      metaEl.textContent = `SHA-256 ${installer.sha256} | ${formatBytes(installer.sizeBytes)}`;
      linkEl.href = installer.url;
      linkEl.textContent = "Download installer";
      linkEl.classList.remove("is-disabled");
      linkEl.removeAttribute("aria-disabled");
    } else {
      copyEl.textContent = manifest.message || "The first public installer has not been published yet.";
      metaEl.textContent = "Public downloads will appear here after the first GitHub Release asset is published.";
      linkEl.href = manifest.releaseNotesUrl || "https://github.com/frizas/shinobi-online/releases";
      linkEl.textContent = "Open releases";
      linkEl.classList.add("is-disabled");
      linkEl.setAttribute("aria-disabled", "true");
    }
  } catch (error) {
    versionEl.textContent = "Unavailable";
    channelEl.textContent = "Unknown";
    installerEl.textContent = "Unknown";
    copyEl.textContent = "The latest manifest could not be loaded.";
    metaEl.textContent = error.message;
  }
}

async function loadServerManifest() {
  const serverEl = document.querySelector("#server-status");
  if (!serverEl) {
    return;
  }

  try {
    const response = await fetch("/public/server.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Server manifest request failed: ${response.status}`);
    }

    const manifest = await response.json();
    serverEl.textContent = formatServerStatus(manifest.status);
    serverEl.title = manifest.message || "";
  } catch {
    serverEl.textContent = "Unknown";
  }
}

function formatServerStatus(status) {
  if (status === "online") {
    return "Online";
  }
  if (status === "maintenance") {
    return "Maintenance";
  }
  return "Offline";
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

loadLatestManifest();
loadServerManifest();
