async function loadLatestManifest() {
  const versionEl = document.querySelector("#release-version");
  const installerEl = document.querySelector("#release-installer");
  const sizeEl = document.querySelector("#release-size");
  const copyEl = document.querySelector("#download-copy");
  const metaEl = document.querySelector("#release-meta");
  const linkEl = document.querySelector("#download-link");
  const androidLinkEl = document.querySelector("#android-download-link");
  const compatibilityEl = document.querySelector("#compatibility-summary");
  const notesEl = document.querySelector("#release-notes-link");

  try {
    const response = await fetch("/public/latest.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Manifest request failed: ${response.status}`);
    }

    const manifest = await response.json();
    const installer = manifest.installer;
    const androidApk = manifest.android && manifest.android.apk;
    const hasInstaller = Boolean(
      manifest.status === "available" &&
      installer &&
      installer.url &&
      installer.sha256 &&
      installer.sizeBytes > 0
    );
    const hasAndroidApk = Boolean(
      manifest.status === "available" &&
      androidApk &&
      androidApk.url &&
      androidApk.sha256 &&
      androidApk.sizeBytes > 0
    );

    versionEl.textContent = manifest.version ? `v${manifest.version}` : "Unpublished";
    installerEl.textContent = hasInstaller ? installer.fileName || "Ready" : "Pending";
    sizeEl.textContent = hasInstaller ? formatBytes(installer.sizeBytes) : "Unavailable";
    renderCompatibilitySummary(compatibilityEl, manifest.compatibility);

    if (notesEl && manifest.releaseNotesUrl) {
      notesEl.href = manifest.releaseNotesUrl;
    }

    if (hasInstaller) {
      copyEl.textContent = formatReleaseDateCopy(manifest.publishedAt);
      metaEl.textContent = "";
      metaEl.hidden = true;
      linkEl.href = installer.url;
      linkEl.textContent = "Download for Windows";
      linkEl.classList.remove("is-disabled");
      linkEl.removeAttribute("aria-disabled");
    } else {
      copyEl.textContent = manifest.message || "The first public installer has not been published yet.";
      metaEl.textContent = "";
      metaEl.hidden = true;
      linkEl.href = manifest.releaseNotesUrl || "https://github.com/frizas/shinobi-online/releases";
      linkEl.textContent = "Open releases";
      linkEl.classList.add("is-disabled");
      linkEl.setAttribute("aria-disabled", "true");
    }

    if (androidLinkEl) {
      if (hasAndroidApk) {
        androidLinkEl.href = androidApk.url;
        androidLinkEl.hidden = false;
        androidLinkEl.classList.remove("is-disabled");
        androidLinkEl.removeAttribute("aria-disabled");
      } else {
        androidLinkEl.href = manifest.releaseNotesUrl || "https://github.com/frizas/shinobi-online/releases";
        androidLinkEl.textContent = "Android coming soon";
        androidLinkEl.hidden = false;
        androidLinkEl.classList.add("is-disabled");
        androidLinkEl.setAttribute("aria-disabled", "true");
      }
    }
  } catch (error) {
    versionEl.textContent = "Unavailable";
    installerEl.textContent = "Unknown";
    sizeEl.textContent = "Unknown";
    copyEl.textContent = "The latest release could not be loaded.";
    metaEl.textContent = "";
    metaEl.hidden = true;
    if (androidLinkEl) {
      androidLinkEl.hidden = true;
    }
    renderCompatibilitySummary(compatibilityEl, null);
  }
}

function formatReleaseDateCopy(publishedAt) {
  const fallback = "Latest release date is listed in the release notes.";
  if (!publishedAt) {
    return fallback;
  }

  const date = new Date(publishedAt);
  if (Number.isNaN(date.getTime())) {
    return fallback;
  }

  const formattedDate = new Intl.DateTimeFormat("en", {
    month: "long",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC"
  }).format(date);

  return `Latest release: ${formattedDate}`;
}

function renderCompatibilitySummary(element, compatibility) {
  if (!element) {
    return;
  }

  const requirements = compatibility || {
    os: "Windows 10 or newer",
    architecture: "x64",
    graphics: "OpenGL-capable GPU driver",
    prerequisiteMode: "detect-and-guide"
  };

  element.textContent = `${formatOs(requirements.os)} ${requirements.architecture}, OpenGL`;
  element.title = [
    requirements.os,
    requirements.architecture,
    requirements.graphics,
    formatPrerequisiteMode(requirements.prerequisiteMode)
  ].join(" | ");
}

function formatPrerequisiteMode(mode) {
  if (mode === "detect-and-guide") {
    return "detected and explained by the launcher";
  }
  return mode || "detected by the launcher";
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
    serverEl.dataset.status = manifest.status || "offline";
    serverEl.title = manifest.message || "";
  } catch {
    serverEl.textContent = "Unknown";
    serverEl.dataset.status = "unknown";
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

function formatOs(os) {
  if (!os) {
    return "Windows 10+";
  }
  return os.replace("Windows 10 or newer", "Windows 10+");
}

loadLatestManifest();
loadServerManifest();
