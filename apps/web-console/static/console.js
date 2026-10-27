if (document.body.dataset.protected === "true") {
  const remaining = Date.parse(document.body.dataset.sessionExpires) - Date.now();
  const endSession = () => {
    document.body.hidden = true;
    window.location.replace("/signed-out?reason=expired");
  };
  if (!Number.isFinite(remaining) || remaining <= 0) endSession();
  else window.setTimeout(endSession, remaining);

  // Conceal cached/background content until the server rechecks the session.
  window.addEventListener("pagehide", () => { document.body.hidden = true; });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) window.location.reload();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) document.body.hidden = true;
    else if (document.body.hidden) window.location.reload();
  });
}
