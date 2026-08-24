(() => {
  const form = document.querySelector("form[data-start-discovery]");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    try {
      const response = await fetch("/api/public/sessions", {
        method: "POST",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error("session creation failed");
      const payload = await response.json();
      window.location.assign(`/play/${encodeURIComponent(payload.session_id)}`);
    } catch (_error) {
      form.submit();
    }
  });
})();
