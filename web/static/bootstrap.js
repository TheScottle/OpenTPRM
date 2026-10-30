(function () {
  var form = document.getElementById("bootstrap-form");
  var out = document.getElementById("bootstrap-result");
  if (!form || !out) return;
  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var fd = new FormData(form);
    var btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;
    out.hidden = false;
    out.textContent = "Creating administrators…";
    out.classList.remove("error");
    try {
      var res = await fetch("/api/v1/auth/bootstrap", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          token: fd.get("token"),
          security_admin_email: fd.get("security_admin_email"),
          system_admin_email: fd.get("system_admin_email"),
          security_admin_password: fd.get("security_admin_password"),
          system_admin_password: fd.get("system_admin_password")
        })
      });
      var text = await res.text();
      var data = null;
      try { data = JSON.parse(text); } catch (_) {}
      if (res.status === 201) {
        var email = fd.get("security_admin_email") || "";
        var next = "/login?bootstrap=1&email=" + encodeURIComponent(email);
        out.textContent = "Administrators created. Redirecting to sign in…";
        window.location.assign(next);
        return;
      }
      out.classList.add("error");
      var detail = (data && (data.detail || data.title)) || text;
      out.textContent = "Could not complete bootstrap (" + res.status + "): " + detail;
      if (btn) btn.disabled = false;
    } catch (e) {
      out.classList.add("error");
      out.textContent = String(e);
      if (btn) btn.disabled = false;
    }
  });
})();
