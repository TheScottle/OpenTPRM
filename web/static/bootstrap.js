(function () {
  var form = document.getElementById("bootstrap-form");
  var out = document.getElementById("bootstrap-result");
  if (!form || !out) return;
  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var fd = new FormData(form);
    out.hidden = false;
    out.textContent = "Submitting…";
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
      out.textContent = res.status + "\n" + text;
      if (res.status === 201) {
        out.textContent += "\n\nNext: open /login with either admin email and password.";
      }
    } catch (e) {
      out.textContent = String(e);
    }
  });
})();
