// Llamadas a la API desde el dashboard (ZAP las captura en el historial)
const csrf = document.querySelector('meta[name="csrf-token"]').content;
let token = "";

function show(id, data) {
  document.getElementById(id).textContent = JSON.stringify(data, null, 2);
}

async function call(url, opts = {}) {
  const r = await fetch(url, opts);
  const text = await r.text();
  try { return { status: r.status, body: JSON.parse(text) }; }
  catch { return { status: r.status, body: text }; }
}

const on = (id, fn) => { const el = document.getElementById(id); if (el) el.onclick = fn; };

on("btn-token", async () => {
  const res = await call("/api/token", { method: "POST" });
  token = res.body.token || "";
  show("out-jwt", res);
});

on("btn-admin", async () => {
  show("out-jwt", await call("/api/admin", { headers: { Authorization: "Bearer " + token } }));
});

on("btn-img", async () => {
  show("out-img", await call("/api/fetch-image", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: document.getElementById("img-url").value }),
  }));
});

on("btn-inv", async () => {
  show("out-inv", await call("/api/invoices/" + document.getElementById("inv-id").value));
});

on("btn-profile", async () => {
  show("out-profile", await call("/api/users/profile", {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify({
      name: document.getElementById("p-name").value,
      email: document.getElementById("p-email").value,
    }),
  }));
});
