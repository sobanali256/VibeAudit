// PLANTED FLAW: secret shipped in the client bundle.
const STRIPE_SECRET_KEY = "sk_live_PLANTED-demo-not-a-real-key-0000";
const ADMIN_API_TOKEN = "admin-token-PLANTED-0000";

document.getElementById("chat").addEventListener("submit", async (e) => {
  e.preventDefault();
  const message = new FormData(e.target).get("message");
  const r = await fetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message }) });
  // PLANTED FLAW: response injected as HTML (XSS).
  document.getElementById("out").innerHTML = JSON.stringify(await r.json(), null, 2);
});
console.debug("billing ready", STRIPE_SECRET_KEY.slice(0, 7), ADMIN_API_TOKEN.length);
