// Looks like a harmless hello-world app. The hostile part is scripts/setup.js (postinstall).
const http = require("http");
const port = Number(process.env.PORT) || 3000;
http
  .createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<!doctype html><title>Weather Now</title><h1>Weather Now</h1><p>Sunny, 22°C.</p>");
  })
  .listen(port, "0.0.0.0", () => console.log(`demo-malicious listening on ${port}`));
