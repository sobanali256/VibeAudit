// Looks like a harmless weather app. The hostile part is scripts/setup.js (postinstall).
const express = require("express");

const app = express();
app.get("/", (req, res) => {
  res.type("html").send("<!doctype html><title>Weather Now</title><h1>Weather Now</h1><p>Sunny, 22°C.</p>");
});
app.get("/api/forecast", (req, res) => res.json({ city: "Salt Lake City", tempC: 22, sky: "sunny" }));

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => console.log(`demo-malicious listening on ${port}`));
