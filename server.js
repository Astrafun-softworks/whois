const express = require("express");
const fs = require("fs");
const net = require("net");
const cors = require("cors");

const app = express();
const PORT = 3000;

const whoisServers = JSON.parse(fs.readFileSync("tld_whois_map.json", "utf-8"));
const fallbackContacts = {
  "cf": "abuse@freenom.com",
  "ml": "abuse@freenom.com",
  "ga": "abuse@freenom.com",
  "tk": "abuse@freenom.com",
  "gq": "abuse@freenom.com"
};

app.use(cors());

function queryWhois(server, domain) {
  return new Promise((resolve, reject) => {
    let data = "";
    const socket = net.createConnection(43, server, () => {
      socket.write(domain + "\r\n");
    });

    socket.on("data", chunk => data += chunk.toString());
    socket.on("end", () => resolve(data));
    socket.on("error", reject);
  });
}

function extractRegistrarInfo(whoisText) {
  const registrar = whoisText.match(/Registrar:\s*(.*)/i)?.[1]?.trim();
  const abuseEmail = whoisText.match(/Abuse Contact Email:\s*(.*)/i)?.[1]?.trim() ||
                     whoisText.match(/Registrar Abuse Contact Email:\s*(.*)/i)?.[1]?.trim();
  return { registrar, abuseEmail };
}

app.get("/api/whois", async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: "Missing domain parameter" });

  const tld = domain.split(".").pop().toLowerCase();
  const whoisServer = whoisServers[tld];

  if (!whoisServer) {
    return res.json({
      domain,
      whois: null,
      fallback: true,
      registry_contact: fallbackContacts[tld] || null,
      message: `WHOIS not available for .${tld} domains.`
    });
  }

  try {
    const whoisData = await queryWhois(whoisServer, domain);
    const { registrar, abuseEmail } = extractRegistrarInfo(whoisData);

    return res.json({
      domain,
      whois: {
        registrar,
        abuse_email: abuseEmail
      },
      fallback: false
    });
  } catch (err) {
    console.error("WHOIS error:", err);
    return res.status(500).json({ error: "WHOIS query failed" });
  }
});

app.listen(PORT, () => {
  console.log(`WHOIS API running on http://localhost:${PORT}`);
});
