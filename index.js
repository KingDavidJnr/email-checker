const express = require("express");
const dns = require("dns").promises;
const net = require("net");
const morgan = require("morgan");
const path = require("path");

// Use reliable public DNS servers
dns.setServers(["8.8.8.8", "1.1.1.1"]);

const app = express();

app.use(express.json());
app.use(morgan("common"));
app.use(express.static(path.join(__dirname, "public")));

/**
 * -------------------------
 * AUTH
 * -------------------------
 */
function parseCookies(req) {
  const raw = req.headers.cookie || "";
  return raw.split(";").reduce((acc, c) => {
    const [k, ...v] = c.trim().split("=");
    if (k) acc[k] = decodeURIComponent(v.join("="));
    return acc;
  }, {});
}

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  return cookies.emailCheckerAuth === "IamHuman";
}

/**
 * -------------------------
 * LOGIN
 * -------------------------
 */
app.post("/login", (req, res) => {
  const { password } = req.body || {};

  if (password === "IamHuman") {
    res.cookie("emailCheckerAuth", "IamHuman", {
      sameSite: "Lax",
      path: "/",
      maxAge: 1000 * 60 * 60 * 2,
    });

    return res.json({ status: "OK" });
  }

  return res.status(401).json({ status: "INVALID_PASSWORD" });
});

/**
 * -------------------------
 * SMTP PROBE ENGINE
 * -------------------------
 */
function smtpProbe(mxHost, targetEmail, senderEmail) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: mxHost, port: 25 });

    let buffer = "";
    let step = 0;
    let done = false;

    socket.setEncoding("utf8");
    socket.setTimeout(12000);

    socket.on("connect", () => {
      console.log("TCP CONNECTED to:", mxHost);
    });

    function finish(result) {
      if (done) return;
      done = true;

      try {
        socket.write("QUIT\r\n");
        socket.end();
        socket.destroy();
      } catch {}

      resolve(result);
    }

    socket.on("data", (chunk) => {
      buffer += chunk;
      const lines = buffer.split("\r\n");
      buffer = lines.pop();

      for (const line of lines) {
        const code = line.substring(0, 3);

        if (step === 0 && code === "220") {
          socket.write(`EHLO verify.local\r\n`);
          step++;
        } else if (step === 1 && code === "250") {
          socket.write(`MAIL FROM:<${senderEmail}>\r\n`);
          step++;
        } else if (step === 2 && code === "250") {
          socket.write(`RCPT TO:<${targetEmail}>\r\n`);
          step++;
        } else if (step === 3) {
          if (code === "250") return finish("DELIVERABLE");
          if (["550", "551", "554"].includes(code))
            return finish("UNDELIVERABLE");
          if (["450", "451", "452"].includes(code)) return finish("TEMPORARY");

          return finish("UNKNOWN");
        }
      }
    });

    // 🔥 IMPORTANT: classify network failures properly
    socket.on("timeout", () => finish("NETWORK_TIMEOUT"));
    socket.on("error", () => finish("NETWORK_ERROR"));
  });
}

/**
 * -------------------------
 * VERIFY ROUTE
 * -------------------------
 */
app.post("/verify", async (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ status: "UNAUTHORIZED" });
  }

  const { email } = req.body || {};
  if (!email || !email.includes("@")) {
    return res.status(400).json({ status: "INVALID_EMAIL" });
  }

  const [, domain] = email.split("@");

  try {
    const mxRecords = await dns.resolveMx(domain);

    if (!mxRecords.length) {
      return res.json({ status: "UNDELIVERABLE" });
    }

    const mxHost = mxRecords
      .sort((a, b) => a.priority - b.priority)[0]
      .exchange.replace(/\.$/, "");

    const fake = `probe_${Date.now()}@${domain}`;

    // Catch-all check
    const catchAll = await smtpProbe(mxHost, fake, "verify@local.test");
    const isCatchAll = catchAll === "DELIVERABLE";

    // Real probe
    const result = await smtpProbe(mxHost, email, "verify@local.test");

    /**
     * 🔥 KEY FIX: classify network failures properly
     */
    if (result === "NETWORK_TIMEOUT" || result === "NETWORK_ERROR") {
      return res.json({
        status: "UNKNOWN",
        reason: "SMTP blocked or unreachable at network level",
        confidence: 0.2,
        catchAll: isCatchAll,
      });
    }

    return res.json({
      status: result,
      catchAll: isCatchAll,
    });
  } catch (e) {
    return res.json({
      status: "ERROR",
      reason: e.message,
    });
  }
});

/**
 * -------------------------
 * SERVER
 * -------------------------
 */
app.listen(3030, () => {
  console.log("SMTP verifier running");
});
