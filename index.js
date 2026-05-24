const express = require("express");
const dns = require("dns").promises;
const net = require("net");
const path = require("path");
const morgan = require("morgan");

const app = express();
app.use(morgan("combined"));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function sanitizeString(value) {
  return value
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, "")
    .trim();
}

function enforceStringBody(req, res, next) {
  if (req.method === "POST" && req.is("application/json")) {
    if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
      return res.status(400).json({
        status: "INVALID_REQUEST",
        message: "Request body must be a JSON object with string values.",
      });
    }

    for (const [key, value] of Object.entries(req.body)) {
      if (typeof value !== "string") {
        return res.status(400).json({
          status: "INVALID_REQUEST",
          message: `Request field \"${key}\" must be a string.`,
        });
      }
      req.body[key] = sanitizeString(value);
    }
  }

  next();
}

app.use(enforceStringBody);

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  return raw.split(";").reduce((cookies, cookie) => {
    const [name, ...rest] = cookie.trim().split("=");
    if (!name) return cookies;
    cookies[name] = decodeURIComponent(rest.join("="));
    return cookies;
  }, {});
}

app.post("/login", (req, res) => {
  const { password } = req.body || {};

  if (typeof password !== "string") {
    return res.status(400).json({
      status: "INVALID_REQUEST",
      message: "Password must be a string.",
    });
  }

  if (password === "IamHuman") {
    res.cookie("emailCheckerAuth", "IamHuman", {
      sameSite: "Lax",
      path: "/",
      maxAge: 1000 * 60 * 60 * 2,
    });
    return res.json({ status: "OK" });
  }

  return res.status(401).json({ status: "INVALID_PASSWORD", message: "Password is incorrect." });
});

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  return cookies.emailCheckerAuth === "IamHuman";
}

// Helper: Performs a raw interactive SMTP handshake on Port 25
function checkSmtpInbox(mxServer, email, senderMail) {
  return new Promise((resolve) => {
    const socket = net.createConnection(25, mxServer);
    let step = 0;
    let resolved = false;

    socket.setTimeout(6000); // 6-second timeout protective boundary
    socket.setEncoding("ascii");

    const finish = (result) => {
      if (!resolved) {
        resolved = true;
        socket.write("QUIT\r\n");
        socket.end();
        socket.destroy();
        resolve(result);
      }
    };

    socket.on("data", (data) => {
      const code = data.substring(0, 3);

      if (step === 0 && code === "220") {
        socket.write(`HELO outlook.com\r\n`);
        step++;
      } else if (step === 1 && code === "250") {
        socket.write(`MAIL FROM:<${senderMail}>\r\n`);
        step++;
      } else if (step === 2 && code === "250") {
        socket.write(`RCPT TO:<${email}>\r\n`);
        step++;
      } else if (step === 3) {
        if (code === "250") {
          finish("DELIVERABLE");
        } else if (code === "550" || code === "551" || code === "554") {
          finish("UNDELIVERABLE");
        } else {
          finish("UNKNOWN_OR_BLOCKED");
        }
      }
    });

    socket.on("error", () => finish("FIREWALL_BLOCKED"));
    socket.on("timeout", () => finish("TIMEOUT"));
  });
}

// THE SINGLE CORE VERIFICATION ENDPOINT
app.post("/verify", async (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({
      status: "UNAUTHORIZED",
      message: "Login required to use the email verification feature.",
    });
  }

  const { email } = req.body;

  if (typeof email !== "string" || !email.includes("@")) {
    return res.status(400).json({
      status: "INVALID_FORMAT",
      message: "Provide a valid email address string.",
    });
  }

  const [username, domain] = email.split("@");
  // Using outlook.com sender to safely bypass corporate SPF restrictions without exposing monesize.com
  const neutralSender = "verification@outlook.com";

  try {
    // 1. DNS MX Record Lookup
    const mxRecords = await dns.resolveMx(domain);
    if (!mxRecords || mxRecords.length === 0) {
      return res.json({
        status: "UNDELIVERABLE",
        reason: "No active MX records found for this domain.",
      });
    }

    // Sort by priority (lowest weight wins)
    const primaryMx = mxRecords.sort((a, b) => a.priority - b.priority)[0]
      .exchange;

    // 2. Catch-All Verification (Test a non-existent fake box first)
    const fakeInbox = `monesize_test_probe_${Math.floor(Math.random() * 100000)}@${domain}`;
    const catchAllCheck = await checkSmtpInbox(
      primaryMx,
      fakeInbox,
      neutralSender,
    );

    if (catchAllCheck === "DELIVERABLE") {
      return res.json({
        status: "RISK_CATCH_ALL",
        reason:
          "The target mail server accepts all email addresses blindly. Direct delivery cannot be fully guaranteed.",
      });
    }

    // 3. Real Target Handshake Execution
    const result = await checkSmtpInbox(primaryMx, email, neutralSender);

    return res.json({ status: result });
  } catch (error) {
    if (error.code === "ENOTFOUND" || error.code === "NODATA") {
      return res.json({
        status: "UNDELIVERABLE",
        reason: "The target domain does not exist.",
      });
    }
    return res.json({ status: "UNKNOWN_OR_BLOCKED", reason: error.message });
  }
});

// Start isolated internal server
const PORT = process.env.PORT || 3030;
app.listen(PORT, () => {
  console.log(`🚀 Isolated Email Verifier active on http://localhost:${PORT}`);
});
