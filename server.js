
const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const PLAN_CURRENCY = "BDT";
const DEFAULT_BKASH_RECEIVER_NUMBER = "01746616678";
const DEFAULT_AMR_RECEIVER_NUMBER = "01746616678";
const PAYMENT_METHODS = Object.freeze({
    bkash: {
        label: "bKash",
        receiverNumber: DEFAULT_BKASH_RECEIVER_NUMBER
    },
    amr: {
        label: "AMR",
        receiverNumber: DEFAULT_AMR_RECEIVER_NUMBER
    }
});
const SUBSCRIPTION_PLANS = Object.freeze({
    basic: { name: "Basic", amount: "500.00" },
    gold: { name: "Gold", amount: "1000.00" },
    platinum: { name: "Platinum", amount: "1500.00" },
    diamond: { name: "Diamond", amount: "2000.00" }
});
const SESSION_COOKIE = "cloudline.sid";
const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000;

const PUBLIC_DIR = path.join(__dirname, "public");

app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));
app.use(express.static(PUBLIC_DIR));

// --------------------------------------------------
// In-memory storage
// Data will reset when the server restarts.
// --------------------------------------------------

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, storedHash) {
    try {
        const [algorithm, salt, hash] = storedHash.split("$");

        if (algorithm !== "scrypt" || !salt || !hash) {
            return false;
        }

        const actual = crypto.scryptSync(password, salt, 64);
        const expected = Buffer.from(hash, "hex");

        return (
            actual.length === expected.length &&
            crypto.timingSafeEqual(actual, expected)
        );
    } catch {
        return false;
    }
}

let users = [
    {
        id: 1,
        username: "user",
        passwordHash: hashPassword("password123"),
        role: "user",
        subscriptionEnd: "2027-10-11",
        subscriptionPlan: "platinum"
    },
    {
        id: 2,
        username: "admin",
        passwordHash: hashPassword("admin123"),
        role: "admin",
        subscriptionEnd: "N/A",
        subscriptionPlan: null
    }
];

const sessions = new Map();
const payments = new Map();
const manualPaymentRequests = new Map();

// Public user data never includes password hashes.
function publicUser(user) {
    return {
        id: user.id,
        username: user.username,
        role: user.role,
        subscriptionEnd: user.subscriptionEnd,
        subscriptionPlan: user.subscriptionPlan || null
    };
}

function findUserById(id) {
    return users.find(user => user.id === Number(id));
}

function normalizePaymentMethod(value = "bkash") {
    const method = String(value ?? "").trim().toLowerCase();

    if (method === "amr" || method === "amr-pay" || method === "amrpay") {
        return "amr";
    }

    return "bkash";
}

function getPaymentMethodConfig(method = "bkash") {
    const normalized = normalizePaymentMethod(method);
    return PAYMENT_METHODS[normalized] || PAYMENT_METHODS.bkash;
}

function getPaymentReceiverNumber(method = "bkash") {
    return getPaymentMethodConfig(method).receiverNumber;
}

// --------------------------------------------------
// Session authentication
// HttpOnly cookie + server-side session storage
// --------------------------------------------------

function parseCookies(header = "") {
    const cookies = {};

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) continue;

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        try {
            cookies[key] = decodeURIComponent(value);
        } catch {
            // Ignore malformed cookies.
        }
    }

    return cookies;
}

function createSession(res, userId) {
    const sessionId = crypto.randomBytes(32).toString("hex");

    sessions.set(sessionId, {
        userId,
        expiresAt: Date.now() + SESSION_DURATION
    });

    const secure = process.env.NODE_ENV === "production"
        ? "; Secure"
        : "";

    res.setHeader(
        "Set-Cookie",
        `${SESSION_COOKIE}=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DURATION / 1000}${secure}`
    );
}

function destroySession(req, res) {
    const cookies = parseCookies(req.headers.cookie);
    const sessionId = cookies[SESSION_COOKIE];

    if (sessionId) {
        sessions.delete(sessionId);
    }

    const secure = process.env.NODE_ENV === "production"
        ? "; Secure"
        : "";

    res.setHeader(
        "Set-Cookie",
        `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`
    );
}

app.use((req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    const sessionId = cookies[SESSION_COOKIE];
    const session = sessionId ? sessions.get(sessionId) : null;

    if (session && session.expiresAt > Date.now()) {
        const user = findUserById(session.userId);

        if (user) {
            req.user = user;
            req.sessionId = sessionId;
        } else {
            sessions.delete(sessionId);
        }
    } else if (sessionId && session) {
        sessions.delete(sessionId);
    }

    next();
});

function requireAuth(req, res, next) {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in first."
        });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Admin access required."
        });
    }

    next();
}

// --------------------------------------------------
// Authentication APIs
// --------------------------------------------------

app.get("/api/me", (req, res) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: "Not logged in."
        });
    }

    res.json({
        success: true,
        user: publicUser(req.user)
    });
});

app.post("/api/login", (req, res) => {
    const username =
        typeof req.body?.username === "string"
            ? req.body.username.trim()
            : "";

    const password =
        typeof req.body?.password === "string"
            ? req.body.password
            : "";

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "Username and password are required."
        });
    }

    const user = users.find(
        item => item.username.toLowerCase() === username.toLowerCase()
    );

    if (!user || !verifyPassword(password, user.passwordHash)) {
        return res.status(401).json({
            success: false,
            message: "Invalid username or password."
        });
    }

    // Prevent session fixation by replacing an existing session.
    destroySession(req, res);
    createSession(res, user.id);

    res.json({
        success: true,
        user: publicUser(user)
    });
});

app.post("/api/register", (req, res) => {
    const username =
        typeof req.body?.username === "string"
            ? req.body.username.trim()
            : "";

    const password =
        typeof req.body?.password === "string"
            ? req.body.password
            : "";

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
        return res.status(400).json({
            success: false,
            message:
                "Username must be 3-30 characters using letters, numbers or underscores."
        });
    }

    if (password.length < 8 || password.length > 128) {
        return res.status(400).json({
            success: false,
            message: "Password must be between 8 and 128 characters."
        });
    }

    const alreadyExists = users.some(
        user => user.username.toLowerCase() === username.toLowerCase()
    );

    if (alreadyExists) {
        return res.status(409).json({
            success: false,
            message: "Username already taken."
        });
    }

    const id = users.length
        ? Math.max(...users.map(user => user.id)) + 1
        : 1;

    users.push({
        id,
        username,
        passwordHash: hashPassword(password),
        role: "user",
        subscriptionEnd: "Inactive",
        subscriptionPlan: null
    });

    res.status(201).json({
        success: true,
        message: "Account created successfully. Please log in."
    });
});

app.post("/api/logout", (req, res) => {
    destroySession(req, res);

    res.json({
        success: true,
        message: "Logged out successfully."
    });
});

// --------------------------------------------------
// Subscription APIs
// Direct free renewal is disabled.
// A verified bKash payment is required.
// --------------------------------------------------

app.post("/api/renew", requireAuth, (req, res) => {
    res.status(402).json({
        success: false,
        message: "Please complete the bKash payment to renew your plan."
    });
});

// --------------------------------------------------
// bKash API configuration. The sandbox URL is used unless overridden.
// Set these variables on the server:
// BKASH_USERNAME, BKASH_PASSWORD, BKASH_APP_KEY,
// BKASH_APP_SECRET, APP_BASE_URL, BKASH_BASE_URL (optional)
// --------------------------------------------------

const BKASH_BASE_URL = (
    process.env.BKASH_BASE_URL ||
    "https://tokenized.sandbox.bka.sh/v1.2.0-beta/tokenized/checkout"
).replace(/\/+$/, "");

let cachedToken = null;
let tokenExpiresAt = 0;

function getBkashConfig() {
    const {
        BKASH_USERNAME,
        BKASH_PASSWORD,
        BKASH_APP_KEY,
        BKASH_APP_SECRET
    } = process.env;

    if (
        !BKASH_USERNAME ||
        !BKASH_PASSWORD ||
        !BKASH_APP_KEY ||
        !BKASH_APP_SECRET
    ) {
        return null;
    }

    return {
        username: BKASH_USERNAME,
        password: BKASH_PASSWORD,
        appKey: BKASH_APP_KEY,
        appSecret: BKASH_APP_SECRET
    };
}

async function bkashRequest(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(30000)
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        const error = new Error(
            data.statusMessage || data.message || "bKash API request failed."
        );
        error.status = 502;
        throw error;
    }

    if (data.statusCode && String(data.statusCode) !== "0000") {
        const error = new Error(
            data.statusMessage || "bKash rejected the request."
        );
        error.status = 502;
        throw error;
    }

    return data;
}

async function getBkashToken() {
    const config = getBkashConfig();

    if (!config) {
        const error = new Error(
            "bKash Sandbox credentials are not configured on the server."
        );
        error.status = 503;
        throw error;
    }

    if (cachedToken && Date.now() < tokenExpiresAt) {
        return { token: cachedToken, config };
    }

    const data = await bkashRequest(
        `${BKASH_BASE_URL}/token/grant`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
                username: config.username,
                password: config.password
            },
            body: JSON.stringify({
                app_key: config.appKey,
                app_secret: config.appSecret
            })
        }
    );

    const token = data.id_token || data.idToken;

    if (!token) {
        throw new Error("bKash did not return an access token.");
    }

    cachedToken = token;

    // Refresh before the token's expected expiry.
    const expiresIn = Number(data.expires_in || 3600);
    tokenExpiresAt = Date.now() + Math.max(60, expiresIn - 120) * 1000;

    return { token, config };
}

function bkashHeaders(token, config) {
    return {
        Authorization: token,
        "X-APP-Key": config.appKey,
        "Content-Type": "application/json",
        Accept: "application/json"
    };
}

function getAppBaseUrl(req) {
    const configured = process.env.APP_BASE_URL;

    if (configured) {
        return configured.replace(/\/+$/, "");
    }

    // Local development fallback only.
    if (process.env.NODE_ENV === "production") {
        throw new Error("APP_BASE_URL must be configured for production.");
    }

    return `${req.protocol}://${req.get("host")}`;
}

// Start a bKash checkout for the logged-in user.
app.post("/api/payments/bkash/create", requireAuth, async (req, res) => {
    if (req.user.role !== "user") {
        return res.status(403).json({
            success: false,
            message: "Only user accounts can purchase a plan."
        });
    }

    const planId =
        typeof req.body?.planId === "string"
            ? req.body.planId.toLowerCase()
            : "";
    const plan = SUBSCRIPTION_PLANS[planId];

    if (!plan) {
        return res.status(400).json({
            success: false,
            message: "Choose a valid subscription plan."
        });
    }

    const hasPendingRequest = Array.from(manualPaymentRequests.values()).some(
        paymentRequest =>
            paymentRequest.userId === req.user.id &&
            paymentRequest.status === "PENDING"
    );

    if (hasPendingRequest) {
        return res.status(409).json({
            success: false,
            message: "You already have a payment waiting for admin review."
        });
    }

    try {
        const { token, config } = await getBkashToken();

        const orderId = crypto.randomUUID();
        const invoiceNumber = `CL-${orderId.slice(0, 8)}`;

        const baseUrl = getAppBaseUrl(req);
        const callbackURL = `${baseUrl}/api/payments/bkash/callback`;

        const data = await bkashRequest(`${BKASH_BASE_URL}/create`, {
            method: "POST",
            headers: bkashHeaders(token, config),
            body: JSON.stringify({
                mode: "0011",
                payerReference: String(req.user.id),
                callbackURL,
                amount: plan.amount,
                currency: PLAN_CURRENCY,
                intent: "sale",
                merchantInvoiceNumber: invoiceNumber
            })
        });

        if (!data.paymentID || !data.bkashURL) {
            throw new Error("bKash did not return the checkout details.");
        }

        payments.set(data.paymentID, {
            orderId,
            paymentID: data.paymentID,
            userId: req.user.id,
            planId,
            planName: plan.name,
            amount: plan.amount,
            currency: PLAN_CURRENCY,
            status: "PENDING",
            transactionId: null,
            createdAt: new Date().toISOString()
        });

        res.json({
            success: true,
            paymentID: data.paymentID,
            checkoutURL: data.bkashURL,
            amount: plan.amount,
            currency: PLAN_CURRENCY
        });
    } catch (error) {
        console.error("bKash create payment error:", error.message);

        res.status(error.status || 502).json({
            success: false,
            message: error.status === 503
                ? error.message
                : "Could not start bKash checkout. Please try again."
        });
    }
});

// bKash redirects the customer here after checkout.
// The redirect parameters alone are never trusted as proof of payment.
app.get("/api/payments/bkash/callback", async (req, res) => {
    const paymentID =
        typeof req.query.paymentID === "string"
            ? req.query.paymentID
            : "";

    const callbackStatus =
        typeof req.query.status === "string"
            ? req.query.status.toLowerCase()
            : "";

    const order = payments.get(paymentID);

    if (!order) {
        return res.redirect("/dashboard.html?payment=unknown");
    }

    if (order.status === "COMPLETED") {
        return res.redirect("/dashboard.html?payment=success");
    }

    if (order.paymentRequestId) {
        return res.redirect("/dashboard.html?payment=pending");
    }

    if (callbackStatus !== "success") {
        order.status = "FAILED";
        return res.redirect("/dashboard.html?payment=failed");
    }

    try {
        const { token, config } = await getBkashToken();

        const result = await bkashRequest(`${BKASH_BASE_URL}/execute`, {
            method: "POST",
            headers: bkashHeaders(token, config),
            body: JSON.stringify({ paymentID })
        });

        const transactionStatus = String(
            result.transactionStatus || ""
        ).toLowerCase();

        const amount = Number(result.amount);
        const currency = String(result.currency || "").toUpperCase();

        if (
            transactionStatus !== "completed" ||
            amount !== Number(order.amount) ||
            currency !== order.currency
        ) {
            order.status = "FAILED";
            return res.redirect("/dashboard.html?payment=unverified");
        }

        const user = findUserById(order.userId);

        if (!user) {
            order.status = "FAILED";
            return res.redirect("/dashboard.html?payment=failed");
        }

        const transactionId = String(result.trxID || paymentID).trim().toUpperCase();
        const duplicateTransaction = Array.from(manualPaymentRequests.values()).some(
            paymentRequest => paymentRequest.transactionId === transactionId
        );

        if (duplicateTransaction) {
            order.status = "FAILED";
            return res.redirect("/dashboard.html?payment=duplicate");
        }

        const paymentRequest = {
            id: crypto.randomUUID(),
            userId: order.userId,
            planId: order.planId,
            planName: order.planName,
            paymentMethod: "ONLINE",
            payerNumber: "Online bKash checkout",
            receiverNumber: DEFAULT_BKASH_RECEIVER_NUMBER,
            transactionId,
            paymentID,
            amount: order.amount,
            currency: order.currency,
            status: "PENDING",
            createdAt: new Date().toISOString(),
            decidedAt: null,
            decidedBy: null
        };

        manualPaymentRequests.set(paymentRequest.id, paymentRequest);
        order.paymentRequestId = paymentRequest.id;
        order.transactionId = transactionId;
        order.status = "PENDING_REVIEW";
        order.verifiedAt = new Date().toISOString();

        return res.redirect("/dashboard.html?payment=pending");
    } catch (error) {
        console.error("bKash callback verification error:", error.message);
        order.status = "VERIFY_FAILED";

        return res.redirect("/dashboard.html?payment=verification_failed");
    }
});

// Logged-in users can view their own payment history.
app.get("/api/payments", requireAuth, (req, res) => {
    const history = Array.from(payments.values())
        .filter(payment => payment.userId === req.user.id)
        .map(payment => ({
            orderId: payment.orderId,
            amount: payment.amount,
            currency: payment.currency,
            status: payment.status,
            transactionId: payment.transactionId,
            createdAt: payment.createdAt,
            completedAt: payment.completedAt || null
        }));

    res.json({ success: true, payments: history });
});

app.get("/api/payments/mine", requireAuth, (req, res) => {
    const requests = Array.from(manualPaymentRequests.values())
        .filter(paymentRequest => paymentRequest.userId === req.user.id)
        .sort((first, second) => second.createdAt.localeCompare(first.createdAt))
        .map(paymentRequest => ({
            id: paymentRequest.id,
            amount: paymentRequest.amount,
            currency: paymentRequest.currency,
            status: paymentRequest.status,
            paymentMethod: paymentRequest.paymentMethod || "MANUAL",
            createdAt: paymentRequest.createdAt,
            decidedAt: paymentRequest.decidedAt
        }));

    res.json({ success: true, requests });
});

function respondWithPaymentInstructions(req, res, methodOverride = "bkash") {
    if (req.user.role !== "user") {
        return res.status(403).json({
            success: false,
            message: "Only user accounts can purchase a plan."
        });
    }

    const method = normalizePaymentMethod(
        req.query?.method || req.query?.paymentMethod || methodOverride
    );
    const config = getPaymentMethodConfig(method);
    const receiverNumber = config.receiverNumber;

    if (!receiverNumber || !/^01[3-9]\d{8}$/.test(receiverNumber)) {
        return res.status(503).json({
            success: false,
            message: `The ${config.label} receiving number is not configured. Contact the administrator.`
        });
    }

    const planId =
        typeof req.query.plan === "string"
            ? req.query.plan.toLowerCase()
            : "";
    const plan = SUBSCRIPTION_PLANS[planId];

    if (!plan) {
        return res.status(400).json({
            success: false,
            message: "Choose a valid subscription plan."
        });
    }

    return res.json({
        success: true,
        paymentMethod: method,
        paymentMethodLabel: config.label,
        receiverNumber,
        amount: plan.amount,
        currency: PLAN_CURRENCY,
        planId,
        planName: plan.name
    });
}

app.get("/api/payments/instructions", requireAuth, respondWithPaymentInstructions);
app.get("/api/payments/bkash/instructions", requireAuth, (req, res) => respondWithPaymentInstructions(req, res, "bkash"));
app.get("/api/payments/amr/instructions", requireAuth, (req, res) => respondWithPaymentInstructions(req, res, "amr"));

function submitManualPaymentRequest(req, res, methodOverride = "bkash") {
    if (req.user.role !== "user") {
        return res.status(403).json({
            success: false,
            message: "Only user accounts can purchase a plan."
        });
    }

    const method = normalizePaymentMethod(
        req.body?.paymentMethod || methodOverride
    );
    const config = getPaymentMethodConfig(method);
    const receiverNumber = getPaymentReceiverNumber(method);
    const planId =
        typeof req.body?.planId === "string"
            ? req.body.planId.toLowerCase()
            : "";
    const plan = SUBSCRIPTION_PLANS[planId];
    const payerNumber =
        typeof req.body?.payerNumber === "string"
            ? req.body.payerNumber.trim()
            : "";
    const transactionId =
        typeof req.body?.transactionId === "string"
            ? req.body.transactionId.trim().toUpperCase()
            : "";

    if (!receiverNumber || !/^01[3-9]\d{8}$/.test(receiverNumber)) {
        return res.status(503).json({
            success: false,
            message: `The ${config.label} receiving number is not configured. Contact the administrator.`
        });
    }

    if (!plan) {
        return res.status(400).json({
            success: false,
            message: "Choose a valid subscription plan."
        });
    }

    if (!/^01[3-9]\d{8}$/.test(payerNumber)) {
        return res.status(400).json({
            success: false,
            message: `Enter a valid 11-digit Bangladeshi ${config.label} number.`
        });
    }

    if (!/^[A-Z0-9]{6,20}$/.test(transactionId)) {
        return res.status(400).json({
            success: false,
            message: `Enter a valid ${config.label} transaction ID (6-20 letters or numbers).`
        });
    }

    const hasPendingRequest = Array.from(manualPaymentRequests.values()).some(
        paymentRequest =>
            paymentRequest.userId === req.user.id &&
            paymentRequest.status === "PENDING"
    );

    if (hasPendingRequest) {
        return res.status(409).json({
            success: false,
            message: "You already have a payment request waiting for admin review."
        });
    }

    const duplicateTransaction = Array.from(manualPaymentRequests.values()).some(
        paymentRequest => paymentRequest.transactionId === transactionId
    );

    if (duplicateTransaction) {
        return res.status(409).json({
            success: false,
            message: "This transaction ID has already been submitted."
        });
    }

    const paymentRequest = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        planId,
        planName: plan.name,
        paymentMethod: method,
        payerNumber,
        receiverNumber,
        transactionId,
        amount: plan.amount,
        currency: PLAN_CURRENCY,
        status: "PENDING",
        createdAt: new Date().toISOString(),
        decidedAt: null,
        decidedBy: null
    };

    manualPaymentRequests.set(paymentRequest.id, paymentRequest);

    return res.status(201).json({
        success: true,
        message: "Payment request submitted. Your subscription will activate after admin approval.",
        request: {
            id: paymentRequest.id,
            status: paymentRequest.status,
            createdAt: paymentRequest.createdAt
        }
    });
}

app.post("/api/payments/manual-request", requireAuth, (req, res) => submitManualPaymentRequest(req, res, req.body?.paymentMethod));
app.post("/api/payments/bkash/manual-request", requireAuth, (req, res) => submitManualPaymentRequest(req, res, "bkash"));
app.post("/api/payments/amr/manual-request", requireAuth, (req, res) => submitManualPaymentRequest(req, res, "amr"));

// --------------------------------------------------
// Admin APIs
// Every route requires a server-verified admin session.
// --------------------------------------------------

app.get("/api/admin/users", requireAdmin, (req, res) => {
    const list = users
        .filter(user => user.role === "user")
        .map(publicUser);

    res.json({ success: true, users: list });
});

app.post("/api/admin/change-password", requireAdmin, (req, res) => {
    const currentPassword =
        typeof req.body?.currentPassword === "string"
            ? req.body.currentPassword
            : "";
    const newPassword =
        typeof req.body?.newPassword === "string"
            ? req.body.newPassword
            : "";

    if (!currentPassword || !newPassword) {
        return res.status(400).json({
            success: false,
            message: "Enter your current password and a new password."
        });
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
        return res.status(400).json({
            success: false,
            message: "New password must be between 8 and 128 characters."
        });
    }

    if (!verifyPassword(currentPassword, req.user.passwordHash)) {
        return res.status(401).json({
            success: false,
            message: "Current password is incorrect."
        });
    }

    if (verifyPassword(newPassword, req.user.passwordHash)) {
        return res.status(400).json({
            success: false,
            message: "Choose a new password different from your current password."
        });
    }

    req.user.passwordHash = hashPassword(newPassword);

    for (const [sessionId, session] of sessions.entries()) {
        if (session.userId === req.user.id && sessionId !== req.sessionId) {
            sessions.delete(sessionId);
        }
    }

    res.json({
        success: true,
        message: "Admin password changed successfully."
    });
});

app.get("/api/admin/payment-requests", requireAdmin, (req, res) => {
    const requests = Array.from(manualPaymentRequests.values())
        .sort((first, second) => second.createdAt.localeCompare(first.createdAt))
        .map(paymentRequest => {
            const user = findUserById(paymentRequest.userId);

            return {
                id: paymentRequest.id,
                username: user?.username || "Deleted user",
                planName: paymentRequest.planName,
                planId: paymentRequest.planId,
                paymentMethod: paymentRequest.paymentMethod || "MANUAL",
                payerNumber: paymentRequest.payerNumber,
                receiverNumber: paymentRequest.receiverNumber,
                transactionId: paymentRequest.transactionId,
                amount: paymentRequest.amount,
                currency: paymentRequest.currency,
                status: paymentRequest.status,
                createdAt: paymentRequest.createdAt,
                decidedAt: paymentRequest.decidedAt,
                decidedBy: paymentRequest.decidedBy
            };
        });

    res.json({ success: true, requests });
});

app.post("/api/admin/payment-requests/:id/approve", requireAdmin, (req, res) => {
    const paymentRequest = manualPaymentRequests.get(req.params.id);

    if (!paymentRequest) {
        return res.status(404).json({
            success: false,
            message: "Payment request not found."
        });
    }

    if (paymentRequest.status !== "PENDING") {
        return res.status(409).json({
            success: false,
            message: "This payment request has already been reviewed."
        });
    }

    const user = findUserById(paymentRequest.userId);

    if (!user || user.role !== "user") {
        return res.status(404).json({
            success: false,
            message: "The account for this payment request no longer exists."
        });
    }

    const now = new Date();
    const currentEnd = new Date(`${user.subscriptionEnd}T00:00:00Z`);
    const startDate =
        !Number.isNaN(currentEnd.getTime()) && currentEnd > now
            ? currentEnd
            : now;

    startDate.setUTCFullYear(startDate.getUTCFullYear() + 1);
    user.subscriptionEnd = startDate.toISOString().slice(0, 10);
    user.subscriptionPlan = paymentRequest.planId;
    paymentRequest.status = "APPROVED";
    paymentRequest.decidedAt = new Date().toISOString();
    paymentRequest.decidedBy = req.user.username;

    if (paymentRequest.paymentID) {
        const payment = payments.get(paymentRequest.paymentID);
        if (payment) {
            payment.status = "COMPLETED";
            payment.completedAt = paymentRequest.decidedAt;
        }
    }

    res.json({
        success: true,
        message: "Payment approved and subscription activated.",
        user: publicUser(user)
    });
});

app.post("/api/admin/payment-requests/:id/reject", requireAdmin, (req, res) => {
    const paymentRequest = manualPaymentRequests.get(req.params.id);

    if (!paymentRequest) {
        return res.status(404).json({
            success: false,
            message: "Payment request not found."
        });
    }

    if (paymentRequest.status !== "PENDING") {
        return res.status(409).json({
            success: false,
            message: "This payment request has already been reviewed."
        });
    }

    paymentRequest.status = "REJECTED";
    paymentRequest.decidedAt = new Date().toISOString();
    paymentRequest.decidedBy = req.user.username;

    res.json({
        success: true,
        message: "Payment request rejected."
    });
});

app.post("/api/admin/extend", requireAdmin, (req, res) => {
    const user = findUserById(req.body?.userId);

    if (!user || user.role !== "user") {
        return res.status(404).json({
            success: false,
            message: "User not found."
        });
    }

    const now = new Date();
    const currentEnd = new Date(`${user.subscriptionEnd}T00:00:00Z`);

    const startDate =
        !Number.isNaN(currentEnd.getTime()) && currentEnd > now
            ? currentEnd
            : now;

    startDate.setUTCFullYear(startDate.getUTCFullYear() + 1);
    user.subscriptionEnd = startDate.toISOString().slice(0, 10);

    res.json({
        success: true,
        message: "Subscription extended by an admin.",
        user: publicUser(user)
    });
});

app.post("/api/admin/reduce", requireAdmin, (req, res) => {
    const user = findUserById(req.body?.userId);

    if (!user || user.role !== "user") {
        return res.status(404).json({
            success: false,
            message: "User not found."
        });
    }

    const currentEnd = new Date(`${user.subscriptionEnd}T00:00:00Z`);

    if (Number.isNaN(currentEnd.getTime())) {
        return res.status(409).json({
            success: false,
            message: "A cancelled subscription cannot be reduced."
        });
    }

    currentEnd.setUTCFullYear(currentEnd.getUTCFullYear() - 1);
    user.subscriptionEnd = currentEnd.toISOString().slice(0, 10);

    res.json({
        success: true,
        message: "Subscription reduced by one year.",
        user: publicUser(user)
    });
});

app.post("/api/admin/cancel", requireAdmin, (req, res) => {
    const user = findUserById(req.body?.userId);

    if (!user || user.role !== "user") {
        return res.status(404).json({
            success: false,
            message: "User not found."
        });
    }

    user.subscriptionEnd = "Cancelled";

    res.json({
        success: true,
        message: "Subscription cancelled.",
        user: publicUser(user)
    });
});

app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const user = findUserById(id);

    if (!user || user.role !== "user") {
        return res.status(404).json({
            success: false,
            message: "User not found."
        });
    }

    users = users.filter(item => item.id !== id);

    // Revoke all sessions belonging to the deleted user.
    for (const [sessionId, session] of sessions.entries()) {
        if (session.userId === id) {
            sessions.delete(sessionId);
        }
    }

    // Retain payment records as a basic in-memory audit trail.
    res.json({
        success: true,
        message: "User deleted successfully."
    });
});

app.get("/api/admin/payments", requireAdmin, (req, res) => {
    const history = Array.from(payments.values()).map(payment => ({
        orderId: payment.orderId,
        userId: payment.userId,
        amount: payment.amount,
        currency: payment.currency,
        status: payment.status,
        transactionId: payment.transactionId,
        createdAt: payment.createdAt,
        completedAt: payment.completedAt || null
    }));

    res.json({ success: true, payments: history });
});

// --------------------------------------------------
// Error handling
// --------------------------------------------------

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        message: "API endpoint not found."
    });
});

app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);

    if (error instanceof SyntaxError && error.status === 400) {
        return res.status(400).json({
            success: false,
            message: "Invalid JSON request body."
        });
    }

    console.error("Server error:", error.message);

    res.status(500).json({
        success: false,
        message: "An unexpected server error occurred."
    });
});

app.listen(PORT, () => {
    console.log(`Cloudline Demo is running at http://localhost:${PORT}`);
    console.log("Default demo accounts:");
    console.log("User: user / password123");
    console.log("Admin: admin / admin123");
    console.log("Plan price: ৳2,000.00 BDT");
    console.log("Manual bKash payments: configured");
});
