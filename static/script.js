const SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "bank",
    "update",
    "secure",
    "password",
];

const URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
];

const HISTORY_STORAGE_KEY = "cyber_guard_scan_history_v1";
const RING_CIRCUMFERENCE = 2 * Math.PI * 50;

/* ---------------- URL Scanner Elements ---------------- */
const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");
const errorBanner = document.getElementById("errorBanner");
const resultPanel = document.getElementById("resultPanel");
const scoreArc = document.getElementById("scoreArc");
const scoreValue = document.getElementById("scoreValue");
const statusBadge = document.getElementById("statusBadge");
const engineTag = document.getElementById("engineTag");
const resultHeading = document.getElementById("result");
const resultUrl = document.getElementById("resultUrl");
const resultMeta = document.getElementById("resultMeta");
const reasonsList = document.getElementById("reasonsList");
const checksGrid = document.getElementById("checksGrid");
const historySection = document.getElementById("historySection");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

function isIpAddress(host) {
    const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    const cleanHost = host.replace(/^\[|\]$/g, "");
    return ipv4.test(cleanHost) || (cleanHost.includes(":") && /^[0-9a-fA-F:]+$/.test(cleanHost));
}

function analyzeUrlClientFallback(rawUrl) {
    const url = (rawUrl || "").trim();
    if (!url) {
        return { error: "Invalid URL: please enter a URL to scan." };
    }
    if (url.length > 2048) {
        return { error: "URL is too long (maximum 2048 characters)." };
    }

    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return {
            error: "Please enter a complete URL starting with http:// or https:// (e.g., https://example.com).",
        };
    }

    const scheme = parsed.protocol.replace(":", "").toLowerCase();
    if ((scheme !== "http" && scheme !== "https") || !parsed.hostname) {
        return {
            error: "Please enter a complete URL starting with http:// or https:// (e.g., https://example.com).",
        };
    }

    let score = 0;
    const reasons = [];
    const checks = [];
    const host = parsed.hostname.toLowerCase();
    const pathAndQuery = (parsed.pathname || "") + (parsed.search || "");

    if (scheme === "http") {
        score += 10;
        reasons.push("Uses HTTP instead of HTTPS (+10)");
        checks.push({ name: "Protocol Security", status: "warn", detail: "Unencrypted HTTP" });
    } else {
        checks.push({ name: "Protocol Security", status: "pass", detail: "HTTPS encryption" });
    }

    const isIp = isIpAddress(host);
    if (isIp) {
        score += 25;
        reasons.push("Uses an IP address instead of a domain name (+25)");
        checks.push({ name: "Host Identity", status: "warn", detail: `Raw IP (${host})` });
    } else {
        checks.push({ name: "Host Identity", status: "pass", detail: host });
    }

    const lowerUrl = url.toLowerCase();
    const matchedKeywords = [];
    for (const word of SUSPICIOUS_KEYWORDS) {
        if (lowerUrl.includes(word)) {
            score += 10;
            matchedKeywords.push(word);
            reasons.push(`Suspicious keyword detected: '${word}' (+10)`);
        }
    }
    checks.push(
        matchedKeywords.length
            ? { name: "Keyword Scan", status: "warn", detail: matchedKeywords.join(", ") }
            : { name: "Keyword Scan", status: "pass", detail: "No flagged keywords" }
    );

    if (url.length > 75) {
        score += 15;
        reasons.push(`Unusually long URL (${url.length} characters > 75) (+15)`);
        checks.push({ name: "URL Length", status: "warn", detail: `${url.length} chars` });
    } else {
        checks.push({ name: "URL Length", status: "pass", detail: `${url.length} chars` });
    }

    if (!isIp && host) {
        const parts = host.split(".").filter(Boolean);
        const subdomainCount = Math.max(0, parts.length - 2);
        if (parts.length > 3) {
            score += 15;
            reasons.push(`Excessive subdomains detected (${subdomainCount} subdomains) (+15)`);
            checks.push({ name: "Subdomain Depth", status: "warn", detail: `${subdomainCount} subdomains` });
        } else {
            checks.push({ name: "Subdomain Depth", status: "pass", detail: `${subdomainCount} subdomain(s)` });
        }
    } else {
        checks.push({ name: "Subdomain Depth", status: "info", detail: "N/A for IP host" });
    }

    const isShortener = URL_SHORTENERS.some(
        (shortener) => host === shortener || host.endsWith("." + shortener)
    );
    if (isShortener) {
        score += 20;
        reasons.push(`Uses a URL shortener service (${host}) (+20)`);
        checks.push({ name: "URL Shortener", status: "warn", detail: host });
    } else {
        checks.push({ name: "URL Shortener", status: "pass", detail: "Direct domain" });
    }

    const symbolFlags = [];
    if (url.includes("@")) {
        score += 20;
        symbolFlags.push("contains '@'");
        reasons.push("Contains '@' symbol which can mask destination (+20)");
    }
    if (host.includes("xn--")) {
        score += 20;
        symbolFlags.push("punycode 'xn--'");
        reasons.push("Uses Punycode ('xn--') which may indicate lookalike domain (+20)");
    }
    if (pathAndQuery.includes("//")) {
        score += 10;
        symbolFlags.push("embedded '//' in path");
        reasons.push("Contains '//' redirect pattern in URL path (+10)");
    }
    const encodedMatches = url.match(/%[0-9a-fA-F]{2}/g) || [];
    if (encodedMatches.length >= 2) {
        score += 10;
        symbolFlags.push(`${encodedMatches.length} encoded sequences`);
        reasons.push(`Contains multiple URL-encoded characters (${encodedMatches.length}) (+10)`);
    }
    if ((host.match(/-/g) || []).length >= 3) {
        score += 10;
        symbolFlags.push("excessive hyphens in host");
        reasons.push("Domain contains excessive hyphens (+10)");
    }

    checks.push(
        symbolFlags.length
            ? { name: "Symbols & Encoding", status: "warn", detail: symbolFlags.join(", ") }
            : { name: "Symbols & Encoding", status: "pass", detail: "Clean syntax" }
    );

    score = Math.min(score, 100);
    let status = "No Obvious Warning Signs";
    if (score >= 50) {
        status = "Suspicious";
    } else if (score >= 20) {
        status = "Needs Verification";
    }

    return {
        url,
        score,
        status,
        reasons,
        checks,
        meta: {
            scheme: scheme.toUpperCase(),
            host,
            length: url.length,
        },
        _engine: "Client-side Preview Mode",
    };
}

function getStatusClass(status) {
    if (status === "Suspicious") return "danger";
    if (status === "Needs Verification") return "warn";
    return "safe";
}

function getGaugeColor(statusClass) {
    if (statusClass === "danger") return "#ef4444";
    if (statusClass === "warn") return "#f59e0b";
    return "#10b981";
}

function renderResult(result) {
    errorBanner.classList.add("hidden");
    resultPanel.classList.remove("hidden");

    const score = Number(result.score) || 0;
    const status = result.status || "No Obvious Warning Signs";
    const statusClass = getStatusClass(status);

    scoreValue.textContent = String(score);
    const offset = RING_CIRCUMFERENCE * (1 - score / 100);
    scoreArc.style.strokeDasharray = String(RING_CIRCUMFERENCE);
    scoreArc.style.strokeDashoffset = String(offset);
    scoreArc.style.stroke = getGaugeColor(statusClass);

    statusBadge.className = `status-badge status-${statusClass}`;
    statusBadge.textContent = status;
    engineTag.textContent = result._engine || "Security Engine";
    resultHeading.textContent = status;
    resultUrl.textContent = result.url || urlInput.value.trim();

    resultMeta.innerHTML = "";
    if (result.meta) {
        const metaItems = [
            `Scheme: ${result.meta.scheme}`,
            `Host: ${result.meta.host}`,
            `Length: ${result.meta.length} chars`,
        ];
        for (const text of metaItems) {
            const pill = document.createElement("span");
            pill.className = "meta-pill";
            pill.textContent = text;
            resultMeta.appendChild(pill);
        }
    }

    reasonsList.innerHTML = "";
    if (Array.isArray(result.reasons) && result.reasons.length > 0) {
        for (const reason of result.reasons) {
            const li = document.createElement("li");
            li.textContent = reason;
            reasonsList.appendChild(li);
        }
    } else {
        const li = document.createElement("li");
        li.className = "no-issues";
        li.textContent = "No suspicious URL patterns triggered across the 7 heuristic checks.";
        reasonsList.appendChild(li);
    }

    checksGrid.innerHTML = "";
    if (Array.isArray(result.checks)) {
        for (const check of result.checks) {
            const item = document.createElement("div");
            item.className = "check-item";

            const top = document.createElement("div");
            top.className = "check-item-top";

            const label = document.createElement("span");
            label.textContent = check.name;

            const dot = document.createElement("span");
            dot.className = `check-dot dot-${check.status || "info"}`;

            top.appendChild(label);
            top.appendChild(dot);

            const detail = document.createElement("span");
            detail.className = "check-detail";
            detail.title = check.detail;
            detail.textContent = check.detail;

            item.appendChild(top);
            item.appendChild(detail);
            checksGrid.appendChild(item);
        }
    }

    saveToHistory({
        url: result.url || urlInput.value.trim(),
        score,
        status,
    });
}

function showError(message) {
    resultPanel.classList.add("hidden");
    errorBanner.textContent = message;
    errorBanner.classList.remove("hidden");
}

function loadHistory() {
    try {
        const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
        return raw ? JSON.parse(raw) : [];
    } catch {
        return [];
    }
}

function saveToHistory(entry) {
    const history = loadHistory().filter((item) => item.url !== entry.url);
    history.unshift(entry);
    const trimmed = history.slice(0, 6);
    try {
        localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(trimmed));
    } catch {
        // Ignore storage errors in restricted modes
    }
    renderHistory(trimmed);
}

function renderHistory(items = loadHistory()) {
    if (!items.length) {
        historySection.classList.add("hidden");
        historyList.innerHTML = "";
        return;
    }

    historySection.classList.remove("hidden");
    historyList.innerHTML = "";

    for (const item of items) {
        const li = document.createElement("li");
        li.className = "history-item";

        const urlSpan = document.createElement("span");
        urlSpan.className = "history-url";
        urlSpan.textContent = item.url;
        urlSpan.title = item.url;

        const right = document.createElement("div");
        right.className = "history-right";

        const badge = document.createElement("span");
        badge.className = `status-badge status-${getStatusClass(item.status)}`;
        badge.textContent = item.status;

        const scoreSpan = document.createElement("span");
        scoreSpan.className = "history-score";
        scoreSpan.textContent = `${item.score}/100`;

        right.appendChild(badge);
        right.appendChild(scoreSpan);
        li.appendChild(urlSpan);
        li.appendChild(right);
        historyList.appendChild(li);
    }
}

async function scanURL() {
    const url = urlInput.value.trim();
    if (!url) {
        showError("Please enter a URL to scan (e.g., https://example.com).");
        return;
    }

    scanBtn.disabled = true;
    scanBtn.classList.add("loading");
    errorBanner.classList.add("hidden");

    try {
        let result;
        if (window.location.protocol === "file:") {
            result = analyzeUrlClientFallback(url);
        } else {
            try {
                const response = await fetch("/scan", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ url }),
                });

                const contentType = response.headers.get("content-type") || "";
                if (!contentType.includes("application/json")) {
                    result = analyzeUrlClientFallback(url);
                } else {
                    result = await response.json();
                    if (!response.ok) {
                        showError(result.error || "Unable to analyze URL.");
                        return;
                    }
                }
            } catch {
                result = analyzeUrlClientFallback(url);
            }
        }

        if (result.error) {
            showError(result.error);
            return;
        }

        renderResult(result);
    } finally {
        scanBtn.disabled = false;
        scanBtn.classList.remove("loading");
    }
}

scanForm.addEventListener("submit", (event) => {
    event.preventDefault();
    scanURL();
});

clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
    errorBanner.classList.add("hidden");
    resultPanel.classList.add("hidden");
});

for (const chip of document.querySelectorAll(".sample-chip")) {
    chip.addEventListener("click", () => {
        urlInput.value = chip.dataset.url || "";
        scanURL();
    });
}

clearHistoryBtn.addEventListener("click", () => {
    try {
        localStorage.removeItem(HISTORY_STORAGE_KEY);
    } catch {
        // Ignore storage errors
    }
    renderHistory([]);
});

renderHistory();

/* ---------------- Password Strength Checker ---------------- */
const passwordInput = document.getElementById("passwordInput");
const togglePasswordBtn = document.getElementById("togglePasswordBtn");
const generatePasswordBtn = document.getElementById("generatePasswordBtn");
const copyPasswordBtn = document.getElementById("copyPasswordBtn");
const passwordStrengthBadge = document.getElementById("passwordStrengthBadge");
const passwordScoreText = document.getElementById("passwordScoreText");
const pwLengthMetric = document.getElementById("pwLengthMetric");
const pwEntropyMetric = document.getElementById("pwEntropyMetric");
const pwCrackMetric = document.getElementById("pwCrackMetric");
const passwordAdviceList = document.getElementById("passwordAdviceList");
const passwordChecklist = document.getElementById("passwordChecklist");
const strengthSegments = Array.from(document.querySelectorAll(".strength-segment"));

const COMMON_WEAK_FRAGMENTS = [
    "password",
    "123456",
    "12345",
    "qwerty",
    "admin",
    "welcome",
    "letmein",
    "abc123",
    "iloveyou",
    "pass123",
];

function hasSequentialOrRepeatedChars(pw) {
    if (!pw) return false;
    if (/(.)\1{2,}/.test(pw)) return true;
    const lower = pw.toLowerCase();
    for (const frag of COMMON_WEAK_FRAGMENTS) {
        if (lower.includes(frag)) return true;
    }
    const sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm"];
    for (const seq of sequences) {
        for (let i = 0; i <= seq.length - 4; i++) {
            const sub = seq.slice(i, i + 4);
            if (lower.includes(sub) || lower.includes([...sub].reverse().join(""))) {
                return true;
            }
        }
    }
    return false;
}

function formatCrackTime(entropyBits) {
    if (entropyBits <= 0) return "—";
    const guessesPerSec = 1e10; // 10 billion guesses/sec offline GPU benchmark
    const seconds = Math.pow(2, Math.max(0, entropyBits - 1)) / guessesPerSec;
    if (seconds < 1) return "Instant";
    if (seconds < 60) return `${Math.round(seconds)} sec`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 86400 * 365) return `${Math.round(seconds / 86400)} days`;
    const years = seconds / (86400 * 365.25);
    if (years < 1000) return `${Math.round(years)} years`;
    if (years < 1e6) return `${Math.round(years / 1000)}k years`;
    if (years < 1e9) return `${Math.round(years / 1e6)}M years`;
    return "Centuries+";
}

function evaluatePassword(pw) {
    const length = pw.length;
    const hasLower = /[a-z]/.test(pw);
    const hasUpper = /[A-Z]/.test(pw);
    const hasNumber = /\d/.test(pw);
    const hasSymbol = /[^A-Za-z0-9]/.test(pw);
    const hasCommonPattern = hasSequentialOrRepeatedChars(pw);

    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNumber) poolSize += 10;
    if (hasSymbol) poolSize += 32;

    const rawEntropy = length > 0 && poolSize > 0 ? Math.round(length * Math.log2(poolSize)) : 0;
    const effectiveEntropy = hasCommonPattern ? Math.max(0, rawEntropy - 22) : rawEntropy;

    let score = 0;
    if (length >= 8) score += 15;
    if (length >= 12) score += 20;
    if (length >= 16) score += 10;
    if (hasLower) score += 10;
    if (hasUpper) score += 12;
    if (hasNumber) score += 13;
    if (hasSymbol) score += 15;
    if (length > 0 && !hasCommonPattern) score += 5;
    if (hasCommonPattern) score = Math.max(5, score - 25);
    if (length > 0 && length < 6) score = Math.min(score, 20);
    score = Math.min(100, Math.max(0, score));

    const rules = {
        length: length >= 12,
        upper: hasUpper,
        lower: hasLower,
        number: hasNumber,
        symbol: hasSymbol,
        pattern: length > 0 && !hasCommonPattern,
    };

    const advice = [];
    if (!length) {
        advice.push("Use at least 12 characters combining uppercase, lowercase, numbers, and symbols.");
    } else {
        if (length < 12) advice.push(`Increase length to at least 12 characters (currently ${length}).`);
        if (!hasUpper) advice.push("Add uppercase letters (A–Z) to expand character variety.");
        if (!hasLower) advice.push("Add lowercase letters (a–z).");
        if (!hasNumber) advice.push("Include numeric digits (0–9).");
        if (!hasSymbol) advice.push("Add special characters such as ! @ # $ % & *.");
        if (hasCommonPattern) advice.push("Avoid dictionary words, keyboard runs (qwerty), or repeated sequences (1234, aaa).");
        if (advice.length === 0) advice.push("Strong password structure. Avoid reusing it across different accounts and enable 2FA.");
    }

    let label = "Enter a password";
    let statusClass = "neutral";
    let activeSegments = 0;

    if (length > 0) {
        if (score >= 80) {
            label = "Very Strong";
            statusClass = "safe";
            activeSegments = 4;
        } else if (score >= 60) {
            label = "Strong";
            statusClass = "info";
            activeSegments = 3;
        } else if (score >= 35) {
            label = "Fair";
            statusClass = "warn";
            activeSegments = 2;
        } else {
            label = "Weak";
            statusClass = "danger";
            activeSegments = 1;
        }
    }

    return {
        length,
        entropy: effectiveEntropy,
        crackTime: formatCrackTime(effectiveEntropy),
        score,
        label,
        statusClass,
        activeSegments,
        rules,
        advice,
    };
}

function updatePasswordUI() {
    const pw = passwordInput.value;
    const analysis = evaluatePassword(pw);

    copyPasswordBtn.disabled = pw.length === 0;
    passwordStrengthBadge.className = `status-badge status-${analysis.statusClass}`;
    passwordStrengthBadge.textContent = analysis.label;
    passwordScoreText.textContent = `${analysis.score} / 100`;

    pwLengthMetric.textContent = `${analysis.length} chars`;
    pwEntropyMetric.textContent = `${analysis.entropy} bits`;
    pwCrackMetric.textContent = analysis.crackTime;

    strengthSegments.forEach((seg, idx) => {
        seg.className = "strength-segment";
        if (idx < analysis.activeSegments) {
            seg.classList.add(`active-${analysis.statusClass}`);
        }
    });

    for (const item of passwordChecklist.querySelectorAll("li")) {
        const rule = item.dataset.rule;
        item.classList.toggle("passed", Boolean(analysis.rules[rule]));
    }

    passwordAdviceList.innerHTML = "";
    for (const tip of analysis.advice) {
        const li = document.createElement("li");
        li.textContent = tip;
        passwordAdviceList.appendChild(li);
    }
}

function generateStrongPassword(length = 16) {
    const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const lower = "abcdefghijkmnopqrstuvwxyz";
    const digits = "23456789";
    const symbols = "!@#$%^&*()-_=+";
    const all = upper + lower + digits + symbols;

    const pick = (charset) => {
        const buf = new Uint32Array(1);
        window.crypto.getRandomValues(buf);
        return charset[buf[0] % charset.length];
    };

    const chars = [pick(upper), pick(lower), pick(digits), pick(symbols)];
    while (chars.length < length) {
        chars.push(pick(all));
    }

    for (let i = chars.length - 1; i > 0; i--) {
        const buf = new Uint32Array(1);
        window.crypto.getRandomValues(buf);
        const j = buf[0] % (i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
}

passwordInput.addEventListener("input", updatePasswordUI);

togglePasswordBtn.addEventListener("click", () => {
    const isHidden = passwordInput.type === "password";
    passwordInput.type = isHidden ? "text" : "password";
    togglePasswordBtn.textContent = isHidden ? "Hide" : "Show";
    togglePasswordBtn.setAttribute("aria-pressed", String(isHidden));
});

generatePasswordBtn.addEventListener("click", () => {
    passwordInput.value = generateStrongPassword(16);
    passwordInput.type = "text";
    togglePasswordBtn.textContent = "Hide";
    togglePasswordBtn.setAttribute("aria-pressed", "true");
    updatePasswordUI();
});

copyPasswordBtn.addEventListener("click", async () => {
    if (!passwordInput.value) return;
    try {
        await navigator.clipboard.writeText(passwordInput.value);
        copyPasswordBtn.textContent = "Copied!";
        setTimeout(() => {
            copyPasswordBtn.textContent = "Copy";
        }, 1400);
    } catch {
        passwordInput.select();
    }
});

updatePasswordUI();

/* ---------------- Cyber Safety Quiz (6 Questions) ---------------- */
const QUIZ_QUESTIONS = [
    {
        question: "You receive an urgent SMS claiming your bank account is suspended and linking to http://192.168.4.22/bank-login-verify. What is the safest action?",
        options: [
            "Open the link and enter your password quickly to avoid account lock",
            "Ignore the link and access your bank only through its official app or bookmarked URL",
            "Reply to the SMS asking if it is legitimate",
            "Forward the link to friends to see if it opens for them",
        ],
        correctIndex: 1,
        explanation: "Urgent threats, unencrypted HTTP, raw IP addresses, and credential keywords are classic phishing traits. Always navigate via official apps or trusted bookmarks.",
    },
    {
        question: "Why can URL shorteners (like bit.ly or tinyurl.com) pose a security risk in unexpected emails or messages?",
        options: [
            "They automatically install antivirus software",
            "They hide the true destination domain until after you click",
            "They encrypt your password before sending it",
            "They only work on HTTPS banking sites",
        ],
        correctIndex: 1,
        explanation: "Shorteners mask the actual target domain, making it harder to spot lookalike or malicious websites before clicking.",
    },
    {
        question: "What does a padlock icon / HTTPS connection on a website actually guarantee?",
        options: [
            "That the company behind the website is 100% trustworthy and scam-free",
            "That traffic between your browser and that server is encrypted in transit",
            "That the website never collects personal data",
            "That your password cannot be phished",
        ],
        correctIndex: 1,
        explanation: "HTTPS encrypts data in transit, which is essential—but phishing sites can also obtain HTTPS certificates. Always verify the exact domain name too.",
    },
    {
        question: "Which password practice offers the strongest protection against credential stuffing and brute-force attacks?",
        options: [
            "Using one complex 10-character password across all your accounts",
            "Changing a single character at the end of your password every month",
            "Using a unique 14+ character passphrase per site combined with two-factor authentication (2FA)",
            "Using your birth year with a capital letter at the start",
        ],
        correctIndex: 2,
        explanation: "Unique, long passwords stop a single data breach from compromising other accounts, and 2FA blocks logins even if a password leaks.",
    },
    {
        question: "What trick is a scammer using when a link looks like https://login.microsoft.com@evil-verify.com/update?",
        options: [
            "Embedding an '@' symbol so everything before '@' is treated as userinfo while the real host is evil-verify.com",
            "Using official Microsoft single sign-on routing",
            "Compressing the webpage for mobile browsers",
            "Enabling end-to-end email encryption",
        ],
        correctIndex: 0,
        explanation: "In URL syntax, text before '@' can be parsed as user credentials, making 'evil-verify.com' the actual destination host.",
    },
    {
        question: "A colleague emails you an unexpected attachment asking you to 'Verify Your Payroll Password' before 5 PM. What should you do first?",
        options: [
            "Open the attachment on your phone instead of your laptop",
            "Enter your current password to check if the form works",
            "Verify the request directly with your colleague or IT team via a known phone number or internal chat",
            "Disable browser warnings so the page loads faster",
        ],
        correctIndex: 2,
        explanation: "Out-of-band verification through a trusted channel defeats compromised email accounts and urgent social engineering attacks.",
    },
];

const quizPlayArea = document.getElementById("quizPlayArea");
const quizResultArea = document.getElementById("quizResultArea");
const quizProgressLabel = document.getElementById("quizProgressLabel");
const quizScoreLabel = document.getElementById("quizScoreLabel");
const quizProgressFill = document.getElementById("quizProgressFill");
const quizQuestionText = document.getElementById("quizQuestionText");
const quizOptions = document.getElementById("quizOptions");
const quizFeedback = document.getElementById("quizFeedback");
const quizFeedbackTitle = document.getElementById("quizFeedbackTitle");
const quizFeedbackText = document.getElementById("quizFeedbackText");
const quizNextBtn = document.getElementById("quizNextBtn");
const quizTierBadge = document.getElementById("quizTierBadge");
const quizFinalHeadline = document.getElementById("quizFinalHeadline");
const quizFinalMessage = document.getElementById("quizFinalMessage");
const quizCorrectCount = document.getElementById("quizCorrectCount");
const quizAccuracyPct = document.getElementById("quizAccuracyPct");
const quizRestartBtn = document.getElementById("quizRestartBtn");

let quizIndex = 0;
let quizScore = 0;
let quizAnswered = false;

function renderQuizQuestion() {
    const total = QUIZ_QUESTIONS.length;
    const current = QUIZ_QUESTIONS[quizIndex];
    quizAnswered = false;

    quizProgressLabel.textContent = `Question ${quizIndex + 1} of ${total}`;
    quizScoreLabel.textContent = `Score: ${quizScore} / ${total}`;
    quizProgressFill.style.width = `${((quizIndex + 1) / total) * 100}%`;

    quizQuestionText.textContent = current.question;
    quizOptions.innerHTML = "";
    quizFeedback.className = "quiz-feedback hidden";
    quizNextBtn.classList.add("hidden");
    quizNextBtn.textContent = quizIndex === total - 1 ? "View Results" : "Next Question";

    const letters = ["A", "B", "C", "D"];
    current.options.forEach((optionText, idx) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "quiz-option-btn";

        const badge = document.createElement("span");
        badge.className = "option-letter";
        badge.textContent = letters[idx];

        const label = document.createElement("span");
        label.textContent = optionText;

        btn.appendChild(badge);
        btn.appendChild(label);
        btn.addEventListener("click", () => handleQuizAnswer(idx));
        quizOptions.appendChild(btn);
    });
}

function handleQuizAnswer(selectedIndex) {
    if (quizAnswered) return;
    quizAnswered = true;

    const total = QUIZ_QUESTIONS.length;
    const current = QUIZ_QUESTIONS[quizIndex];
    const isCorrect = selectedIndex === current.correctIndex;
    if (isCorrect) quizScore += 1;

    quizScoreLabel.textContent = `Score: ${quizScore} / ${total}`;

    const optionButtons = quizOptions.querySelectorAll(".quiz-option-btn");
    optionButtons.forEach((btn, idx) => {
        btn.disabled = true;
        if (idx === current.correctIndex) {
            btn.classList.add("option-correct");
        } else if (idx === selectedIndex && !isCorrect) {
            btn.classList.add("option-wrong");
        }
    });

    quizFeedback.className = `quiz-feedback ${isCorrect ? "feedback-correct" : "feedback-wrong"}`;
    quizFeedbackTitle.textContent = isCorrect ? "Correct!" : "Not quite — stay alert";
    quizFeedbackText.textContent = current.explanation;
    quizNextBtn.classList.remove("hidden");
}

function showQuizResults() {
    const total = QUIZ_QUESTIONS.length;
    const pct = Math.round((quizScore / total) * 100);

    quizPlayArea.classList.add("hidden");
    quizResultArea.classList.remove("hidden");

    quizCorrectCount.textContent = `${quizScore} / ${total}`;
    quizAccuracyPct.textContent = `${pct}%`;
    quizFinalHeadline.textContent = `You scored ${quizScore} out of ${total}`;

    if (quizScore >= 5) {
        quizTierBadge.className = "status-badge status-safe";
        quizTierBadge.textContent = "Cyber Guard Pro";
        quizFinalMessage.textContent = "Excellent awareness! You know how to spot disguised phishing URLs, risky shorteners, and social engineering traps.";
    } else if (quizScore >= 3) {
        quizTierBadge.className = "status-badge status-warn";
        quizTierBadge.textContent = "Security Aware";
        quizFinalMessage.textContent = "Solid foundation. Review the URL inspection signals and password best practices to close the remaining gaps.";
    } else {
        quizTierBadge.className = "status-badge status-danger";
        quizTierBadge.textContent = "Needs Practice";
        quizFinalMessage.textContent = "Phishing attackers rely on subtle tricks. Retake the quiz and test sample links in the URL Scanner above.";
    }
}

quizNextBtn.addEventListener("click", () => {
    if (quizIndex < QUIZ_QUESTIONS.length - 1) {
        quizIndex += 1;
        renderQuizQuestion();
    } else {
        showQuizResults();
    }
});

quizRestartBtn.addEventListener("click", () => {
    quizIndex = 0;
    quizScore = 0;
    quizResultArea.classList.add("hidden");
    quizPlayArea.classList.remove("hidden");
    renderQuizQuestion();
});

renderQuizQuestion();
