
const API_URL = "http://127.0.0.1:8000";

// ==============================
// DASHBOARD ELEMENTS
// ==============================

const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const scanResult = document.getElementById("scanResult");

// ==============================
// AUTHENTICATION
// ==============================

const token = localStorage.getItem("access_token");
const savedUser = localStorage.getItem("user");

let currentUser = null;

try {
    currentUser = savedUser ? JSON.parse(savedUser) : null;
} catch (error) {
    currentUser = null;
}

// Redirect unauthenticated users to login.
if (!token) {
    window.location.href = "login.html";
}

// Display logged-in user information.
if (currentUser) {
    const userName = document.getElementById("userName");
    const welcomeName = document.getElementById("welcomeName");
    const userEmail = document.getElementById("userEmail");

    if (userName) {
        userName.textContent = currentUser.name || "User";
    }

    if (welcomeName) {
        welcomeName.textContent = currentUser.name || "User";
    }

    if (userEmail) {
        userEmail.textContent = currentUser.email || "";
    }
}

// ==============================
// URL SCANNER EVENT LISTENERS
// ==============================

if (scanButton && urlInput && scanResult) {
    scanButton.addEventListener("click", scanURL);

    urlInput.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            scanURL();
        }
    });
} else {
    console.error(
        "URL scanner elements are missing. Check the IDs in dashboard.html."
    );
}

// ==============================
// SCAN URL
// ==============================

async function scanURL() {
    const url = urlInput.value.trim();

    if (!url) {
        showMessage("Please enter a URL to scan.", "error");
        return;
    }

    if (!token) {
        window.location.href = "login.html";
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    scanResult.textContent = "Analyzing URL...";

    try {
        const response = await fetch(`${API_URL}/scan/url`, {
            method: "POST",

            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },

            body: JSON.stringify({
                url: url
            })
        });

        const data = await response.json();

        // Handle expired or invalid authentication.
        if (response.status === 401) {
            localStorage.removeItem("access_token");
            localStorage.removeItem("user");

            alert("Your session has expired. Please log in again.");

            window.location.href = "login.html";
            return;
        }

        if (!response.ok) {
            throw new Error(
                data.detail || "The URL scan failed."
            );
        }

        displayResult(data);

    } catch (error) {
        console.error("URL scan error:", error);

        showMessage(
            error.message || "Unable to connect to the backend.",
            "error"
        );

    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan URL";
    }
}

// ==============================
// DISPLAY SCAN RESULT
// ==============================

function displayResult(data) {
    const card = document.createElement("div");

    card.className = "result-card " + getResultClass(data.result);

    const heading = document.createElement("h2");
    heading.textContent = data.result || "Unknown";

    const score = document.createElement("p");
    score.textContent = "Risk Score: " + data.risk_score + "/100";

    const scannedURL = document.createElement("p");
    scannedURL.textContent = "URL: " + (data.url || "");

    const explanationHeading = document.createElement("h3");
    explanationHeading.textContent = "Analysis";

    const explanation = document.createElement("p");
    explanation.textContent =
        data.explanation || "No explanation available.";

    const indicatorsHeading = document.createElement("h3");
    indicatorsHeading.textContent = "Detected Indicators";

    const indicatorsList = document.createElement("ul");

    if (Array.isArray(data.indicators) && data.indicators.length > 0) {
        data.indicators.forEach(function (indicator) {
            const item = document.createElement("li");
            item.textContent = indicator;
            indicatorsList.appendChild(item);
        });
    } else {
        const item = document.createElement("li");
        item.textContent = "No indicators reported.";
        indicatorsList.appendChild(item);
    }

    card.append(
        heading,
        score,
        scannedURL,
        explanationHeading,
        explanation,
        indicatorsHeading,
        indicatorsList
    );

    scanResult.replaceChildren(card);
}

// ==============================
// RESULT CLASSIFICATION
// ==============================

function getResultClass(result) {
    if (result === "SAFE") {
        return "safe";
    }

    if (result === "SUSPICIOUS") {
        return "suspicious";
    }

    return "phishing";
}

// ==============================
// DISPLAY MESSAGES
// ==============================

function showMessage(message, type) {
    const paragraph = document.createElement("p");

    paragraph.className =
        type === "error" ? "scan-error" : "scan-message";

    paragraph.textContent = message;

    scanResult.replaceChildren(paragraph);
}

// ==============================
// LOGOUT
// ==============================

const logoutButton = document.getElementById("logoutButton");

if (logoutButton) {
    logoutButton.addEventListener("click", function (event) {
        event.preventDefault();

        localStorage.removeItem("access_token");
        localStorage.removeItem("user");

        window.location.href = "login.html";
    });
}

async function loadScanHistory() {
    const historyBody = document.getElementById("scanHistoryBody");

    if (!historyBody) {
        console.error("Scan history table body not found.");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/scan/history`, {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });

        if (response.status === 401) {
            localStorage.removeItem("access_token");
            localStorage.removeItem("user");
            window.location.href = "login.html";
            return;
        }

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Unable to load scan history.");
        }

        const scans = Array.isArray(data.scans) ? data.scans : [];

        // Update dashboard statistics using actual scan records.
        document.getElementById("totalScans").textContent = scans.length;

        document.getElementById("safeScans").textContent =
            scans.filter(scan => scan.result === "SAFE").length;

        document.getElementById("suspiciousScans").textContent =
            scans.filter(scan => scan.result === "SUSPICIOUS").length;

        document.getElementById("highRiskScans").textContent =
            scans.filter(scan =>
                scan.result === "PHISHING" || Number(scan.risk_score) >= 70
            ).length;

        // Clear existing rows.
        historyBody.replaceChildren();

        if (scans.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.textContent = "No scans found. Scan a URL to get started.";
            row.appendChild(cell);
            historyBody.appendChild(row);
            return;
        }

        scans.forEach(scan => {
            const row = document.createElement("tr");

            const values = [
                scan.input_data || "N/A",
                scan.scan_type || "URL",
                scan.result || "UNKNOWN",
                `${scan.risk_score ?? 0}/100`,
                scan.created_at
                    ? new Date(scan.created_at).toLocaleString()
                    : "N/A"
            ];

            values.forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.appendChild(cell);
            });

            historyBody.appendChild(row);
        });

    } catch (error) {
        console.error("Scan history error:", error);

        historyBody.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent = "Unable to load scan history. Please refresh the page.";

        row.appendChild(cell);
        historyBody.appendChild(row);
    }
}

// Load history when the dashboard opens.
loadScanHistory();

// ==============================
// EMAIL PHISHING ANALYZER
// ==============================

const emailScanButton = document.getElementById("emailScanButton");
const emailInput = document.getElementById("emailInput");
const emailScanResult = document.getElementById("emailScanResult");

if (emailScanButton && emailInput && emailScanResult) {
emailScanButton.addEventListener("click", async function () {
const emailText = emailInput.value.trim();


    // Validate the input.
    if (!emailText) {
        emailScanResult.textContent = "Please paste an email before scanning.";
        return;
    }

    const currentToken = localStorage.getItem("access_token");

    if (!currentToken) {
        window.location.href = "login.html";
        return;
    }

    emailScanButton.disabled = true;
    emailScanButton.textContent = "Analyzing...";
    emailScanResult.replaceChildren();

    try {
        const response = await fetch(`${API_URL}/scan/email`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${currentToken}`
            },
            body: JSON.stringify({
                email_text: emailText
            })
        });

        const data = await response.json();

        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem("access_token");
            localStorage.removeItem("user");
            window.location.href = "login.html";
            return;
        }

        if (!response.ok) {
            throw new Error(
                data.detail || "Email analysis failed. Please try again."
            );
        }

        // // Build the result safely using textContent.
        // const resultCard = document.createElement("div");
        // resultCard.className = "scanner-card";
        // resultCard.style.marginTop = "20px";

        // const heading = document.createElement("h3");
        // heading.textContent = "Email Analysis Result";
        // resultCard.appendChild(heading);

        // const classification = document.createElement("p");
        // classification.textContent = `Classification: ${data.result}`;
        // resultCard.appendChild(classification);

        // const score = document.createElement("p");
        // score.textContent = `Risk Score: ${data.risk_score}/100`;
        // resultCard.appendChild(score);

        // const explanation = document.createElement("p");
        // explanation.textContent = data.explanation || "No explanation provided.";
        // resultCard.appendChild(explanation);

        // const indicatorsHeading = document.createElement("h4");
        // indicatorsHeading.textContent = "Detected Indicators";
        // resultCard.appendChild(indicatorsHeading);

        // const indicatorsList = document.createElement("ul");

        // (Array.isArray(data.indicators) ? data.indicators : [])
        //     .forEach(indicator => {
        //         const item = document.createElement("li");
        //         item.textContent = indicator;
        //         indicatorsList.appendChild(item);
        //     });

        // if (!indicatorsList.children.length) {
        //     const item = document.createElement("li");
        //     item.textContent = "No configured phishing indicators detected.";
        //     indicatorsList.appendChild(item);
        // }

        // resultCard.appendChild(indicatorsList);

        // const urlsHeading = document.createElement("h4");
        // urlsHeading.textContent = "Extracted URLs";
        // resultCard.appendChild(urlsHeading);

        // const urlsList = document.createElement("ul");

        // (Array.isArray(data.extracted_urls) ? data.extracted_urls : [])
        //     .forEach(url => {
        //         const item = document.createElement("li");
        //         item.textContent = url;
        //         urlsList.appendChild(item);
        //     });

        // if (!urlsList.children.length) {
        //     const item = document.createElement("li");
        //     item.textContent = "No URLs found in the email.";
        //     urlsList.appendChild(item);
        // }

        // resultCard.appendChild(urlsList);

        // const recommendationsHeading = document.createElement("h4");
        // recommendationsHeading.textContent = "Safety Recommendations";
        // resultCard.appendChild(recommendationsHeading);

        // const recommendationsList = document.createElement("ul");

        // (Array.isArray(data.recommendations) ? data.recommendations : [])
        //     .forEach(recommendation => {
        //         const item = document.createElement("li");
        //         item.textContent = recommendation;
        //         recommendationsList.appendChild(item);
        //     });

        // resultCard.appendChild(recommendationsList);

        // emailScanResult.replaceChildren(resultCard);

        
        // Refresh statistics and history after a successful scan.

        // Build a professional result card safely.
        const resultCard = document.createElement("div");
        resultCard.className = "email-result-card";

        const result = String(data.result || "UNKNOWN").toUpperCase();
        const riskScore = Math.max(
            0,
            Math.min(100, Number(data.risk_score) || 0)
        );

        let riskClass = "email-risk-unknown";
        let riskLabel = "UNKNOWN";

        if (result === "LOW_RISK" || result === "SAFE") {
            riskClass = "email-risk-low";
            riskLabel = "LOW RISK";
        } else if (result === "SUSPICIOUS") {
            riskClass = "email-risk-suspicious";
            riskLabel = "SUSPICIOUS";
        } else if (result === "PHISHING" || result === "HIGH_RISK") {
            riskClass = "email-risk-high";
            riskLabel = "HIGH RISK";
        }

        // Header
        const header = document.createElement("div");
        header.className = "email-result-header";

        const headingGroup = document.createElement("div");

        const heading = document.createElement("h3");
        heading.textContent = "Email Analysis Report";

        const subtitle = document.createElement("p");
        subtitle.textContent = `Scan ID: ${data.scan_id ?? "N/A"}`;

        headingGroup.append(heading, subtitle);

        const badge = document.createElement("span");
        badge.className = `email-risk-badge ${riskClass}`;
        badge.textContent = riskLabel;

        header.append(headingGroup, badge);
        resultCard.appendChild(header);

        // Risk score panel
        const scorePanel = document.createElement("div");
        scorePanel.className = "email-score-panel";

        const scoreTop = document.createElement("div");
        scoreTop.className = "email-score-top";

        const scoreLabel = document.createElement("span");
        scoreLabel.className = "email-score-label";
        scoreLabel.textContent = "Email Risk Score";

        const scoreValue = document.createElement("span");
        scoreValue.className = "email-score-value";
        scoreValue.textContent = `${riskScore}/100`;

        scoreTop.append(scoreLabel, scoreValue);

        const track = document.createElement("div");
        track.className = "email-score-track";
        track.setAttribute("role", "progressbar");
        track.setAttribute("aria-label", "Email risk score");
        track.setAttribute("aria-valuemin", "0");
        track.setAttribute("aria-valuemax", "100");
        track.setAttribute("aria-valuenow", String(riskScore));

        const fill = document.createElement("div");
        fill.className = `email-score-fill ${riskClass}`;
        fill.style.width = `${riskScore}%`;

        track.appendChild(fill);
        scorePanel.append(scoreTop, track);
        resultCard.appendChild(scorePanel);

        // Explanation
        const explanation = document.createElement("p");
        explanation.className = "email-result-explanation";
        explanation.textContent =
            data.explanation || "No explanation was provided.";
        resultCard.appendChild(explanation);

        // Helper to safely build detail cards.
        function createDetailCard(title, entries, emptyMessage) {
            const card = document.createElement("div");
            card.className = "email-detail-card";

            const cardHeading = document.createElement("h4");
            cardHeading.textContent = title;
            card.appendChild(cardHeading);

            const list = document.createElement("ul");
            list.className = "email-detail-list";

            if (!Array.isArray(entries) || entries.length === 0) {
                const item = document.createElement("li");
                item.className = "email-empty-item";
                item.textContent = emptyMessage;
                list.appendChild(item);
            } else {
                entries.forEach(entry => {
                    const item = document.createElement("li");
                    item.textContent = String(entry);
                    list.appendChild(item);
                });
            }

            card.appendChild(list);
            return card;
        }

        // Indicators, URLs and recommendations.
        const resultGrid = document.createElement("div");
        resultGrid.className = "email-result-grid";

        resultGrid.appendChild(
            createDetailCard(
                "Detected Indicators",
                data.indicators,
                "No configured phishing indicators were detected."
            )
        );

        resultGrid.appendChild(
            createDetailCard(
                "Extracted URLs",
                data.extracted_urls,
                "No URLs were found in the email."
            )
        );

        resultGrid.appendChild(
            createDetailCard(
                "Safety Recommendations",
                data.recommendations,
                "Follow your organization's email security guidance."
            )
        );

        resultCard.appendChild(resultGrid);

        emailScanResult.replaceChildren(resultCard);
        
        await loadScanHistory();

    } catch (error) {
        console.error("Email analysis error:", error);
        emailScanResult.textContent =
            error.message || "Unable to analyze the email. Please try again.";
    } finally {
        emailScanButton.disabled = false;
        emailScanButton.textContent = "Analyze Email";
    }
});


}
