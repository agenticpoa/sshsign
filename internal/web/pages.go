package web

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"github.com/agenticpoa/sshsign/internal/storage"
)

// partyFields are metadata keys that describe parties, not deal terms.
var partyFields = map[string]bool{
	"founder_name": true, "founder_title": true, "founder_company": true, "founder_email": true,
	"investor_name": true, "investor_title": true, "investor_company": true, "investor_email": true,
	"company_name": true, "party_name": true,
}

func approvalPage(ps *storage.PendingSignature, auth *storage.Authorization) string {
	// Parse metadata for display
	var metadata map[string]any
	json.Unmarshal([]byte(ps.Metadata), &metadata)

	// Split metadata into party info and deal terms
	var partyInfoHTML strings.Builder
	var termsHTML strings.Builder
	for k, v := range metadata {
		label := html.EscapeString(formatFieldLabel(k))
		value := html.EscapeString(formatTermValue(k, v))
		row := fmt.Sprintf(`<div class="party"><span class="party-label">%s</span><span class="party-value">%s</span></div>`, label, value)
		if partyFields[k] {
			partyInfoHTML.WriteString(row)
		} else {
			termsHTML.WriteString(fmt.Sprintf(`<div class="term"><span class="term-label">%s</span><span class="term-value">%s</span></div>`, label, value))
		}
	}

	// Constraint summary
	var constraintsHTML strings.Builder
	for _, mc := range auth.MetadataConstraints {
		constraintsHTML.WriteString(fmt.Sprintf(`<div class="constraint">%s: %s</div>`,
			html.EscapeString(formatFieldLabel(mc.Field)),
			html.EscapeString(formatConstraintRange(mc)),
		))
	}

	scope := html.EscapeString(formatScope(ps.DocType))

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign &amp; Approve - sshsign</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; max-width: 520px; width: 100%%; padding: 32px; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .scope { color: #58a6ff; font-size: 14px; margin-bottom: 24px; }
  .section-label { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
  .terms { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
  .term { display: flex; justify-content: space-between; padding: 6px 0; }
  .term-label { color: #8b949e; }
  .term-value { color: #e6edf3; font-weight: 500; }
  .parties { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
  .party { display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; }
  .party-label { color: #8b949e; }
  .party-value { color: #e6edf3; }
  .mono { font-family: monospace; font-size: 12px; }
  .constraints { font-size: 13px; color: #8b949e; margin-bottom: 20px; }
  .constraint { padding: 2px 0; }
  .esign-disclosure { font-size: 12px; color: #8b949e; line-height: 1.5; margin-bottom: 12px; padding: 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; }
  .consent { display: flex; align-items: center; gap: 8px; margin-bottom: 20px; font-size: 14px; color: #8b949e; cursor: pointer; }
  .consent input { width: 16px; height: 16px; cursor: pointer; }
  .canvas-wrap { background: #fff; border-radius: 8px; margin-bottom: 16px; position: relative; overflow: hidden; }
  canvas { display: block; width: 100%%; height: 160px; touch-action: none; }
  .canvas-hint { position: absolute; top: 50%%; left: 50%%; transform: translate(-50%%, -50%%); color: #999; font-size: 14px; pointer-events: none; transition: opacity 0.2s; }
  .actions { display: flex; gap: 8px; }
  .btn { flex: 1; padding: 12px; border: none; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
  .btn-clear { background: #21262d; color: #8b949e; }
  .btn-clear:hover { background: #30363d; }
  .btn-sign { background: #238636; color: #fff; }
  .btn-sign:hover { background: #2ea043; }
  .btn-sign:disabled { background: #21262d; color: #484f58; cursor: not-allowed; }
  .status { text-align: center; padding: 20px 0; font-size: 14px; color: #8b949e; }
  .done { text-align: center; padding: 20px 0; }
  .done h2 { color: #3fb950; margin-bottom: 8px; }
  .done .hash { font-family: monospace; font-size: 12px; color: #8b949e; word-break: break-all; }
  .error { color: #f85149; text-align: center; padding: 12px; }
</style>
</head>
<body>
<div class="card">
  <div id="review">
    <h1>Review &amp; Sign</h1>
    <div class="scope">%s</div>

    <div class="section-label">Parties</div>
    <div class="parties">
      %s
      <div class="party"><span class="party-label">Requested by</span><span class="party-value mono">%s</span></div>
      <div class="party"><span class="party-label">Signing as</span><span class="party-value mono">%s</span></div>
      <div class="party"><span class="party-label">Key</span><span class="party-value mono">%s</span></div>
      <div class="party"><span class="party-label">Submitted</span><span class="party-value">%s</span></div>
    </div>

    <div class="section-label">Agreed Terms</div>
    <div class="terms">%s</div>

    <div class="section-label">Your Authorized Range</div>
    <div class="constraints">%s</div>

    <div class="esign-disclosure">
      <strong>What you're signing</strong><br><br>
      An AI agent negotiated these terms on your behalf, within the boundaries
      you authorized. Please review the agreed terms and your authorized range
      above before signing.<br><br>
      By drawing your signature below, you confirm:<br>
      &bull; You delegated negotiation authority with the constraints shown above<br>
      &bull; You have reviewed and approve the final terms<br>
      &bull; Your drawn signature is legally binding, equivalent to a handwritten signature<br>
      &bull; You may close this page to cancel at any time before signing<br><br>
      Your signature will be sealed into a tamper-evident record with your
      identity, IP address, and timestamp. This constitutes an electronic
      signature under the ESIGN Act (15 U.S.C. &sect; 7001).
    </div>

    <label class="consent">
      <input type="checkbox" id="consent">
      I have read the above and consent to sign electronically
    </label>

    <div class="section-label">Your Signature</div>
    <div class="canvas-wrap">
      <canvas id="sig-canvas"></canvas>
      <div class="canvas-hint" id="hint">Draw your signature</div>
    </div>

    <div class="actions">
      <button class="btn btn-clear" onclick="clearSig()">Clear</button>
      <button class="btn btn-sign" id="signBtn" disabled onclick="submitSignature()">Sign &amp; Approve</button>
    </div>

    <div id="error" class="error" style="display:none"></div>
    <div id="status" class="status" style="display:none">Signing...</div>
  </div>

  <div id="done" class="done" style="display:none">
    <h2>Signed</h2>
    <p style="color:#8b949e; margin-bottom:12px">This document has been approved and cryptographically signed.</p>
    <div class="hash" id="envelope-hash"></div>
  </div>
</div>

<script>
// Minimal signature pad (no external dependencies)
const canvas = document.getElementById('sig-canvas');
const ctx = canvas.getContext('2d');
const hint = document.getElementById('hint');
const signBtn = document.getElementById('signBtn');
const consentBox = document.getElementById('consent');
let drawing = false;
let hasDrawn = false;
let lastX, lastY;

function resize() {
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  ctx.strokeStyle = '#000';
  ctx.lineWidth = 2;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
}
resize();
window.addEventListener('resize', resize);

function getPos(e) {
  const rect = canvas.getBoundingClientRect();
  const t = e.touches ? e.touches[0] : e;
  return [t.clientX - rect.left, t.clientY - rect.top];
}

function startDraw(e) {
  e.preventDefault();
  drawing = true;
  [lastX, lastY] = getPos(e);
  hint.style.opacity = '0';
  hasDrawn = true;
  updateBtn();
}

function draw(e) {
  if (!drawing) return;
  e.preventDefault();
  const [x, y] = getPos(e);
  ctx.beginPath();
  ctx.moveTo(lastX, lastY);
  ctx.lineTo(x, y);
  ctx.stroke();
  lastX = x;
  lastY = y;
}

function stopDraw() { drawing = false; }

canvas.addEventListener('mousedown', startDraw);
canvas.addEventListener('mousemove', draw);
canvas.addEventListener('mouseup', stopDraw);
canvas.addEventListener('mouseleave', stopDraw);
canvas.addEventListener('touchstart', startDraw, {passive: false});
canvas.addEventListener('touchmove', draw, {passive: false});
canvas.addEventListener('touchend', stopDraw);

consentBox.addEventListener('change', updateBtn);

function updateBtn() {
  signBtn.disabled = !(hasDrawn && consentBox.checked);
}

function clearSig() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  hint.style.opacity = '1';
  hasDrawn = false;
  updateBtn();
}

async function submitSignature() {
  signBtn.disabled = true;
  document.getElementById('status').style.display = 'block';
  document.getElementById('error').style.display = 'none';

  const dataURL = canvas.toDataURL('image/png');

  try {
    const resp = await fetch(window.location.href, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({signature_image: dataURL})
    });

    const data = await resp.json();

    if (!resp.ok) {
      throw new Error(data.error || 'signing failed');
    }

    document.getElementById('review').style.display = 'none';
    document.getElementById('done').style.display = 'block';
    document.getElementById('envelope-hash').textContent = 'Envelope: ' + data.envelope_hash;

    // Redirect to callback URL if provided (e.g. Telegram deep link)
    const params = new URLSearchParams(window.location.search);
    const callback = params.get('callback');
    if (callback) {
      setTimeout(() => { window.location.href = callback; }, 1500);
    }
  } catch (err) {
    document.getElementById('status').style.display = 'none';
    document.getElementById('error').style.display = 'block';
    document.getElementById('error').textContent = err.message;
    signBtn.disabled = false;
  }
}
</script>
</body>
</html>`, scope,
		partyInfoHTML.String(),
		html.EscapeString(ps.RequesterID),
		html.EscapeString(auth.GrantedBy),
		html.EscapeString(ps.SigningKeyID),
		html.EscapeString(ps.CreatedAt.Format("Jan 2, 2006 15:04 UTC")),
		termsHTML.String(),
		constraintsHTML.String())
}

func approvalAlreadyDonePage(status string) string {
	msg := "This document has already been " + html.EscapeString(status) + "."
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sshsign</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; color: #e6edf3; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; text-align: center; }
</style>
</head>
<body><div class="card"><p>%s</p></div></body>
</html>`, msg)
}

// knownLabels maps field names to display labels for common acronyms and terms.
var knownLabels = map[string]string{
	"mfn":              "Most Favored Nation",
	"pro_rata":         "Pro-Rata Rights",
	"valuation_cap":    "Valuation Cap",
	"discount_rate":    "Discount Rate",
	"nda_type":         "NDA Type",
	"term_years":       "Term (Years)",
	"founder_name":     "Founder",
	"founder_title":    "Title",
	"founder_company":  "Company",
	"founder_email":    "Email",
	"investor_name":    "Investor",
	"investor_title":   "Title",
	"investor_company": "Firm",
	"investor_email":   "Email",
	"company_name":     "Company",
}

func formatFieldLabel(field string) string {
	if label, ok := knownLabels[field]; ok {
		return label
	}
	return strings.ReplaceAll(strings.Title(strings.ReplaceAll(field, "_", " ")), " ", " ")
}

func formatScope(scope string) string {
	switch scope {
	case "safe-agreement":
		return "SAFE Agreement"
	case "nda":
		return "Non-Disclosure Agreement"
	case "git-commit":
		return "Git Commit"
	default:
		return scope
	}
}

func formatConstraintRange(mc storage.MetadataConstraint) string {
	fmtVal := func(v *float64) string {
		if rateFields[mc.Field] {
			if v == nil {
				return "?"
			}
			return fmt.Sprintf("%.0f%%", *v*100)
		}
		s := formatNum(v)
		if currencyFields[mc.Field] {
			return "$" + s
		}
		return s
	}

	switch mc.Type {
	case "range":
		return fmt.Sprintf("%s - %s", fmtVal(mc.Min), fmtVal(mc.Max))
	case "minimum":
		return fmt.Sprintf("min %s", fmtVal(mc.Min))
	case "maximum":
		return fmt.Sprintf("max %s", fmtVal(mc.Max))
	case "enum":
		return strings.Join(mc.Allowed, ", ")
	case "required_bool":
		if mc.Required != nil && *mc.Required {
			return "required"
		}
		return "optional"
	}
	return mc.Type
}

// rateFields are displayed as percentages (0.2 -> 20%).
var rateFields = map[string]bool{
	"discount_rate": true,
}

// currencyFields are displayed with $ prefix.
var currencyFields = map[string]bool{
	"valuation_cap": true,
}

func formatTermValue(field string, v any) string {
	switch val := v.(type) {
	case float64:
		if rateFields[field] {
			return fmt.Sprintf("%.0f%%", val*100)
		}
		if currencyFields[field] {
			if val == float64(int64(val)) {
				return "$" + formatIntWithCommas(int64(val))
			}
			return fmt.Sprintf("$%.2f", val)
		}
		if val == float64(int64(val)) {
			return formatIntWithCommas(int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "Yes"
		}
		return "No"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func formatNum(v *float64) string {
	if v == nil {
		return "?"
	}
	if *v == float64(int64(*v)) {
		return formatIntWithCommas(int64(*v))
	}
	return fmt.Sprintf("%.2f", *v)
}

func formatIntWithCommas(n int64) string {
	s := fmt.Sprintf("%d", n)
	if n < 0 {
		return "-" + formatIntWithCommas(-n)
	}
	if len(s) <= 3 {
		return s
	}
	var result strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result.WriteByte(',')
		}
		result.WriteRune(c)
	}
	return result.String()
}
