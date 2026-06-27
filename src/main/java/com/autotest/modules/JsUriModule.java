package com.autotest.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.autotest.*;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JavaScript-URI Injection detection.
 *
 * Phase 1 — Probe: inject {@code javascript:alert()} and check if the response
 *            body contains {@code javascript:}.
 * Phase 2 — Unique token: inject {@code javascript:AUTOTEST_<hex>} and check:
 *            a) the token is reflected in the response.
 *            b) the token appears inside an attribute context
 *               ({@code href}, {@code src}, {@code action}, or {@code data}).
 *
 * Confidence:
 *   FIRM    if attribute-context pattern is confirmed.
 *   TENTATIVE if only general reflection found.
 */
public class JsUriModule extends AbstractTestModule {

    @Override public String name() { return "JS-URI"; }

    private static final String INITIAL_PAYLOAD = "javascript:alert()";

    private static final Pattern ATTR_PATTERN = Pattern.compile(
            "(href|src|action|data)=[\"']?javascript:",
            Pattern.CASE_INSENSITIVE);

    public JsUriModule(MontoyaApi api, ScopeGuard scopeGuard,
                        DeduplicationCache dedupCache, RateLimiter rateLimiter,
                        ExtensionLogger logger, BaselineFetcher baselineFetcher) {
        super(api, scopeGuard, dedupCache, rateLimiter, logger, baselineFetcher);
    }

    @Override
    public void run(HttpRequest request, BaselineFetcher.BaselineResult baseline, PayloadBudget budget) {
        for (InjectablePoint point : InjectablePoint.from(request)) {
            if (!budget.canSend()) return;
            testPoint(request, baseline, budget, point);
            if (!scopeGuard.check(request.url())) return;
        }
    }

    private void testPoint(HttpRequest request,
                            BaselineFetcher.BaselineResult baseline,
                            PayloadBudget budget,
                            InjectablePoint point) {

        String url    = request.url();
        String method = request.method();

        // ── Phase 1: initial probe ─────────────────────────────────────────────
        SendResult phase1Res = trySend(url, method, point.name, INITIAL_PAYLOAD,
                                        point.buildRequest(INITIAL_PAYLOAD), budget);
        if (phase1Res.shouldAbortTask()) return;

        if (!phase1Res.hasResponse()) return;

        String phase1Body = bodyString(phase1Res.response());
        if (!phase1Body.contains("javascript:")) return; // no reflection at all

        // ── Phase 2: unique token ──────────────────────────────────────────────
        if (!budget.canSend()) return;

        String token        = "AUTOTEST_" + randomHexToken();
        String tokenPayload = "javascript:" + token;

        SendResult tokenRes = trySend(url, method, point.name, tokenPayload,
                                       point.buildRequest(tokenPayload), budget);
        if (tokenRes.shouldAbortTask()) return;

        if (!tokenRes.hasResponse()) {
            logger.logInfo("[JS-URI] Token request sent but no response — "
                    + point.pointType + " '" + point.name + "' @ " + url);
            return;
        }

        String tokenBody = bodyString(tokenRes.response());

        // Check both general reflection AND attribute-context placement
        boolean tokenReflected   = tokenBody.contains("javascript:" + token);
        boolean inAttributeCtx   = false;

        if (tokenReflected) {
            Matcher m = ATTR_PATTERN.matcher(tokenBody);
            while (m.find()) {
                // Verify the matched attribute actually contains our token nearby
                int matchEnd = m.end();
                int searchEnd = Math.min(matchEnd + token.length() + 20, tokenBody.length());
                if (tokenBody.substring(matchEnd, searchEnd).contains(token)) {
                    inAttributeCtx = true;
                    break;
                }
            }
        }

        if (!tokenReflected) {
            logger.logInfo("[JS-URI] Initial reflection but unique token not found — "
                    + point.pointType + " '" + point.name + "' @ " + url);
            return;
        }

        AuditIssueConfidence confidence = inAttributeCtx
                ? AuditIssueConfidence.FIRM
                : AuditIssueConfidence.TENTATIVE;
        AuditIssueSeverity severity = inAttributeCtx
                ? AuditIssueSeverity.HIGH
                : AuditIssueSeverity.MEDIUM;

        List<HttpRequestResponse> evidence = tokenRes.rr != null
                ? List.of(tokenRes.rr) : List.of();

        String title = "[PassiveAutoTester] [JS-URI] JavaScript-URI Injection in "
                       + point.pointType + " '" + point.name + "'";

        String detail = String.format(
            "URL: %s%n"
            + "Point: %s '%s'  (original value: %s)%n"
            + "Initial probe: %s%n"
            + "Token payload: %s%n"
            + "Token reflected: %s%n"
            + "Attribute context confirmed: %s%n"
            + "Confidence: %s | Severity: %s",
            url,
            point.pointType, point.name, point.originalValue,
            INITIAL_PAYLOAD,
            tokenPayload,
            tokenReflected ? "YES" : "NO",
            inAttributeCtx  ? "YES" : "NO",
            confidence.name(), severity.name()
        );

        reportIssue(title, detail,
                "JavaScript-URI injection allows an attacker to inject javascript: scheme URIs "
                + "into href/src/action attributes, enabling XSS via navigation.",
                "Validate and allowlist URL schemes. Never reflect raw user input into href/src/action attributes.",
                url, severity, confidence, evidence);
    }
}
