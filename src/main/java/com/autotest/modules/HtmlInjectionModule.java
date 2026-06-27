package com.autotest.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.autotest.*;

import java.util.List;
import java.util.regex.Pattern;

/**
 * HTML Injection detection via reflection + unique-token confirmation.
 *
 * Phase 1 — Initial probe: inject two HTML payloads and check for reflection.
 * Phase 2 — Unique token: inject a token-bearing payload and confirm exact token
 *            appears in a clean HTML context (not inside a comment, script, or style block).
 * Phase 3 — Report with FIRM or TENTATIVE confidence depending on context.
 *
 * BUG FIX: Content-Type lookups now use the protected static headerValue(HttpResponse, String)
 * from AbstractTestModule (stream-based) instead of response.headerValue() directly,
 * which removes any dependence on a specific Montoya API method signature.
 *
 * BUG FIX: String.transform() call removed — replaced with explicit chained replaceAll()
 * calls so the code compiles cleanly on all JVM 17 builds without ambiguity.
 */
public class HtmlInjectionModule extends AbstractTestModule {

    @Override public String name() { return "HTMLi"; }

    private static final String[] INITIAL_PAYLOADS = {
        "<h1>test</h1>",
        "\"><h1>test</h1>"
    };

    private static final Pattern HTML_COMMENT = Pattern.compile("<!--.*?-->",
            Pattern.DOTALL);
    private static final Pattern SCRIPT_BLOCK = Pattern.compile(
            "<script[^>]*>.*?</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern STYLE_BLOCK  = Pattern.compile(
            "<style[^>]*>.*?</style>",  Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    private static final Pattern NON_HTML_CT = Pattern.compile(
            "application/json|text/plain|application/xml|text/xml|"
            + "application/javascript|text/javascript|image/",
            Pattern.CASE_INSENSITIVE);

    public HtmlInjectionModule(MontoyaApi api, ScopeGuard scopeGuard,
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

        // ── Phase 1: probe for initial reflection ─────────────────────────────
        String reflectedPayload = null;

        for (String payload : INITIAL_PAYLOADS) {
            if (!budget.canSend()) return;

            SendResult res = trySend(url, method, point.name, payload,
                                      point.buildRequest(payload), budget);
            if (res.shouldAbortTask()) return;

            if (res.hasResponse()) {
                // BUG FIX: use protected static headerValue(HttpResponse, String)
                String contentType = headerValue(res.response(), "Content-Type");
                if (NON_HTML_CT.matcher(contentType).find()) return;
                if (bodyString(res.response()).toLowerCase().contains("<h1>test</h1>")) {
                    reflectedPayload = payload;
                    break;
                }
            }
        }

        if (reflectedPayload == null) return;

        // ── Phase 2: unique-token confirmation ────────────────────────────────
        String token        = "AUTOTEST_" + randomHexToken();
        String tokenPayload = "<h1>" + token + "</h1>";

        SendResult tokenRes = trySend(url, method, point.name, tokenPayload,
                                       point.buildRequest(tokenPayload), budget);
        if (tokenRes.shouldAbortTask()) return;

        if (!tokenRes.hasResponse()) {
            logger.logInfo("[HTMLi] Token request sent but no response — "
                    + point.pointType + " '" + point.name + "' @ " + url);
            return;
        }

        String tokenBody   = bodyString(tokenRes.response());
        String contentType = headerValue(tokenRes.response(), "Content-Type");

        if (NON_HTML_CT.matcher(contentType).find()) return;

        boolean tokenReflected = tokenBody.contains(token);
        boolean inContext       = tokenReflected && isContextClear(tokenBody, token);

        if (!tokenReflected) {
            logger.logInfo("[HTMLi] Phase 1 reflected but unique token absent — "
                    + point.pointType + " '" + point.name + "' @ " + url);
            return;
        }

        AuditIssueConfidence confidence = inContext
                ? AuditIssueConfidence.FIRM
                : AuditIssueConfidence.TENTATIVE;
        AuditIssueSeverity severity = AuditIssueSeverity.MEDIUM;

        List<HttpRequestResponse> evidence = tokenRes.rr != null
                ? List.of(tokenRes.rr) : List.of();

        String title = "[PassiveAutoTester] [HTMLi] HTML Injection in "
                       + point.pointType + " '" + point.name + "'";

        String detail = String.format(
            "URL: %s%n"
            + "Point: %s '%s'  (original value: %s)%n"
            + "Initial reflecting payload: %s%n"
            + "Unique token payload: %s%n"
            + "Token reflected: %s%n"
            + "Clean HTML context (not in comment/script/style): %s%n"
            + "Confidence: %s",
            url,
            point.pointType, point.name, point.originalValue,
            reflectedPayload,
            tokenPayload,
            tokenReflected ? "YES" : "NO",
            inContext       ? "YES" : "NO",
            confidence.name()
        );

        reportIssue(title, detail,
                "HTML injection arises when user input is placed into an HTML page without "
                + "proper encoding, allowing arbitrary markup to be injected.",
                "HTML-encode all reflected output. Apply a strict Content-Security-Policy header.",
                url, severity, confidence, evidence);
    }

    /**
     * Returns true only if the token is present AFTER stripping comment/script/style blocks.
     * A token surviving stripping means it sits in normally-rendered HTML.
     *
     * BUG FIX: replaced String.transform() chain with explicit replaceAll() calls
     * to avoid any compiler ambiguity around the Java 12 transform() method.
     */
    private static boolean isContextClear(String body, String token) {
        String s = HTML_COMMENT.matcher(body).replaceAll("");
        s = SCRIPT_BLOCK.matcher(s).replaceAll("");
        s = STYLE_BLOCK.matcher(s).replaceAll("");
        return s.contains(token);
    }
}
