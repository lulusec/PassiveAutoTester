package com.autotest.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.autotest.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

/**
 * Shared infrastructure for all test modules.
 *
 * The core helper is {@link #trySend}, which atomically:
 *   1. Claims a deduplication slot (skip if already claimed).
 *   2. Consumes one payload budget slot (abort if exhausted).
 *   3. Re-checks scope live before the outbound call.
 *   4. Enforces the 300 ms rate limit.
 *   5. Sends via {@code api.http().sendRequest()}.
 *
 * All logging goes to {@link ExtensionLogger} → Burp's native output pane.
 * Zero Swing, zero AWT.
 */
public abstract class AbstractTestModule implements TestModule {

    protected final MontoyaApi         api;
    protected final ScopeGuard         scopeGuard;
    protected final DeduplicationCache dedupCache;
    protected final RateLimiter        rateLimiter;
    protected final ExtensionLogger    logger;
    protected final BaselineFetcher    baselineFetcher;  // protected — only subclasses need it

    private static final SecureRandom RNG = new SecureRandom();

    protected AbstractTestModule(MontoyaApi api,
                                  ScopeGuard scopeGuard,
                                  DeduplicationCache dedupCache,
                                  RateLimiter rateLimiter,
                                  ExtensionLogger logger,
                                  BaselineFetcher baselineFetcher) {
        this.api             = api;
        this.scopeGuard      = scopeGuard;
        this.dedupCache      = dedupCache;
        this.rateLimiter     = rateLimiter;
        this.logger          = logger;
        this.baselineFetcher = baselineFetcher;
    }

    // ── Core send helper ──────────────────────────────────────────────────────

    /**
     * Attempt to send one payload request through all gate checks.
     *
     * @param originalUrl URL used for dedup key and scope check.
     * @param method      HTTP method.
     * @param pointName   Name of the injectable point (param or header name).
     * @param payload     Full injected value (used for dedup key).
     * @param modifiedReq Pre-built request with payload substituted in.
     * @param budget      Shared budget — atomically consumed here.
     * @return {@link SendResult} — callers check {@link SendResult#shouldAbortTask()}
     *         to decide whether to abort all further testing for this request.
     */
    protected SendResult trySend(String originalUrl,
                                  String method,
                                  String pointName,
                                  String payload,
                                  HttpRequest modifiedReq,
                                  PayloadBudget budget) {
        // 1. Dedup — claim slot atomically (before budget, to avoid budget waste on dupes)
        if (!dedupCache.shouldTest(method, originalUrl, pointName, payload)) {
            return SendResult.DEDUP;
        }

        // 2. Budget — atomically consume one slot
        if (!budget.consume()) {
            return SendResult.BUDGET_EXHAUSTED;
        }

        // 3. Live scope check on the modified request URL
        if (!scopeGuard.check(modifiedReq.url())) {
            return SendResult.SCOPE_FAILED;
        }

        // 4. Rate limit
        rateLimiter.throttle();

        // 5. Send
        try {
            HttpRequestResponse rr = api.http().sendRequest(modifiedReq);
            return SendResult.sent(rr);
        } catch (Exception e) {
            logger.logError(originalUrl, "[" + name() + "] send error: " + e.getMessage());
            return SendResult.ERROR;
        }
    }

    // ── Response helpers ──────────────────────────────────────────────────────

    /** Decode response body to UTF-8 string. Returns "" on null/error. */
    protected static String bodyString(HttpResponse response) {
        if (response == null) return "";
        try {
            return new String(response.body().getBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /** Body length in bytes. */
    protected static int bodyLength(HttpResponse response) {
        if (response == null) return 0;
        return response.body().length();
    }

    /**
     * Case-insensitive header value lookup using stream traversal.
     * Avoids relying on a specific {@code headerValue()} overload in the Montoya API.
     * Returns empty string if the header is absent.
     */
    protected static String headerValue(HttpResponse response, String name) {
        if (response == null) return "";
        return response.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(HttpHeader::value)
                .findFirst()
                .orElse("");
    }

    /**
     * Searches body for the first keyword from the array (case-insensitive).
     * Returns the matched keyword (original case), or {@code null} if none found.
     */
    protected static String findKeywordIn(String body, String[] keywords) {
        String lower = body.toLowerCase();
        for (String kw : keywords) {
            if (lower.contains(kw.toLowerCase())) return kw;
        }
        return null;
    }

    /** Generate a random 8-char uppercase hex token. */
    protected static String randomHexToken() {
        byte[] b = new byte[4];
        RNG.nextBytes(b);
        return String.format("%08X",
                ((long)(b[0] & 0xFF) << 24) |
                ((long)(b[1] & 0xFF) << 16) |
                ((long)(b[2] & 0xFF) << 8)  |
                ((long)(b[3] & 0xFF)));
    }

    /** First 300 characters of body for issue detail excerpts. */
    protected static String excerpt(String body) {
        if (body == null || body.isEmpty()) return "(empty)";
        return body.length() > 300 ? body.substring(0, 300) + "…" : body;
    }

    // ── Issue reporting ───────────────────────────────────────────────────────

    /**
     * Creates an {@link AuditIssue}, adds it to the Burp site map, and logs the finding.
     */
    protected void reportIssue(String title,
                                String detail,
                                String background,
                                String remediation,
                                String baseUrl,
                                AuditIssueSeverity severity,
                                AuditIssueConfidence confidence,
                                List<HttpRequestResponse> evidence) {
        AuditIssue issue = AuditIssue.auditIssue(
                title, detail, remediation,
                baseUrl,
                severity, confidence,
                background,
                remediation,
                severity,
                evidence);
        api.siteMap().add(issue);
        logger.logFinding("[" + name() + "] " + confidence.name() + " — " + title);
    }

    // ── SendResult ────────────────────────────────────────────────────────────

    /**
     * Outcome of a {@link #trySend} call.
     * Immutable value-object; the constant instances are reused for non-SENT outcomes.
     */
    protected static final class SendResult {

        public enum Kind { SENT, DEDUP, BUDGET_EXHAUSTED, SCOPE_FAILED, ERROR }

        // Reusable constants (no alloc on fast paths)
        public static final SendResult DEDUP            = new SendResult(Kind.DEDUP,            null);
        public static final SendResult BUDGET_EXHAUSTED = new SendResult(Kind.BUDGET_EXHAUSTED, null);
        public static final SendResult SCOPE_FAILED     = new SendResult(Kind.SCOPE_FAILED,     null);
        public static final SendResult ERROR            = new SendResult(Kind.ERROR,             null);

        public final Kind                kind;
        public final HttpRequestResponse rr;

        private SendResult(Kind kind, HttpRequestResponse rr) {
            this.kind = kind;
            this.rr   = rr;
        }

        public static SendResult sent(HttpRequestResponse rr) {
            return new SendResult(Kind.SENT, rr);
        }

        public boolean wasSent()          { return kind == Kind.SENT;             }
        public boolean budgetExhausted()  { return kind == Kind.BUDGET_EXHAUSTED; }
        public boolean scopeFailed()      { return kind == Kind.SCOPE_FAILED;     }

        /** If true the caller must abort ALL further testing for this request. */
        public boolean shouldAbortTask()  { return kind == Kind.BUDGET_EXHAUSTED || kind == Kind.SCOPE_FAILED; }

        public boolean hasResponse() {
            return wasSent() && rr != null && rr.hasResponse();
        }

        public HttpResponse response() {
            return hasResponse() ? rr.response() : null;
        }
    }
}
