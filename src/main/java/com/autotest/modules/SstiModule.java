package com.autotest.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.autotest.*;

import java.util.List;

/**
 * Server-Side Template Injection (SSTI) detection via arithmetic confirmation.
 *
 * Phase 1 — Math result: inject {@code {{7*7}}} and check if "49" appears
 *            in the response but NOT in the baseline.
 *
 * Phase 2 — Alternate arithmetic confirm: inject the same syntax with {@code 33*33}.
 *            Check if "1089" appears in the response but NOT in the baseline.
 *
 *            BUG FIX: Previously used 3*3=9. The digit "9" is present in virtually
 *            every HTML page (dates, IDs, version strings), causing constant false-
 *            negatives — Phase 2 was always discarded. Replaced with 33*33=1089,
 *            a four-digit result highly unlikely to appear naturally.
 *
 * Phase 3 — Engine fingerprint: send an engine-specific probe and check the result.
 *
 * Confidence matrix:
 *   Phase 2 + Phase 3 engine identified → CERTAIN
 *   Phase 2 confirmed only              → FIRM
 *   Phase 1 only (49 found, 1089 absent)→ TENTATIVE
 */
public class SstiModule extends AbstractTestModule {

    @Override public String name() { return "SSTI"; }

    private record SstiPayload(
        String syntax,
        String payload49,
        String payload1089,   // BUG FIX: was payload9 / 3*3; now 33*33 → 1089
        String engineProbe,
        String engineResult,
        String engineName
    ) {}

    private static final SstiPayload[] PAYLOADS = {
        new SstiPayload("{{...}}",
                "{{7*7}}",          "{{33*33}}",
                "{{7*'7'}}",        "7777777",      "Jinja2/Twig"),

        new SstiPayload("${...}",
                "${7*7}",           "${33*33}",
                "${\"test\".toUpperCase()}", "TEST", "FreeMarker/Spring EL"),

        new SstiPayload("<%= %>",
                "<%= 7*7 %>",       "<%= 33*33 %>",
                "<%= 7*'7' %>",     "49",            "ERB/Ruby"),

        new SstiPayload("#{...}",
                "#{7*7}",           "#{33*33}",
                "#{'test'.toUpperCase()}", "TEST",   "Thymeleaf/Pebble"),
    };

    public SstiModule(MontoyaApi api, ScopeGuard scopeGuard,
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

        for (SstiPayload sp : PAYLOADS) {
            if (!budget.canSend()) return;

            // ── Phase 1: {{7*7}} → expect "49" in response, absent from baseline ──
            SendResult p1Res = trySend(url, method, point.name, sp.payload49(),
                                        point.buildRequest(sp.payload49()), budget);
            if (p1Res.shouldAbortTask()) return;
            if (!p1Res.hasResponse()) continue;

            String  p1Body = bodyString(p1Res.response());
            boolean p1Hit  = p1Body.contains("49") && !baseline.bodyContent.contains("49");
            if (!p1Hit) continue;

            // ── Phase 2: {{33*33}} → expect "1089" in response, absent from baseline
            if (!budget.canSend()) return;

            SendResult p2Res = trySend(url, method, point.name, sp.payload1089(),
                                        point.buildRequest(sp.payload1089()), budget);
            if (p2Res.shouldAbortTask()) return;

            boolean phase2Confirmed = false;
            String  p2Body          = "(no response)";

            if (p2Res.hasResponse()) {
                p2Body          = bodyString(p2Res.response());
                phase2Confirmed = p2Body.contains("1089")
                               && !baseline.bodyContent.contains("1089");
            }

            // ── Phase 3: engine fingerprint ───────────────────────────────────────
            boolean             engineConfirmed = false;
            HttpRequestResponse p3RR            = null;

            if (phase2Confirmed && budget.canSend()) {
                SendResult p3Res = trySend(url, method, point.name, sp.engineProbe(),
                                            point.buildRequest(sp.engineProbe()), budget);
                if (p3Res.shouldAbortTask()) return;

                if (p3Res.hasResponse()) {
                    String p3Body = bodyString(p3Res.response());
                    engineConfirmed = p3Body.contains(sp.engineResult())
                                   && !baseline.bodyContent.contains(sp.engineResult());
                    p3RR = p3Res.rr;
                }
            }

            // ── Confidence matrix ──────────────────────────────────────────────────
            AuditIssueConfidence confidence;
            AuditIssueSeverity   severity = AuditIssueSeverity.HIGH;

            if (phase2Confirmed && engineConfirmed) {
                confidence = AuditIssueConfidence.CERTAIN;
            } else if (phase2Confirmed) {
                confidence = AuditIssueConfidence.FIRM;
            } else {
                confidence = AuditIssueConfidence.TENTATIVE;
                severity   = AuditIssueSeverity.MEDIUM;
            }

            // ── Evidence ──────────────────────────────────────────────────────────
            List<HttpRequestResponse> evidence;
            if (p3RR != null && p1Res.rr != null) {
                evidence = List.of(p1Res.rr, p3RR);
            } else if (p1Res.rr != null) {
                evidence = List.of(p1Res.rr);
            } else {
                evidence = List.of();
            }

            String title = "[PassiveAutoTester] [SSTI] Template Injection in "
                           + point.pointType + " '" + point.name + "'";

            String detail = String.format(
                "URL: %s%n"
                + "Point: %s '%s'  (original value: %s)%n"
                + "Syntax: %s%n"
                + "Phase 1: %s  →  49 in response (not baseline): %s%n"
                + "Phase 2: %s  →  1089 in response (not baseline): %s%n"
                + "Engine probe: %s  →  '%s' confirmed: %s%n"
                + "Engine identified: %s%n"
                + "Phase 2 response excerpt:%n%s%n"
                + "Confidence: %s | Severity: %s",
                url,
                point.pointType, point.name, point.originalValue,
                sp.syntax(),
                sp.payload49(),    p1Hit          ? "YES" : "NO",
                sp.payload1089(),  phase2Confirmed ? "YES" : "NO",
                sp.engineProbe(),  sp.engineResult(), engineConfirmed ? "YES" : "NO",
                engineConfirmed ? sp.engineName() : "(unknown)",
                excerpt(p2Body),
                confidence.name(), severity.name()
            );

            reportIssue(title, detail,
                    "SSTI allows attackers to inject template directives that are evaluated "
                    + "server-side, potentially leading to remote code execution.",
                    "Never pass user-controlled input directly into template rendering. "
                    + "Use sandboxed environments and strict input validation.",
                    url, severity, confidence, evidence);

            return; // one syntax triggered per point — stop iterating syntaxes
        }
    }
}
