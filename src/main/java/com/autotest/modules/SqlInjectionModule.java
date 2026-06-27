package com.autotest.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.autotest.*;

import java.util.ArrayList;
import java.util.List;

/**
 * SQL Injection detection via the Break-and-Repair method.
 *
 * Phase 1  — Break with ' and ".
 * Phase 2  — String-context repairs.
 * Phase 3  — Integer-context repairs (fallback).
 * Phase 4  — Boolean TRUE/FALSE verification.
 * Phase 5  — Error-keyword cross-check against baseline (pre-existing error page filter).
 *
 * BUG FIX: INT_REPAIRS now include a leading space so the payload is valid SQL
 * (e.g. "1 AND 1=1" instead of "1AND 1=1").
 */
public class SqlInjectionModule extends AbstractTestModule {

    @Override public String name() { return "SQLi"; }

    private static final String[] SQL_ERRORS = {
        "sql syntax",
        "mysql_fetch",
        "ORA-",
        "sqlite_error",
        "pg_query",
        "syntax error",
        "unclosed quotation",
        "quoted string not properly terminated",
        "Microsoft OLE DB",
        "ODBC SQL",
        "you have an error in your SQL syntax"
    };

    private static final String[] STRING_REPAIRS = {
        "' '",
        "'||'",
        "'+'",
        "' AND '1'='1",
        "' -- -"
    };

    // ── BUG FIX: leading space added so injection reads "1 AND 1=1" not "1AND 1=1"
    private static final String[] INT_REPAIRS = {
        " AND 1=1",
        " AND 1=1 -- -"
    };

    public SqlInjectionModule(MontoyaApi api, ScopeGuard scopeGuard,
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

        // ── Phase 1: Break with single quote ─────────────────────────────────
        String singleQuotePayload = point.originalValue + "'";
        SendResult sqRes = trySend(url, method, point.name, singleQuotePayload,
                                    point.buildRequest(singleQuotePayload), budget);
        if (sqRes.shouldAbortTask()) return;

        boolean             singleQuoteBreaks = false;
        String              detectedErrorKw   = null;
        HttpRequestResponse sqRR              = null;

        if (sqRes.hasResponse()) {
            HttpResponse sqResp  = sqRes.response();
            String       sqBody  = bodyString(sqResp);
            String       foundKw = findKeywordIn(sqBody, SQL_ERRORS);
            boolean statusDiff   = sqResp.statusCode() != baseline.statusCode;
            boolean bodyDiff     = !baseline.bodyWithinTolerance(bodyLength(sqResp), 0.10);

            if (foundKw != null || statusDiff || bodyDiff) {
                singleQuoteBreaks = true;
                detectedErrorKw   = foundKw;
                sqRR              = sqRes.rr;
            }
        }

        if (!budget.canSend()) return;

        // ── Phase 1: Break with double quote ──────────────────────────────────
        String doubleQuotePayload = point.originalValue + "\"";
        SendResult dqRes = trySend(url, method, point.name, doubleQuotePayload,
                                    point.buildRequest(doubleQuotePayload), budget);
        if (dqRes.shouldAbortTask()) return;

        boolean doubleQuoteBreaks = false;
        if (dqRes.hasResponse()) {
            HttpResponse dqResp  = dqRes.response();
            String       dqBody  = bodyString(dqResp);
            boolean dqStatus     = dqResp.statusCode() != baseline.statusCode;
            boolean dqBodyDiff   = !baseline.bodyWithinTolerance(bodyLength(dqResp), 0.10);
            boolean dqError      = findKeywordIn(dqBody, SQL_ERRORS) != null;
            doubleQuoteBreaks    = dqStatus || dqBodyDiff || dqError;
        }

        if (!singleQuoteBreaks) return; // Need single quote to break before proceeding

        // ── Phase 5 pre-check: discard if error keyword already in baseline ───
        if (detectedErrorKw != null &&
                baseline.bodyContent.toLowerCase().contains(detectedErrorKw.toLowerCase())) {
            // BUG FIX: added log entry for this discard path
            logger.logInfo("[SQLi] Phase 5 discard — keyword '" + detectedErrorKw
                    + "' pre-exists in baseline at " + url + " [" + point.name + "]");
            return;
        }
        boolean phase5Passed = (detectedErrorKw != null); // keyword found in break, NOT in baseline

        // ── Phase 2: String-context repairs ──────────────────────────────────
        String successfulRepair = null;

        for (String repair : STRING_REPAIRS) {
            if (!budget.canSend()) return;
            String repairPayload = point.originalValue + repair;
            SendResult rRes = trySend(url, method, point.name, repairPayload,
                                       point.buildRequest(repairPayload), budget);
            if (rRes.shouldAbortTask()) return;

            if (rRes.hasResponse()) {
                HttpResponse rResp = rRes.response();
                if (baseline.matchesBaseline(rResp.statusCode(), bodyLength(rResp), 0.05)) {
                    successfulRepair = repair;
                    break;
                }
            }
        }

        // ── Phase 3: Integer-context repairs (if string repairs all failed) ───
        if (successfulRepair == null) {
            for (String repair : INT_REPAIRS) {
                if (!budget.canSend()) return;
                String repairPayload = point.originalValue + repair;
                SendResult rRes = trySend(url, method, point.name, repairPayload,
                                           point.buildRequest(repairPayload), budget);
                if (rRes.shouldAbortTask()) return;

                if (rRes.hasResponse()) {
                    HttpResponse rResp = rRes.response();
                    if (baseline.matchesBaseline(rResp.statusCode(), bodyLength(rResp), 0.05)) {
                        successfulRepair = repair;
                        break;
                    }
                }
            }
        }

        if (successfulRepair == null) {
            logger.logInfo("[SQLi] Phase 1 only — no repair succeeded, not reported. "
                    + point.pointType + " '" + point.name + "' @ " + url);
            return;
        }

        // ── Phase 4: Boolean TRUE/FALSE verification ──────────────────────────
        if (budget.remaining() < 2) {
            logger.logInfo("[SQLi] Repair OK but budget too low for Phase 4 — "
                    + point.name + " @ " + url);
            return;
        }

        String truePayload  = point.originalValue + "' AND '1'='1";
        String falsePayload = point.originalValue + "' AND '1'='2";

        SendResult trueRes = trySend(url, method, point.name, truePayload,
                                      point.buildRequest(truePayload), budget);
        if (trueRes.shouldAbortTask()) return;

        SendResult falseRes = trySend(url, method, point.name, falsePayload,
                                       point.buildRequest(falsePayload), budget);
        if (falseRes.shouldAbortTask()) return;

        boolean trueMatches  = false;
        boolean falseDiffers = false;

        if (trueRes.hasResponse()) {
            HttpResponse tr = trueRes.response();
            trueMatches = baseline.matchesBaseline(tr.statusCode(), bodyLength(tr), 0.05);
        }
        if (falseRes.hasResponse()) {
            HttpResponse fr = falseRes.response();
            falseDiffers = !baseline.statusMatches(fr.statusCode())
                        || !baseline.bodyWithinTolerance(bodyLength(fr), 0.10);
        }

        boolean phase4Confirmed = trueMatches && falseDiffers;

        if (!phase4Confirmed) {
            logger.logInfo("[SQLi] Repair OK but boolean verify failed — "
                    + point.name + " @ " + url);
            return;
        }

        // ── Confidence matrix ─────────────────────────────────────────────────
        AuditIssueConfidence confidence;
        AuditIssueSeverity   severity;

        if (phase4Confirmed && phase5Passed && doubleQuoteBreaks) {
            confidence = AuditIssueConfidence.CERTAIN;
            severity   = AuditIssueSeverity.HIGH;
        } else if (phase4Confirmed && phase5Passed) {
            confidence = AuditIssueConfidence.FIRM;
            severity   = AuditIssueSeverity.HIGH;
        } else {
            confidence = AuditIssueConfidence.TENTATIVE;
            severity   = AuditIssueSeverity.MEDIUM;
        }

        // ── Build evidence list and report ────────────────────────────────────
        List<HttpRequestResponse> evidence = new ArrayList<>();
        if (sqRR        != null) evidence.add(sqRR);
        if (trueRes.rr  != null) evidence.add(trueRes.rr);
        if (falseRes.rr != null) evidence.add(falseRes.rr);

        String trueBody  = excerpt(bodyString(trueRes.response()));
        String falseBody = excerpt(bodyString(falseRes.response()));

        String title = "[PassiveAutoTester] [SQLi] Possible SQL Injection in "
                       + point.pointType + " '" + point.name + "'";

        String detail = String.format(
            "Original URL: %s%n"
            + "Injectable point: %s '%s'%n"
            + "Original value: %s%n"
            + "Break payload: %s%n"
            + "Repair payload: %s%n"
            + "Boolean TRUE payload: %s → baseline match: %s%n"
            + "Boolean FALSE payload: %s → differs from baseline: %s%n"
            + "SQL error keyword: %s%n"
            + "Keyword in baseline (Phase 5): %s  →  Phase 5 passed: %s%n"
            + "Both quotes broke: %s%n"
            + "Confidence: %s | Severity: %s%n"
            + "TRUE response excerpt:%n%s%n"
            + "FALSE response excerpt:%n%s%n"
            + "Evidence requests: %d",
            url,
            point.pointType, point.name,
            point.originalValue,
            singleQuotePayload,
            successfulRepair,
            truePayload,  trueMatches  ? "YES" : "NO",
            falsePayload, falseDiffers ? "YES" : "NO",
            detectedErrorKw != null ? detectedErrorKw : "none",
            phase5Passed ? "NO" : "YES", phase5Passed ? "YES" : "NO",
            doubleQuoteBreaks ? "YES" : "NO",
            confidence.name(), severity.name(),
            trueBody,
            falseBody,
            evidence.size()
        );

        reportIssue(title, detail,
                "SQL injection vulnerabilities arise when user-supplied input is incorporated "
                + "into SQL queries without proper sanitisation.",
                "Use parameterised queries / prepared statements exclusively.",
                url, severity, confidence, evidence);
    }
}
