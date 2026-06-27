package com.autotest;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.autotest.modules.TestModule;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * Intercepts Burp proxy traffic via {@code api.http().registerHttpHandler()}.
 *
 * Gate criteria (applied in order — first failure = immediate pass-through, nothing logged):
 *   1. Source must be {@link ToolType#PROXY}.  Extension's own sendRequest() calls
 *      appear as {@code EXTENSIONS} — silently skipped, preventing infinite loops.
 *   2. Method must be GET (case-insensitive).
 *   3. URL must be in Burp active scope — HARD STOP, logged as [SKIPPED].
 *
 * The original request is NEVER modified or delayed.
 * {@link RequestToBeSentAction#continueWith(HttpRequest)} is always returned immediately.
 * All testing happens on the shared background thread pool.
 */
public class BackgroundTestHandler implements HttpHandler {

    private final ScopeGuard        scopeGuard;
    private final ExtensionLogger   logger;
    private final ExecutorService   executor;
    private final List<TestModule>  modules;
    private final BaselineFetcher   baselineFetcher;

    public BackgroundTestHandler(MontoyaApi api,
                                  ScopeGuard scopeGuard,
                                  ExtensionLogger logger,
                                  ExecutorService executor,
                                  List<TestModule> modules,
                                  BaselineFetcher baselineFetcher) {
        this.scopeGuard      = scopeGuard;
        this.logger          = logger;
        this.executor        = executor;
        this.modules         = modules;
        this.baselineFetcher = baselineFetcher;
    }

    // ── HttpHandler ───────────────────────────────────────────────────────────

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {

        // Gate 1 — Proxy traffic only.
        // Own extension requests → ToolType.EXTENSIONS → silently ignored (no loop).
        if (!requestToBeSent.toolSource().isFromTool(ToolType.PROXY)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Gate 2 — GET only
        if (!requestToBeSent.method().equalsIgnoreCase("GET")) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Gate 3 — HARD SCOPE CHECK (check #1 of N)
        String url = requestToBeSent.url();
        if (!scopeGuard.check(url)) {
            logger.logSkipped(url);
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // HttpRequest is immutable — safe to hand off to background thread
        final HttpRequest snapshot = requestToBeSent;
        CompletableFuture.runAsync(() -> runTests(snapshot), executor);

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // ── Async test orchestration ──────────────────────────────────────────────

    private void runTests(HttpRequest request) {
        String url = request.url();

        // SCOPE CHECK #2 — inside async thread; scope may have changed since dispatch
        if (!scopeGuard.check(url)) return;

        PayloadBudget budget = new PayloadBudget();
        if (!budget.consume()) return; // consumes slot 0 for the baseline fetch

        BaselineFetcher.BaselineResult baseline = baselineFetcher.getOrFetch(request);
        if (baseline == null)        return; // scope failed inside fetcher, or network error

        int payloadsBefore = budget.used(); // = 1 (baseline slot)

        // Run modules in priority order; abort on budget exhaustion or scope change
        for (TestModule module : modules) {
            if (!budget.canSend())       break;
            if (!scopeGuard.check(url))  return; // SCOPE CHECK #3 — before each module

            try {
                module.run(request, baseline, budget);
            } catch (Exception e) {
                logger.logError(url, "[" + module.name() + "] " + e.getMessage());
            }
        }

        int payloadsSent = budget.used() - payloadsBefore;
        logger.logTested(url, payloadsSent);
    }
}
