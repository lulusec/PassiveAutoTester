package com.autotest;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.autotest.modules.*;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * PassiveAutoTester — headless Burp Suite extension.
 *
 * No UI panel, no Swing, no AWT.  All output goes to the Burp
 * "Extensions > PassiveAutoTester > Output" pane via the native logging API.
 *
 * Resource profile (intentionally minimal):
 *   • 2 background test threads (reduced from 3)
 *   • No heap overhead from Swing components
 *   • AtomicInteger counters only; no live stats widgets
 */
@SuppressWarnings("unused")
public class PassiveAutoTester implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("PassiveAutoTester");

        // ── Shared infrastructure ──────────────────────────────────────────────
        ExtensionLogger    logger          = new ExtensionLogger(api);
        ScopeGuard         scopeGuard      = new ScopeGuard(api);
        DeduplicationCache dedupCache      = new DeduplicationCache();
        RateLimiter        rateLimiter     = new RateLimiter();
        BaselineFetcher    baselineFetcher = new BaselineFetcher(api, scopeGuard);

        // ── Thread pool — 2 concurrent background threads (lean footprint) ─────
        ExecutorService executor = Executors.newFixedThreadPool(2);

        // ── Test modules in priority order ─────────────────────────────────────
        List<TestModule> modules = List.of(
            new SqlInjectionModule (api, scopeGuard, dedupCache, rateLimiter, logger, baselineFetcher),
            new HtmlInjectionModule(api, scopeGuard, dedupCache, rateLimiter, logger, baselineFetcher),
            new JsUriModule        (api, scopeGuard, dedupCache, rateLimiter, logger, baselineFetcher),
            new SstiModule         (api, scopeGuard, dedupCache, rateLimiter, logger, baselineFetcher)
        );

        // ── HTTP handler (proxy traffic only, GET only, scope-gated) ──────────
        BackgroundTestHandler handler = new BackgroundTestHandler(
                api, scopeGuard, logger, executor, modules, baselineFetcher);
        api.http().registerHttpHandler(handler);

        // ── Graceful shutdown ──────────────────────────────────────────────────
        api.extension().registerUnloadingHandler(() -> {
            executor.shutdown();
            logger.logStats();
            api.logging().logToOutput("[PassiveAutoTester] Unloaded.");
        });

        api.logging().logToOutput("[PassiveAutoTester] Loaded — headless mode, 2 test threads.");
        api.logging().logToOutput("[PassiveAutoTester] ⚠ Only in-scope targets are tested.");
    }
}
