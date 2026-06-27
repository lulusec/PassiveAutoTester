package com.autotest.modules;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.autotest.BaselineFetcher;
import com.autotest.PayloadBudget;

/**
 * Contract that every test module must fulfill.
 *
 * {@link #run} is called once per original GET request that passed all gate checks.
 * The module receives:
 *   <ul>
 *     <li>The original, unmodified request snapshot.</li>
 *     <li>The cached baseline response for that request shape.</li>
 *     <li>A shared {@link PayloadBudget} counter (max 25 across ALL modules for
 *         this request — modules must call {@link PayloadBudget#consume()} before
 *         every payload and stop when it returns {@code false}).</li>
 *   </ul>
 *
 * Modules MUST NOT modify the original request.
 * Modules MUST call {@link com.autotest.ScopeGuard#check(String)} before every
 * outbound payload — the abstract base class {@link AbstractTestModule} provides
 * the helper {@code sendIfAllowed()} which enforces this automatically.
 */
public interface TestModule {
    /** Short human-readable module name used in log messages and issue titles. */
    String name();

    /** Execute all test phases against every injectable point in the request. */
    void run(HttpRequest request,
             BaselineFetcher.BaselineResult baseline,
             PayloadBudget budget);
}
