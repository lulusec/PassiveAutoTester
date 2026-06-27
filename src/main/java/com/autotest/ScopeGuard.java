package com.autotest;

import burp.api.montoya.MontoyaApi;

/**
 * Centralised scope gate — every outbound request in this extension must pass through here.
 *
 * NEVER call api.scope().isInScope() anywhere else in the codebase.
 * Always use ScopeGuard.check() so the live (no-cache) contract is enforced.
 */
public class ScopeGuard {

    private final MontoyaApi api;

    public ScopeGuard(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Hard scope gate.
     *
     * Calls Burp's scope API live — never cached — so scope changes at runtime are respected.
     *
     * @param url Full URL to test (scheme + host + path + query)
     * @return true  if the URL is actively in Burp's configured scope
     *         false if out-of-scope, scope is empty, or the check throws for any reason
     */
    public boolean check(String url) {
        if (url == null || url.isBlank()) return false;
        try {
            return api.scope().isInScope(url);
        } catch (Exception e) {
            // Fail safe: if the scope API raises, do NOT test
            return false;
        }
    }
}
