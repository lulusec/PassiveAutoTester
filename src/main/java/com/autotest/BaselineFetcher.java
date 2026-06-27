package com.autotest;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Fetches and caches a single unmodified baseline response per unique request shape.
 *
 * Cache key: method + host:port + path-without-query + sorted URL param names
 *
 * The baseline request itself passes through ScopeGuard before being sent.
 * If scope check fails, null is returned and all testing for that request is aborted.
 */
public class BaselineFetcher {

    private final MontoyaApi    api;
    private final ScopeGuard    scopeGuard;
    private final ConcurrentHashMap<String, BaselineResult> cache = new ConcurrentHashMap<>();

    public BaselineFetcher(MontoyaApi api, ScopeGuard scopeGuard) {
        this.api        = api;
        this.scopeGuard = scopeGuard;
    }

    /**
     * Returns a cached baseline, or fetches a fresh one.
     * Returns null if scope check fails or the request cannot be sent.
     */
    public BaselineResult getOrFetch(HttpRequest request) {
        String key = cacheKey(request);
        // computeIfAbsent is atomic — only one thread fetches per key
        return cache.computeIfAbsent(key, k -> fetchBaseline(request));
    }

    // ── private ───────────────────────────────────────────────────────────────

    private BaselineResult fetchBaseline(HttpRequest request) {
        // SCOPE GATE — baseline itself must be in scope
        if (!scopeGuard.check(request.url())) {
            return null;
        }
        try {
            long start = System.currentTimeMillis();
            HttpRequestResponse rr = api.http().sendRequest(request);
            long elapsed = System.currentTimeMillis() - start;

            if (!rr.hasResponse()) return null;
            HttpResponse resp = rr.response();

            String body = new String(resp.body().getBytes(), StandardCharsets.UTF_8);
            return new BaselineResult(resp.statusCode(), resp.body().length(), body, elapsed);

        } catch (Exception e) {
            return null;
        }
    }

    private static String cacheKey(HttpRequest req) {
        List<String> sortedNames = req.parameters().stream()
                .filter(p -> p.type() == HttpParameterType.URL)
                .map(ParsedHttpParameter::name)
                .sorted()
                .collect(Collectors.toList());

        String hostPort = req.httpService().host() + ":" + req.httpService().port();
        String pathOnly = pathWithoutQuery(req.url());
        return req.method() + ":" + hostPort + pathOnly + "?{" + String.join(",", sortedNames) + "}";
    }

    private static String pathWithoutQuery(String url) {
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    // ── Inner result ──────────────────────────────────────────────────────────

    /** Immutable snapshot of a baseline response. */
    public static final class BaselineResult {

        public final int    statusCode;
        public final int    bodyLength;    // bytes
        public final String bodyContent;  // decoded UTF-8 body
        public final long   responseTimeMs;

        public BaselineResult(int statusCode, int bodyLength, String bodyContent, long responseTimeMs) {
            this.statusCode     = statusCode;
            this.bodyLength     = bodyLength;
            this.bodyContent    = bodyContent;
            this.responseTimeMs = responseTimeMs;
        }

        /** True if otherStatus matches baseline status. */
        public boolean statusMatches(int otherStatus) {
            return this.statusCode == otherStatus;
        }

        /**
         * True if |bodyLength - otherLength| / bodyLength ≤ toleranceFraction.
         * (0.05 = 5%, 0.10 = 10%)
         */
        public boolean bodyWithinTolerance(int otherLength, double toleranceFraction) {
            if (bodyLength == 0) return otherLength == 0;
            double diff = Math.abs((double)(bodyLength - otherLength)) / (double) bodyLength;
            return diff <= toleranceFraction;
        }

        /** Convenience: checks status AND body within given fraction. */
        public boolean matchesBaseline(int otherStatus, int otherBodyLength, double toleranceFraction) {
            return statusMatches(otherStatus) && bodyWithinTolerance(otherBodyLength, toleranceFraction);
        }
    }
}
