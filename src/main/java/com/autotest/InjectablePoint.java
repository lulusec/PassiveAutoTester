package com.autotest;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Represents a single injection point within a request: either a URL query
 * parameter or one of the four testable HTTP headers.
 *
 * The {@link #buildRequest(String)} method returns a modified copy of the
 * original request with the injection point set to the given full value.
 * Callers are responsible for constructing the full value
 * (e.g. {@code originalValue + "'"} for SQLi break, or just the payload
 * for HTML/JS-URI/SSTI injection).
 */
public final class InjectablePoint {

    /** Display name of the injection point (parameter name or header name). */
    public final String name;

    /** The value this injection point had in the original unmodified request. */
    public final String originalValue;

    /** Human-readable type string for reporting: "query parameter" or "header". */
    public final String pointType;

    private final Function<String, HttpRequest> requestBuilder;

    private InjectablePoint(String name, String originalValue, String pointType,
                             Function<String, HttpRequest> requestBuilder) {
        this.name           = name;
        this.originalValue  = originalValue;
        this.pointType      = pointType;
        this.requestBuilder = requestBuilder;
    }

    /**
     * Returns a copy of the original request with this injection point set
     * to {@code fullValue}.  The original request is never modified.
     */
    public HttpRequest buildRequest(String fullValue) {
        return requestBuilder.apply(fullValue);
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    /**
     * Produces the ordered list of injectable points for a GET request.
     *
     * Priority (per spec):
     *   1. URL query parameters, sorted alphabetically by name
     *   2. Headers in the order: User-Agent, Referer, X-Forwarded-For, X-Custom-IP-Authorization
     */
    public static List<InjectablePoint> from(HttpRequest request) {
        List<InjectablePoint> points = new ArrayList<>();

        // ── Query parameters (alphabetically sorted) ──────────────────────────
        request.parameters().stream()
                .filter(p -> p.type() == HttpParameterType.URL)
                .sorted((a, b) -> a.name().compareToIgnoreCase(b.name()))
                .forEach(param -> {
                    final String pName  = param.name();
                    final String pValue = param.value();
                    points.add(new InjectablePoint(
                            pName, pValue, "query parameter",
                            value -> request.withUpdatedParameters(
                                    HttpParameter.parameter(pName, value, HttpParameterType.URL))
                    ));
                });

        // ── Headers ───────────────────────────────────────────────────────────
        for (String hName : INJECTABLE_HEADERS) {
            final String existing = headerValue(request, hName);
            points.add(new InjectablePoint(
                    hName,
                    existing != null ? existing : "",
                    "header",
                    value -> setHeader(request, hName, value)
            ));
        }

        return points;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static final String[] INJECTABLE_HEADERS = {
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "X-Custom-IP-Authorization"
    };

    /** Case-insensitive header lookup; returns null if absent. */
    private static String headerValue(HttpRequest req, String name) {
        return req.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(HttpHeader::value)
                .findFirst()
                .orElse(null);
    }

    /** Upsert a header: update if it already exists, otherwise add it. */
    private static HttpRequest setHeader(HttpRequest req, String name, String value) {
        boolean exists = req.headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase(name));
        HttpHeader header = HttpHeader.httpHeader(name, value);
        return exists ? req.withUpdatedHeader(header) : req.withAddedHeader(header);
    }
}
