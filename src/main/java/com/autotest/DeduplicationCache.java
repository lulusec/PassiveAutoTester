package com.autotest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe SHA-256 deduplication cache.
 *
 * Keyed by SHA-256(method|url|paramName|payload) — prevents sending the same
 * payload to the same parameter twice, even under concurrent access.
 *
 * Keys are added BEFORE sending (not after) to prevent race conditions
 * where two threads both decide to send the same payload simultaneously.
 */
public class DeduplicationCache {

    private final ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();

    /**
     * Attempts to claim a test slot for the given combination.
     *
     * @return true  if this combination has NOT been seen before (slot claimed — proceed to send)
     *         false if this combination was already claimed (skip silently)
     */
    public boolean shouldTest(String method, String url, String paramName, String payload) {
        String key = sha256(method + "|" + url + "|" + paramName + "|" + payload);
        // putIfAbsent returns null only if the key was absent (i.e., we just inserted it)
        return seen.putIfAbsent(key, Boolean.TRUE) == null;
    }

    /** Current number of unique test combinations claimed. */
    public int size() {
        return seen.size();
    }

    // ── private ───────────────────────────────────────────────────────────────

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available in every Java SE runtime
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
