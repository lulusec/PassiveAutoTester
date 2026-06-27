package com.autotest;

/**
 * Enforces a 300 ms delay between consecutive payload requests.
 * Called on the background test thread — blocking is intentional.
 */
public class RateLimiter {

    private static final long DELAY_MS = 300L;

    /** Blocks the calling thread for 300 ms. Respects thread interruption. */
    public void throttle() {
        try {
            Thread.sleep(DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
