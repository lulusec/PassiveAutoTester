package com.autotest;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-request payload budget counter.
 *
 * Maximum 25 payload requests (including baseline) per original GET request.
 * Thread-safe via AtomicInteger — multiple modules share one instance per request.
 */
public class PayloadBudget {

    public static final int MAX_PAYLOADS = 25;

    private final AtomicInteger count = new AtomicInteger(0);

    /** Returns true and atomically increments if budget is still available. */
    public boolean consume() {
        // getAndIncrement returns the value BEFORE incrementing.
        // If it is < MAX, we are within budget.
        return count.getAndIncrement() < MAX_PAYLOADS;
    }

    /** Peek: is any budget remaining? (May race — use consume() to atomically claim.) */
    public boolean canSend() {
        return count.get() < MAX_PAYLOADS;
    }

    /** How many slots have been consumed so far (capped at MAX). */
    public int used() {
        return Math.min(count.get(), MAX_PAYLOADS);
    }

    /** How many slots remain. */
    public int remaining() {
        return Math.max(0, MAX_PAYLOADS - count.get());
    }
}
