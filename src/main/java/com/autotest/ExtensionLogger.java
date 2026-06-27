package com.autotest;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Lightweight logger for the headless PassiveAutoTester extension.
 *
 * All output goes to Burp's native Extension output / error panels — zero Swing,
 * zero AWT, zero heap pressure from JTextPane/StyledDocument.
 *
 * Counters are AtomicInteger; all methods are thread-safe.
 */
public class ExtensionLogger {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final Logging logging;

    // ── Live counters ─────────────────────────────────────────────────────────
    private final AtomicInteger tested        = new AtomicInteger(0);
    private final AtomicInteger skipped       = new AtomicInteger(0);
    private final AtomicInteger findings      = new AtomicInteger(0);
    private final AtomicInteger infoOnly      = new AtomicInteger(0);
    private final AtomicInteger totalPayloads = new AtomicInteger(0);

    public ExtensionLogger(MontoyaApi api) {
        this.logging = api.logging();
    }

    // ── Log methods ───────────────────────────────────────────────────────────

    public void logTested(String url, int payloadsSent) {
        totalPayloads.addAndGet(payloadsSent);
        tested.incrementAndGet();
        out("[TESTED]  GET " + url + " — " + payloadsSent + " payloads sent");
    }

    public void logSkipped(String url) {
        skipped.incrementAndGet();
        out("[SKIPPED] OUT OF SCOPE — GET " + url);
    }

    public void logFinding(String message) {
        findings.incrementAndGet();
        out("[FINDING] " + message);
    }

    public void logInfo(String message) {
        infoOnly.incrementAndGet();
        out("[INFO]    " + message);
    }

    public void logError(String url, String reason) {
        err("[ERROR]   " + url + " — " + reason);
    }

    public void logRaw(String message) {
        out(message);
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    public void logStats() {
        out(String.format(
            "[STATS] tested=%d  skipped=%d  payloads=%d  findings=%d  unconfirmed=%d",
            tested.get(), skipped.get(), totalPayloads.get(), findings.get(), infoOnly.get()));
    }

    public int getTested()        { return tested.get();        }
    public int getSkipped()       { return skipped.get();       }
    public int getFindings()      { return findings.get();      }
    public int getInfoOnly()      { return infoOnly.get();      }
    public int getTotalPayloads() { return totalPayloads.get(); }

    // ── Private ───────────────────────────────────────────────────────────────

    private void out(String message) {
        logging.logToOutput("[" + LocalTime.now().format(TIME_FMT) + "] " + message);
    }

    private void err(String message) {
        logging.logToError("[" + LocalTime.now().format(TIME_FMT) + "] " + message);
    }
}
