# PassiveAutoTester - Burp Suite Extension

A passive-only Burp Suite extension built on the Montoya API that automatically tests in-scope GET requests for four common web vulnerabilities. It runs entirely in the background, adds no UI panel, and never modifies or blocks your traffic.

---

## What it does

Every GET request that passes through Burp Proxy is tested automatically — provided the target URL is in your active scope. The extension sends up to 25 payload requests per original request, covers four vulnerability classes, and reports confirmed findings as native Burp `AuditIssue` entries (visible in the Target / Site Map issues tab).

### Vulnerability modules

| Module | Technique | Confidence levels |
|--------|-----------|-------------------|
| **SQL Injection** | Break-and-repair + boolean TRUE/FALSE | CERTAIN / FIRM / TENTATIVE |
| **HTML Injection** | Reflection + unique token in clean HTML context | FIRM / TENTATIVE |
| **JavaScript-URI Injection** | `javascript:` reflection + attribute context check | FIRM / TENTATIVE |
| **SSTI** | Arithmetic evaluation (7×7→49, 33×33→1089) + engine fingerprint | CERTAIN / FIRM / TENTATIVE |

### Injection points tested per request

- All URL query parameters (alphabetical order)
- `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Custom-IP-Authorization` headers

---

## How it works

```
Proxy traffic
     │
     ▼
BackgroundTestHandler.handleHttpRequestToBeSent()
     │  Gate 1: ToolType.PROXY only (prevents infinite loop on own requests)
     │  Gate 2: GET method only
     │  Gate 3: Live scope check #1
     │
     ▼
CompletableFuture.runAsync() → 2-thread pool
     │
     ▼
runTests()
     │  Scope check #2 (live, never cached)
     │  PayloadBudget (max 25 slots)
     │  BaselineFetcher (cached per URL shape, scope-gated)
     │
     ├─▶ SqlInjectionModule
     ├─▶ HtmlInjectionModule
     ├─▶ JsUriModule
     └─▶ SstiModule
              │  Each module → InjectablePoint.from(request)
              │  Each point → trySend() with scope check #N, dedup, rate limit
              └─▶ api.siteMap().add(AuditIssue)  ← finding reported
```

**Safety guarantees:**

- Scope is checked live before every single outbound payload — if the user removes a target from scope mid-session, testing stops immediately.
- SHA-256 deduplication prevents the same payload being sent twice to the same point.
- 300 ms rate limiting between payloads.
- Extension's own requests appear as `ToolType.EXTENSIONS` — the PROXY filter prevents self-triggering loops.
- No request is ever modified or blocked; `continueWith(requestToBeSent)` is always returned immediately.

---

## How to get it running

### Requirements

- **Burp Suite Professional or Community** (2023.12+ recommended)
- **Java 17+** JDK to build from source
- **Gradle 8.5** (wrapper included — no separate install needed)

---

### Option A — Load the pre-built JAR

1. Download `PassiveAutoTester-1.0.0.jar` from the Releases page.
2. Open Burp Suite → **Extensions** → **Installed** → **Add**.
3. Set **Extension type** to `Java`, select the JAR, click **Next**.
4. The Output pane will show:
   ```
   [PassiveAutoTester] Loaded — headless mode, 2 test threads.
   [PassiveAutoTester] ⚠ Only in-scope targets are tested.
   ```

---

### Option B — Build from source

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/PassiveAutoTester.git
cd PassiveAutoTester

# 2. Build the fat JAR (downloads Gradle 8.5 on first run)
./gradlew jar          # Linux / macOS
gradlew.bat jar        # Windows

# 3. The JAR lands at:
#    build/libs/PassiveAutoTester-1.0.0.jar

# 4. Load in Burp Suite (same steps as Option A)
```

> **Windows note:** If `gradlew.bat` reports Java not found, set `JAVA_HOME` to your JDK 17 installation directory before running, e.g.:
> ```bat
> set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-17.0.11.9-hotspot
> gradlew.bat jar
> ```

---

### Verifying it works

1. Add a target to Burp scope (Target → Scope → Include).
2. Browse to the target through Burp Proxy.
3. Open **Extensions → PassiveAutoTester → Output**.
4. You should see `[TESTED]` entries for each scoped GET request.
5. Any findings appear under **Target → Site Map → Issues** with the `[PassiveAutoTester]` prefix in the issue name.

---

## Configuration

There is no configuration UI — this is intentional (minimal RAM footprint). Tunable constants live directly in source:

| Constant | File | Default | Description |
|----------|------|---------|-------------|
| `MAX_PAYLOADS` | `PayloadBudget.java` | `25` | Max payloads per request |
| `DELAY_MS` | `RateLimiter.java` | `300` | ms between payloads |
| Thread count | `PassiveAutoTester.java` | `2` | Background test threads |

---

## Project structure

```
PassiveAutoTester/
├── build.gradle                        # Gradle build — fat JAR, Java 17
├── settings.gradle
├── gradlew / gradlew.bat               # Gradle wrapper (no install needed)
├── gradle/wrapper/
│   ├── gradle-wrapper.jar
│   └── gradle-wrapper.properties       # Points to Gradle 8.5
└── src/main/
    ├── resources/META-INF/services/
    │   └── burp.api.montoya.BurpExtension   # SPI registration
    └── java/com/autotest/
        ├── PassiveAutoTester.java       # Entry point — wires everything together
        ├── BackgroundTestHandler.java   # HttpHandler — proxy filter + async dispatch
        ├── BaselineFetcher.java         # Per-URL baseline cache
        ├── DeduplicationCache.java      # SHA-256 dedup map
        ├── ExtensionLogger.java         # Timestamped logging → Burp output pane
        ├── InjectablePoint.java         # URL params + header injection point factory
        ├── PayloadBudget.java           # 25-slot atomic budget counter
        ├── RateLimiter.java             # 300 ms throttle
        ├── ScopeGuard.java              # Live scope check wrapper
        └── modules/
            ├── TestModule.java          # Module interface
            ├── AbstractTestModule.java  # Shared send/report/log infrastructure
            ├── SqlInjectionModule.java  # Break-and-repair SQLi
            ├── HtmlInjectionModule.java # HTML injection via token reflection
            ├── JsUriModule.java         # javascript: URI injection
            └── SstiModule.java          # Template injection via arithmetic
```

---

## Output format

All output appears in **Extensions → PassiveAutoTester → Output** tab:

```
[14:23:01] [SKIPPED] OUT OF SCOPE — GET https://external-site.com/api
[14:23:04] [TESTED]  GET https://target.com/search?q=test — 18 payloads sent
[14:23:04] [FINDING] [SQLi] CERTAIN — [PassiveAutoTester] [SQLi] Possible SQL Injection in query parameter 'q'
[14:23:45] [STATS]   tested=12  skipped=3  payloads=187  findings=1  unconfirmed=0
```

Findings are simultaneously added to Burp's native issue tracker (Target → Issues).

---

## Known limitations

- **GET requests only** — POST, PUT, etc. are not tested.
- **Proxy source only** — requests from Repeater, Scanner, etc. are ignored.
- **No authentication handling** — if a session expires mid-test, payloads may get login-page responses that appear as false negatives.
- **25-payload budget** — complex endpoints with many parameters will exhaust the budget before all modules run.
- **Rate limiting is per-request, not global** — two simultaneous in-scope requests will each send up to 25×300 ms payloads on separate threads.

---

## License

MIT — do whatever you want, no warranty.
