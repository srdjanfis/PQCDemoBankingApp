package si.unm.fis.pqcdemobankingapp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import si.unm.fis.pqcdemobankingapp.dto.PublicKeyResponse;
import si.unm.fis.pqcdemobankingapp.dto.TransferRequest;
import si.unm.fis.pqcdemobankingapp.dto.TransferResponse;
import si.unm.fis.pqcdemobankingapp.service.PqcSignatureService;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Benchmark klijent koji poredi:
 *  - PQC-TLS (BCJSSE, ML-KEM-768 + ML-DSA-65 sertifikat) naspram klasičnog TLS 1.3
 *  - potpisan (/transfer) naspram nepotpisanog (/transfer-unsigned) odgovora
 *  - keep-alive (realan produkcioni scenario) naspram fresh-connection-per-request
 *    (izoluje čist trošak TLS handshake-a)
 *
 * VAŽNO: namerno koristi HttpsURLConnection (setSSLSocketFactory), a ne
 * java.net.http.HttpClient. HttpClient interno gradi sopstveni SSLParameters
 * i primenjuje ga preko standardnog javax.net.ssl API-ja, čime prepiše/obriše
 * BC-specifične namedGroups/signatureSchemes postavljene preko system
 * property-ja — rezultat je "no selectable cipher suite" jer se mldsa65
 * potpisna šema izgubi iz ponude. HttpsURLConnection to ne radi.
 *
 * Zahteva da oba servera budu upaljena pre pokretanja:
 *   Terminal 1 (PQC):      mvn spring-boot:run
 *   Terminal 2 (klasičan): java -Dpqc.tls.enabled=false -Dspring.profiles.active=classic -jar target/*.jar
 *
 * Pokreni ovu klasu iz istog Maven modula (isti classpath sa BC i Jackson
 * zavisnostima, i pristupom projektnim DTO/servisnim klasama).
 */
public class PqcBankingBenchmarkClient {

    private static final String PQC_HOST = "https://localhost:8443";
    private static final String CLASSIC_HOST = "https://localhost:8444";

    private static final String TRANSFER_PATH = "/api/v1/banking/transfer";
    private static final String TRANSFER_UNSIGNED_PATH = "/api/v1/banking/transfer-unsigned";
    private static final String PUBLIC_KEY_PATH = "/api/v1/banking/public-key";

    private static final int WARMUP_REQUESTS = 75;
    private static final int TOTAL_REQUESTS = 3000;
    private static final int CONCURRENCY_LEVEL = 8;
    private static final int TIMEOUT_MS = 10_000;
    private static final int REPEAT_RUNS = 3; // ponovi ceo benchmark N puta radi varijanse

    private static final ObjectMapper MAPPER = buildObjectMapper();

    static {
        String schemes = "mldsa65,mldsa44,mldsa87,dilithium3,dilithium2,dilithium5,ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256";
        String groups = "x25519,secp256r1,secp384r1,mlkem768";

        System.setProperty("org.bouncycastle.jsse.client.signatureSchemes", schemes);
        System.setProperty("org.bouncycastle.jsse.server.signatureSchemes", schemes);
        System.setProperty("org.bouncycastle.jsse.client.signatureSchemesCert", schemes);
        System.setProperty("org.bouncycastle.jsse.server.signatureSchemesCert", schemes);
        System.setProperty("org.bouncycastle.jsse.client.namedGroups", groups);
        System.setProperty("org.bouncycastle.jsse.server.namedGroups", groups);
        System.setProperty("org.bouncycastle.jsse.client.acceptUnknownCLI", "true");

        if (Security.getProvider("BCJSSE") == null) {
            Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
        }
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 2);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("==================================================================");
        System.out.println("  PQC vs KLASICAN TLS BANKING BENCHMARK (ML-DSA-65 / ML-KEM-768)  ");
        System.out.println("  " + TOTAL_REQUESTS + " zahteva po scenariju, " + REPEAT_RUNS + " ponavljanja  ");
        System.out.println("==================================================================\n");

        Map<String, List<Scenario>> aggregate = new LinkedHashMap<>();

        for (int run = 1; run <= REPEAT_RUNS; run++) {
            System.out.println("\n########## PROLAZ " + run + "/" + REPEAT_RUNS + " ##########");

            List<BenchmarkResult> results = new ArrayList<>();
            results.add(runSuiteFor("PQC-TLS", PQC_HOST, true));
            results.add(runSuiteFor("Klasican TLS", CLASSIC_HOST, false));

            printComparisonSummary(results);

            for (BenchmarkResult r : results) {
                addToAggregate(aggregate, r.label + " | potpisano,   keep-alive", r.signedKeepAlive);
                addToAggregate(aggregate, r.label + " | nepotpisano, keep-alive", r.unsignedKeepAlive);
                addToAggregate(aggregate, r.label + " | potpisano,   fresh-conn", r.signedFreshConn);
                addToAggregate(aggregate, r.label + " | nepotpisano, fresh-conn", r.unsignedFreshConn);
            }
        }

        printAggregateAcrossRuns(aggregate);
    }

    private static void addToAggregate(Map<String, List<Scenario>> aggregate, String key, Scenario scenario) {
        aggregate.computeIfAbsent(key, k -> new ArrayList<>()).add(scenario);
    }

    private static double mean(List<Double> values) {
        return values.stream().mapToDouble(Double::doubleValue).average().orElse(0);
    }

    private static double stddev(List<Double> values) {
        if (values.size() < 2) return 0;
        double m = mean(values);
        double sumSq = values.stream().mapToDouble(v -> (v - m) * (v - m)).sum();
        return Math.sqrt(sumSq / (values.size() - 1));
    }

    private static void printAggregateAcrossRuns(Map<String, List<Scenario>> aggregate) {
        System.out.println("\n==================================================================");
        System.out.println("      AGREGAT PREKO " + REPEAT_RUNS + " PROLAZA (srednja vrednost ± stddev)      ");
        System.out.println("==================================================================");
        for (Map.Entry<String, List<Scenario>> entry : aggregate.entrySet()) {
            List<Double> tpsValues = new ArrayList<>();
            List<Double> avgValues = new ArrayList<>();
            for (Scenario s : entry.getValue()) {
                tpsValues.add(s.throughput());
                avgValues.add(s.avgMs);
            }
            System.out.printf("%-42s tps=%7.1f ± %5.1f   avg=%6.2fms ± %5.2f%n",
                    entry.getKey(), mean(tpsValues), stddev(tpsValues), mean(avgValues), stddev(avgValues));
        }
    }

    // ---------- Orkestracija jedne mete (jednog servera) ----------

    private static BenchmarkResult runSuiteFor(String label, String host, boolean pqc) throws Exception {
        System.out.println("------------------------------------------------------------------");
        System.out.println("META: " + label + "  (" + host + ")");
        System.out.println("------------------------------------------------------------------");

        SSLSocketFactory factory = pqc ? createPqcSocketFactory() : createClassicSocketFactory();

        PublicKey serverSigningKey = null;
        try {
            serverSigningKey = fetchPublicKey(host, factory);
            System.out.println("Javni ML-DSA-65 kljuc servera preuzet (" + serverSigningKey.getAlgorithm() + ").");
        } catch (Exception e) {
            System.out.println("UPOZORENJE: nisam mogao da preuzmem javni kljuc sa " + host
                    + PUBLIC_KEY_PATH + " (" + e + ") - potpisi se nece verifikovati.");
        }

        BenchmarkResult result = new BenchmarkResult(label);
        result.signedKeepAlive = runScenario(host + TRANSFER_PATH, factory, true, false, serverSigningKey, "potpisano   / keep-alive  ");
        result.unsignedKeepAlive = runScenario(host + TRANSFER_UNSIGNED_PATH, factory, false, false, null, "nepotpisano / keep-alive  ");
        result.signedFreshConn = runScenario(host + TRANSFER_PATH, factory, true, true, serverSigningKey, "potpisano   / fresh-conn  ");
        result.unsignedFreshConn = runScenario(host + TRANSFER_UNSIGNED_PATH, factory, false, true, null, "nepotpisano / fresh-conn  ");

        System.out.println();
        return result;
    }

    private static Scenario runScenario(String url, SSLSocketFactory factory, boolean expectSignature,
                                        boolean freshConnectionPerRequest, PublicKey verifyKey,
                                        String label) throws Exception {

        System.out.print("  -> " + label + " ... ");

        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            try {
                sendOnce(factory, url, freshConnectionPerRequest);
            } catch (Exception ignored) {
                // warmup - ignorisemo greske
            }
        }

        ConcurrentLinkedQueue<Long> latencies = new ConcurrentLinkedQueue<>();
        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger failure = new AtomicInteger(0);
        AtomicInteger verified = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(CONCURRENCY_LEVEL);
        long startNanos = System.nanoTime();

        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < TOTAL_REQUESTS; i++) {
            futures.add(executor.submit(() -> {
                long reqStart = System.nanoTime();
                try {
                    RequestResult rr = sendOnce(factory, url, freshConnectionPerRequest);
                    long latencyMs = (System.nanoTime() - reqStart) / 1_000_000;

                    if (rr.statusCode == 200) {
                        success.incrementAndGet();
                        latencies.add(latencyMs);

                        if (expectSignature && verifyKey != null) {
                            TransferResponse parsed = MAPPER.readValue(rr.body, TransferResponse.class);
                            if (PqcSignatureService.verify(parsed, verifyKey)) {
                                verified.incrementAndGet();
                            }
                        }
                    } else {
                        failure.incrementAndGet();
                    }
                } catch (Exception e) {
                    failure.incrementAndGet();
                }
            }));
        }
        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        double totalSeconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        System.out.println("gotovo.");

        return Scenario.from(latencies, success.get(), failure.get(), verified.get(), expectSignature, totalSeconds);
    }

    // ---------- HTTP pozivi (HttpsURLConnection) ----------

    private static class RequestResult {
        final int statusCode;
        final String body;
        RequestResult(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }
    }

    private static RequestResult sendOnce(SSLSocketFactory factory, String url, boolean freshConnection) throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        conn.setSSLSocketFactory(factory);
        conn.setHostnameVerifier((hostname, session) -> true);
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        if (freshConnection) {
            // Forsira zatvaranje konekcije posle odgovora -> sledeci zahtev
            // mora da otvori novu TLS konekciju (meri cist handshake trosak).
            conn.setRequestProperty("Connection", "close");
        }
        conn.setDoOutput(true);

        TransferRequest body = randomTransferRequest();
        String json = MAPPER.writeValueAsString(body);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }

        int status = conn.getResponseCode();
        InputStream is = (status == 200) ? conn.getInputStream() : conn.getErrorStream();
        String responseBody = is != null ? new String(is.readAllBytes(), StandardCharsets.UTF_8) : "";

        if (freshConnection) {
            conn.disconnect();
        }
        // U keep-alive rezimu NE zovemo disconnect() - JDK sam vraca konekciju
        // u interni keep-alive pool posto je stream do kraja procitan.

        return new RequestResult(status, responseBody);
    }

    private static TransferRequest randomTransferRequest() {
        return new TransferRequest(
                "RS35" + ThreadLocalRandom.current().nextLong(100000000L, 999999999L),
                "RS35" + ThreadLocalRandom.current().nextLong(100000000L, 999999999L),
                BigDecimal.valueOf(ThreadLocalRandom.current().nextDouble(1, 5000)).setScale(2, RoundingMode.HALF_UP),
                "EUR"
        );
    }

    private static PublicKey fetchPublicKey(String host, SSLSocketFactory factory) throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) new URL(host + PUBLIC_KEY_PATH).openConnection();
        conn.setSSLSocketFactory(factory);
        conn.setHostnameVerifier((hostname, session) -> true);
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setRequestMethod("GET");

        int status = conn.getResponseCode();
        if (status != 200) {
            throw new IllegalStateException("HTTP " + status);
        }

        String responseBody = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        PublicKeyResponse pk = MAPPER.readValue(responseBody, PublicKeyResponse.class);
        byte[] keyBytes = Base64.getDecoder().decode(pk.getPublicKeyBase64());
        KeyFactory kf = KeyFactory.getInstance(PqcSignatureService.ALGORITHM, PqcSignatureService.PROVIDER_NAME);
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    // ---------- SSL podešavanje ----------

    private static SSLSocketFactory createPqcSocketFactory() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        ctx.init(null, trustAllCerts(), new SecureRandom());
        return ctx.getSocketFactory();
    }

    private static SSLSocketFactory createClassicSocketFactory() throws Exception {
        // Eksplicitno "SunJSSE" da klasican scenario zaista prolazi kroz
        // standardni JDK TLS stack, a ne kroz BCJSSE (i dalje registrovan u JVM-u).
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "SunJSSE");
        ctx.init(null, trustAllCerts(), new SecureRandom());
        return ctx.getSocketFactory();
    }

    private static TrustManager[] trustAllCerts() {
        // Samo za lokalni benchmark sa samopotpisanim sertifikatima.
        // NE koristiti ovakav TrustManager u produkciji.
        return new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
    }

    private static ObjectMapper buildObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }

    // ---------- Statistika i izveštaj ----------

    private static long percentile(List<Long> sorted, double p) {
        if (sorted.isEmpty()) return 0;
        int idx = (int) Math.ceil((p / 100.0) * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(idx, sorted.size() - 1)));
    }

    private static class Scenario {
        int success, failure, verified;
        boolean expectSignature;
        double totalSeconds;
        double avgMs, minMs, maxMs;
        long p50, p95, p99;

        static Scenario from(ConcurrentLinkedQueue<Long> latenciesQ, int success, int failure,
                             int verified, boolean expectSignature, double totalSeconds) {
            Scenario s = new Scenario();
            s.success = success;
            s.failure = failure;
            s.verified = verified;
            s.expectSignature = expectSignature;
            s.totalSeconds = totalSeconds;

            List<Long> sorted = new ArrayList<>(latenciesQ);
            Collections.sort(sorted);
            s.avgMs = sorted.stream().mapToLong(Long::longValue).average().orElse(0);
            s.minMs = sorted.isEmpty() ? 0 : sorted.get(0);
            s.maxMs = sorted.isEmpty() ? 0 : sorted.get(sorted.size() - 1);
            s.p50 = percentile(sorted, 50);
            s.p95 = percentile(sorted, 95);
            s.p99 = percentile(sorted, 99);
            return s;
        }

        double throughput() {
            return totalSeconds > 0 ? success / totalSeconds : 0;
        }

        void print() {
            System.out.printf("uspesnih=%d/%d  tps=%6.1f  avg=%6.1fms  p50=%4dms  p95=%4dms  p99=%4dms  min=%4.0fms  max=%5.0fms",
                    success, success + failure, throughput(), avgMs, p50, p95, p99, minMs, maxMs);
            if (expectSignature) {
                System.out.printf("  verifikovano=%d/%d", verified, success);
            }
            System.out.println();
        }
    }

    private static class BenchmarkResult {
        final String label;
        Scenario signedKeepAlive, unsignedKeepAlive, signedFreshConn, unsignedFreshConn;

        BenchmarkResult(String label) { this.label = label; }
    }

    private static void printComparisonSummary(List<BenchmarkResult> results) {
        System.out.println("==================================================================");
        System.out.println("                       REZIME / POREDJENJE                         ");
        System.out.println("==================================================================");
        for (BenchmarkResult r : results) {
            System.out.println("\n" + r.label + ":");
            System.out.print("  potpisano,   keep-alive: "); r.signedKeepAlive.print();
            System.out.print("  nepotpisano, keep-alive: "); r.unsignedKeepAlive.print();
            System.out.print("  potpisano,   fresh-conn: "); r.signedFreshConn.print();
            System.out.print("  nepotpisano, fresh-conn: "); r.unsignedFreshConn.print();
        }

        System.out.println("\nTumacenje:");
        System.out.println(" - keep-alive vs fresh-conn (isti red)     = cena TLS handshake-a po zahtevu");
        System.out.println(" - PQC-TLS vs Klasican TLS (isti scenario) = cena ML-KEM-768/ML-DSA-65 u TLS handshake-u");
        System.out.println(" - potpisano vs nepotpisano (isti red)     = cena ML-DSA-65 potpisa/verifikacije na app nivou");
    }
}