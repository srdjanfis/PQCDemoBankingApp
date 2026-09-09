package si.unm.fis.pqcdemobankingapp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import si.unm.fis.pqcdemobankingapp.dto.PublicKeyResponse;
import si.unm.fis.pqcdemobankingapp.dto.TransferRequest;
import si.unm.fis.pqcdemobankingapp.dto.TransferResponse;
import si.unm.fis.pqcdemobankingapp.service.PqcSignatureService;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
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
 * Zahteva da oba servera budu upaljena pre pokretanja:
 *   Terminal 1 (PQC):     mvn spring-boot:run
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

    private static final int WARMUP_REQUESTS = 10;
    private static final int TOTAL_REQUESTS = 200;
    private static final int CONCURRENCY_LEVEL = 8;

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

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCJSSE") == null) {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("==================================================================");
        System.out.println("  PQC vs KLASICAN TLS BANKING BENCHMARK (ML-DSA-65 / ML-KEM-768)  ");
        System.out.println("==================================================================\n");

        List<BenchmarkResult> results = new ArrayList<>();
        results.add(runSuiteFor("PQC-TLS", PQC_HOST, true));
        results.add(runSuiteFor("Klasican TLS", CLASSIC_HOST, false));

        printComparisonSummary(results);
    }

    // ---------- Orkestracija jedne mete (jednog servera) ----------

    private static BenchmarkResult runSuiteFor(String label, String host, boolean pqc) throws Exception {
        System.out.println("------------------------------------------------------------------");
        System.out.println("META: " + label + "  (" + host + ")");
        System.out.println("------------------------------------------------------------------");

        SSLContext sslContext = pqc ? createPqcSslContext() : createClassicSslContext();

        PublicKey serverSigningKey = null;
        try {
            serverSigningKey = fetchPublicKey(host, sslContext);
            System.out.println("Javni ML-DSA-65 kljuc servera preuzet (" + serverSigningKey.getAlgorithm() + ").");
        } catch (Exception e) {
            System.out.println("UPOZORENJE: nisam mogao da preuzmem javni kljuc sa " + host
                    + PUBLIC_KEY_PATH + " (" + e.getMessage() + ") - potpisi se nece verifikovati.");
        }

        BenchmarkResult result = new BenchmarkResult(label);
        result.signedKeepAlive = runScenario(host + TRANSFER_PATH, sslContext, true, false, serverSigningKey, "potpisano   / keep-alive  ");
        result.unsignedKeepAlive = runScenario(host + TRANSFER_UNSIGNED_PATH, sslContext, false, false, null, "nepotpisano / keep-alive  ");
        result.signedFreshConn = runScenario(host + TRANSFER_PATH, sslContext, true, true, serverSigningKey, "potpisano   / fresh-conn  ");
        result.unsignedFreshConn = runScenario(host + TRANSFER_UNSIGNED_PATH, sslContext, false, true, null, "nepotpisano / fresh-conn  ");

        System.out.println();
        return result;
    }

    private static Scenario runScenario(String url, SSLContext sslContext, boolean expectSignature,
                                         boolean freshConnectionPerRequest, PublicKey verifyKey,
                                         String label) throws Exception {

        System.out.print("  -> " + label + " ... ");

        HttpClient sharedClient = freshConnectionPerRequest ? null : buildClient(sslContext);

        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            HttpClient client = freshConnectionPerRequest ? buildClient(sslContext) : sharedClient;
            try {
                sendOnce(client, url);
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
                HttpClient client = freshConnectionPerRequest ? buildClient(sslContext) : sharedClient;
                long reqStart = System.nanoTime();
                try {
                    HttpResponse<String> response = sendOnce(client, url);
                    long latencyMs = (System.nanoTime() - reqStart) / 1_000_000;

                    if (response.statusCode() == 200) {
                        success.incrementAndGet();
                        latencies.add(latencyMs);

                        if (expectSignature && verifyKey != null) {
                            TransferResponse parsed = MAPPER.readValue(response.body(), TransferResponse.class);
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

    // ---------- HTTP pozivi ----------

    private static HttpResponse<String> sendOnce(HttpClient client, String url) throws Exception {
        TransferRequest body = new TransferRequest(
                "RS35" + ThreadLocalRandom.current().nextLong(100000000L, 999999999L),
                "RS35" + ThreadLocalRandom.current().nextLong(100000000L, 999999999L),
                BigDecimal.valueOf(ThreadLocalRandom.current().nextDouble(1, 5000)).setScale(2, RoundingMode.HALF_UP),
                "EUR"
        );
        String json = MAPPER.writeValueAsString(body);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static PublicKey fetchPublicKey(String host, SSLContext sslContext) throws Exception {
        HttpClient client = buildClient(sslContext);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(host + PUBLIC_KEY_PATH))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("HTTP " + response.statusCode());
        }

        PublicKeyResponse pk = MAPPER.readValue(response.body(), PublicKeyResponse.class);
        byte[] keyBytes = Base64.getDecoder().decode(pk.getPublicKeyBase64());
        KeyFactory kf = KeyFactory.getInstance(PqcSignatureService.ALGORITHM, PqcSignatureService.PROVIDER_NAME);
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    // ---------- SSL / HTTP klijent podešavanje ----------

    private static HttpClient buildClient(SSLContext sslContext) {
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(10))
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    private static SSLContext createPqcSslContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        ctx.init(null, trustAllCerts(), new SecureRandom());
        return ctx;
    }

    private static SSLContext createClassicSslContext() throws Exception {
        // Eksplicitno "SunJSSE" (a ne bez-provider lookup) da bismo bili sigurni
        // da klasican scenario zaista prolazi kroz standardni JDK TLS stack,
        // a ne kroz BCJSSE koji je i dalje registrovan u ovom JVM procesu.
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "SunJSSE");
        ctx.init(null, trustAllCerts(), new SecureRandom());
        return ctx;
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
