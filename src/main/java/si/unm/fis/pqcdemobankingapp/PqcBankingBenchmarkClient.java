package si.unm.fis.pqcdemobankingapp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class PqcBankingBenchmarkClient {

    private static final String TARGET_URL = "https://localhost:8443/api/v1/bank/transaction"; // prilagodi endpoint
    private static final String JSON_PAYLOAD = "{\"amount\": 100}";
    private static final int TOTAL_REQUESTS = 50;
    private static final int WARMUP_REQUESTS = 10;
    private static final int CONCURRENCY_LEVEL = 5;

    static {
        // 1. Postavljanje svojstava PRE registracije provajdera
        String pqcSchemes = "mldsa65,mldsa44,mldsa87,dilithium3,dilithium2,dilithium5,ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256";
        System.setProperty("org.bouncycastle.jsse.client.signatureSchemes", pqcSchemes);
        System.setProperty("org.bouncycastle.jsse.server.signatureSchemes", pqcSchemes);
        System.setProperty("org.bouncycastle.jsse.client.signatureSchemesCert", pqcSchemes);
        System.setProperty("org.bouncycastle.jsse.server.signatureSchemesCert", pqcSchemes);
        System.setProperty("org.bouncycastle.jsse.client.acceptUnknownCLI", "true");

        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        if (Security.getProvider("BCJSSE") == null) {
            Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        }

        Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
        Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("==============================================================");
        System.out.println("      STARTING PQC HTTPS + ML-DSA BENCHMARK TEST SUITE       ");
        System.out.println("==============================================================");

        HttpClient httpClient = createPqcHttpClient();

        System.out.print("Izvršavam Warmup fazu (" + WARMUP_REQUESTS + " zahteva)... ");
        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(TARGET_URL)).GET().build();
                httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (Exception ignored) {}
        }
        System.out.println("ZAVRŠENO.\n");

        System.out.println("Započinjem glavno merenje...");
        ConcurrentLinkedQueue<Long> latencies = new ConcurrentLinkedQueue<>();
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(CONCURRENCY_LEVEL);
        long globalStartTime = System.currentTimeMillis();

        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < TOTAL_REQUESTS; i++) {
            futures.add(executor.submit(() -> {
                long start = System.nanoTime();
                try {
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(TARGET_URL))
                            .header("Content-Type", "application/json")
                            .timeout(Duration.ofSeconds(5))
                            .POST(HttpRequest.BodyPublishers.ofString(JSON_PAYLOAD))
                            .build();

                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    long latencyMs = (System.nanoTime() - start) / 1_000_000;

                    if (response.statusCode() == 200) {
                        successCount.incrementAndGet();
                        latencies.add(latencyMs);
                    } else {
                        failureCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    if (failureCount.get() == 0) {
                        System.err.println("Konekcija odbijena / SSL Greška:");
                        e.printStackTrace();
                    }
                    failureCount.incrementAndGet();
                }
            }));
        }

        for (Future<?> future : futures) {
            future.get();
        }

        long globalEndTime = System.currentTimeMillis();
        executor.shutdown();

        double totalTimeSeconds = (globalEndTime - globalStartTime) / 1000.0;
        System.out.println("--------------------------------------------------------------");
        System.out.printf("Uspešni zahtevi: %d / %d%n", successCount.get(), TOTAL_REQUESTS);
        System.out.printf("Ukupno vreme: %.2f s%n", totalTimeSeconds);
        System.out.printf("Prosečni TPS: %.2f%n", successCount.get() / totalTimeSeconds);
    }

    private static HttpClient createPqcHttpClient() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

        SSLParameters sslParams = sslContext.getDefaultSSLParameters();
        try {
            sslParams.setSignatureSchemes(new String[]{"mldsa65", "mldsa44", "mldsa87", "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"});
        } catch (Throwable ignored) {}

        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }
    private static void executeWarmup(HttpClient client) {
        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(TARGET_URL))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(JSON_PAYLOAD))
                        .build();
                client.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (Exception ignored) {}
        }
    }

    private static void printResults(ConcurrentLinkedQueue<Long> latenciesQueue, int success, int failures, double totalTimeSec) {
        List<Long> latencies = new ArrayList<>(latenciesQueue);
        Collections.sort(latencies);

        double tps = success / totalTimeSec;
        double avgLatency = latencies.stream().mapToLong(Long::longValue).average().orElse(0.0);
        long minLatency = latencies.isEmpty() ? 0 : latencies.get(0);
        long maxLatency = latencies.isEmpty() ? 0 : latencies.get(latencies.size() - 1);
        long p50 = getPercentile(latencies, 50);
        long p95 = getPercentile(latencies, 95);
        long p99 = getPercentile(latencies, 99);

        System.out.println("\n==============================================================");
        System.out.println("                 BENCHMARK RESULTS REPORT                     ");
        System.out.println("==============================================================");
        System.out.printf("Ukupno vreme izvršavanja : %.2f s%n", totalTimeSec);
        System.out.printf("Uspešnih zahteva         : %d%n", success);
        System.out.printf("Neuspešnih zahteva       : %d%n", failures);
        System.out.println("--------------------------------------------------------------");
        System.out.printf("THROUGHPUT (TPS)         : %.2f req/sec%n", tps);
        System.out.println("--------------------------------------------------------------");
        System.out.printf("Prosečna latencija (Avg) : %.2f ms%n", avgLatency);
        System.out.printf("Minimalna latencija (Min): %d ms%n", minLatency);
        System.out.printf("Maksimalna latencija (Max): %d ms%n", maxLatency);
        System.out.printf("50th Percentile (P50)    : %d ms%n", p50);
        System.out.printf("95th Percentile (P95)    : %d ms%n", p95);
        System.out.printf("99th Percentile (P99)    : %d ms%n", p99);
        System.out.println("==============================================================\n");
    }

    private static long getPercentile(List<Long> sortedLatencies, double percentile) {
        if (sortedLatencies.isEmpty()) return 0;
        int index = (int) Math.ceil((percentile / 100.0) * sortedLatencies.size()) - 1;
        return sortedLatencies.get(Math.max(0, Math.min(index, sortedLatencies.size() - 1)));
    }
}
