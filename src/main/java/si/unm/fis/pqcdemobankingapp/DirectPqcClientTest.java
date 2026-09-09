package si.unm.fis.pqcdemobankingapp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.X509Certificate;

public class DirectPqcClientTest {

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

    public static void main(String[] args) {
        try {
            // TrustManager koji prihvata samopotpisani sertifikat
            TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };

            // Kreiramo SSLContext izričito preko BCJSSE provajdera
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
            sslContext.init(null, trustAll, new java.security.SecureRandom());

            URL url = new URL("https://localhost:8443/api/v1/bank/transaction");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // Postavljamo BCJSSE Socket Factory i HostnameVerifier
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.setHostnameVerifier((hostname, session) -> true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            String body = "{\"amount\": 100}";
            try (OutputStream os = connection.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int code = connection.getResponseCode();
            System.out.println(">>> TLS 1.3 ML-DSA-65 HANDSHAKE USPEO! Status kod: " + code);

            InputStream is = (code == 200) ? connection.getInputStream() : connection.getErrorStream();
            String response = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            System.out.println(">>> Odgovor servera: " + response);

        } catch (Exception e) {
            System.err.println(">>> Greška tokom rukovanja:");
            e.printStackTrace();
        }
    }
}
