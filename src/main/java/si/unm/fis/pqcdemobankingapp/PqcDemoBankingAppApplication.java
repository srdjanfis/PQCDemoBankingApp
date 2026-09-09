package si.unm.fis.pqcdemobankingapp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;

@SpringBootApplication
public class PqcDemoBankingAppApplication {

    // Pokreni sa -Dpqc.tls.enabled=false da dobiješ KLASIČAN TLS baseline
    // (standardni JDK JSSE, bez ML-KEM/ML-DSA šema) — koristi se zajedno
    // sa spring.profiles.active=classic i application-classic.properties.
    private static final boolean PQC_TLS_ENABLED =
            !"false".equalsIgnoreCase(System.getProperty("pqc.tls.enabled", "true"));

    static {
        // BC provajder je uvek potreban — koristi ga PqcSignatureService za
        // ML-DSA-65 potpis na nivou aplikacije, nezavisno od TLS rezima.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        if (PQC_TLS_ENABLED) {
            String schemes = "mldsa65,mldsa44,mldsa87,dilithium3,dilithium2,dilithium5,ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256";
            String groups = "x25519,secp256r1,secp384r1,mlkem768";

            System.setProperty("org.bouncycastle.jsse.server.signatureSchemes", schemes);
            System.setProperty("org.bouncycastle.jsse.client.signatureSchemes", schemes);
            System.setProperty("org.bouncycastle.jsse.server.signatureSchemesCert", schemes);
            System.setProperty("org.bouncycastle.jsse.client.signatureSchemesCert", schemes);
            System.setProperty("org.bouncycastle.jsse.server.namedGroups", groups);
            System.setProperty("org.bouncycastle.jsse.client.namedGroups", groups);

            // BCJSSE na poziciju 1 da ga Tomcat primarno koristi za SSLContext.
            if (Security.getProvider("BCJSSE") == null) {
                Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
            }

            Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
            Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");

            System.out.println(">>> TLS rezim: PQC (BCJSSE, ML-KEM-768 + ML-DSA-65)");
        } else {
            // Namerno NE registrujemo BCJSSE — Tomcat ostaje na podrazumevanom
            // JDK SunJSSE stack-u sa klasičnim algoritmima (EC/ECDSA sertifikat).
            System.out.println(">>> TLS rezim: KLASIČAN (standardni JDK JSSE, bez PQC šema)");
        }
    }

    public static void main(String[] args) {
        String keystoreResource = PQC_TLS_ENABLED ? "/keystore-pqc.p12" : "/keystore-classic.p12";
        String keystoreAlias = PQC_TLS_ENABLED ? "pqckey" : "classickey";

        try (InputStream is = PqcDemoBankingAppApplication.class.getResourceAsStream(keystoreResource)) {
            if (is != null) {
                // Za PQC keystore eksplicitno tražimo BC (jer čuva ML-DSA ključ);
                // za klasičan keystore koristimo podrazumevani JDK provider.
                KeyStore ks = PQC_TLS_ENABLED
                        ? KeyStore.getInstance("PKCS12", "BC")
                        : KeyStore.getInstance("PKCS12");
                ks.load(is, "changeit".toCharArray());
                System.out.println(">>> Učitan keystore (" + keystoreResource + "), algoritam ključa: "
                        + ks.getCertificate(keystoreAlias).getPublicKey().getAlgorithm());
            } else {
                System.err.println("Upozorenje: keystore " + keystoreResource + " nije pronađen na classpath-u.");
            }
        } catch (Exception e) {
            System.err.println("Upozorenje pri proveri keystore-a: " + e.getMessage());
        }

        SpringApplication.run(PqcDemoBankingAppApplication.class, args);
    }
}
