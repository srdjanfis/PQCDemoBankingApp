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

    static {
        // 1. Postavljanje BCJSSE svojstava pre registracije provajdera
        String schemes = "mldsa65,mldsa44,mldsa87,dilithium3,dilithium2,dilithium5,ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256";
        String groups = "x25519,secp256r1,secp384r1,mlkem768";

        System.setProperty("org.bouncycastle.jsse.server.signatureSchemes", schemes);
        System.setProperty("org.bouncycastle.jsse.client.signatureSchemes", schemes);
        System.setProperty("org.bouncycastle.jsse.server.signatureSchemesCert", schemes);
        System.setProperty("org.bouncycastle.jsse.client.signatureSchemesCert", schemes);
        System.setProperty("org.bouncycastle.jsse.server.namedGroups", groups);
        System.setProperty("org.bouncycastle.jsse.client.namedGroups", groups);

        // 2. KLJUČNO: BCJSSE stavljamo na poziciju 1 da ga Tomcat primarno koristi za SSLContext
        if (Security.getProvider("BCJSSE") == null) {
            Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
        }
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 2);
        }

        Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
        Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");
    }

    public static void main(String[] args) {
        // Provera učitavanja PQC ključa u konzoli pre podizanja Spring-a
        try (InputStream is = PqcDemoBankingAppApplication.class.getResourceAsStream("/keystore-pqc.p12")) {
            if (is != null) {
                KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
                ks.load(is, "changeit".toCharArray());
                System.out.println(">>> Uspesno ucitan PQC Keystore! Alijas 'pqckey' algoritam: "
                        + ks.getCertificate("pqckey").getPublicKey().getAlgorithm());
            }
        } catch (Exception e) {
            System.err.println("Upozorenje pri proveri keystore-a: " + e.getMessage());
        }

        SpringApplication.run(PqcDemoBankingAppApplication.class, args);
    }
}
