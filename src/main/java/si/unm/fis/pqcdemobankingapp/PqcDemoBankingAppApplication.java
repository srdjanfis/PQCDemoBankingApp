package si.unm.fis.pqcdemobankingapp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;

/*
 VAŽNA NAPOMENA (posle 3 dana debugovanja):

 Originalna zamisao je bila da TLS sertifikat sam bude potpisan ML-DSA-65
 ključem (keystore-pqc.p12 / PqcKeystoreGenerator). To NE RADI sa BCJSSE
 (BouncyCastle JSSE providerom) — server dosledno odbija handshake sa
 "no selectable cipher suite" bez obzira šta klijent ponudi. Ovo je
 poznat, nerešen bug u bc-java: BCJSSE trenutno ne ume da autentifikuje
 TLS 1.3 handshake sertifikatom čiji je ključ ML-DSA (isti obrazac kao
 poznati bug za SM2 krivu). Videti: https://github.com/bcgit/bc-java/issues/2102

 Zato je PQC deo ovde SVEDEN na ono što BCJSSE stvarno podržava:
   - Hibridni ML-KEM-768 key exchange (namedGroups) — ovo RADI i ovo je
     isti mehanizam koji Chrome/Firefox koriste u produkciji danas.
   - Sertifikat je NAMERNO klasičan (EC/ECDSA), isti keystore-classic.p12
     koji koristi i "classic" profil.
   - ML-DSA-65 potpis payload-a i dalje postoji, ali isključivo na nivou
     aplikacije (PqcSignatureService) — taj deo uopšte ne dodiruje BCJSSE
     TLS/KeyManager sloj, pa nije pogođen ovim bagom.

 Rezultat: PQC-TLS profil i klasičan profil koriste IDENTIČAN sertifikat;
 jedina razlika je BCJSSE + mlkem768 vs. standardni JDK JSSE bez PQC grupa.
 To je upravo promenljiva koju benchmark treba da izoluje.
*/
@SpringBootApplication
public class PqcDemoBankingAppApplication {

    // Pokreni sa -Dpqc.tls.enabled=false da dobiješ KLASIČAN TLS baseline
    // (standardni JDK JSSE, bez ML-KEM grupe) — zajedno sa
    // spring.profiles.active=classic i application-classic.properties.
    private static final boolean PQC_TLS_ENABLED =
            !"false".equalsIgnoreCase(System.getProperty("pqc.tls.enabled", "true"));

    static {
        if (PQC_TLS_ENABLED) {
            // Samo klasične potpisne šeme — sertifikat je EC/ECDSA, ML-DSA
            // ovde namerno nije ponuđen kao TLS signature scheme (vidi napomenu gore).
            String schemes = "ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha256";
            // ML-KEM-768 hibridna grupa — ovo je stvarni PQC deo koji radi.
            String groups = "x25519,secp256r1,secp384r1,mlkem768";

            System.setProperty("org.bouncycastle.jsse.server.signatureSchemes", schemes);
            System.setProperty("org.bouncycastle.jsse.client.signatureSchemes", schemes);
            System.setProperty("org.bouncycastle.jsse.server.signatureSchemesCert", schemes);
            System.setProperty("org.bouncycastle.jsse.client.signatureSchemesCert", schemes);
            System.setProperty("org.bouncycastle.jsse.server.namedGroups", groups);
            System.setProperty("org.bouncycastle.jsse.client.namedGroups", groups);

            // BCJSSE na poziciju 1, BC odmah iza na poziciju 2.
            if (Security.getProvider("BCJSSE") == null) {
                Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
            }
            if (Security.getProvider("BC") == null) {
                Security.insertProviderAt(new BouncyCastleProvider(), 2);
            }

            Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
            Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");

            System.out.println(">>> TLS rezim: PQC (BCJSSE, hibridni ML-KEM-768 key exchange; sertifikat je klasican EC, vidi napomenu u kodu)");
        } else {
            // Namerno NE registrujemo BCJSSE — Tomcat ostaje na podrazumevanom
            // JDK SunJSSE stack-u sa klasičnim algoritmima.
            // BC i dalje treba za app-layer ML-DSA potpis (PqcSignatureService);
            // pozicija u listi ovde nije bitna jer se uvek traži po imenu "BC".
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            System.out.println(">>> TLS rezim: KLASIČAN (standardni JDK JSSE, bez PQC šema)");
        }
    }

    public static void main(String[] args) {
        // Oba profila (PQC i classic) sada koriste ISTI klasičan keystore —
        // jedina razlika je da li je BCJSSE + mlkem768 aktivan ili ne.
        try (InputStream is = PqcDemoBankingAppApplication.class.getResourceAsStream("/keystore-classic.p12")) {
            if (is != null) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(is, "changeit".toCharArray());
                System.out.println(">>> Učitan keystore-classic.p12, algoritam ključa: "
                        + ks.getCertificate("classickey").getPublicKey().getAlgorithm());
            } else {
                System.err.println("Upozorenje: keystore-classic.p12 nije pronađen na classpath-u. "
                        + "Pokreni ClassicKeystoreGenerator.main() jednom pre starta servera.");
            }
        } catch (Exception e) {
            System.err.println("Upozorenje pri proveri keystore-a: " + e.getMessage());
        }

        SpringApplication.run(PqcDemoBankingAppApplication.class, args);
    }
}