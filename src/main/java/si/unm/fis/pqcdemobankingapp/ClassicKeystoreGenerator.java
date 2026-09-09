package si.unm.fis.pqcdemobankingapp;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/*
 Generiše KLASIČAN (ne-PQC) EC/ECDSA samopotpisani sertifikat i PKCS12
 keystore koji služi kao "obična" TLS 1.3 baseline konfiguracija za
 poređenje sa PQC (ML-KEM/ML-DSA) konfiguracijom iz PqcKeystoreGenerator-a.

 Namerno NE traži "BC" provajder za sam ključ/keystore (samo bcpkix klase
 za X.509 strukturu) — tako da rezultujući profil (application-classic.properties)
 radi sa čisto standardnim JDK JSSE stack-om, bez BCJSSE u igri.

 Pokreni jednom, isto kao PqcKeystoreGenerator, pre pokretanja "classic" profila.
*/
public class ClassicKeystoreGenerator {

    public static void main(String[] args) throws Exception {
        // 1. Klasičan EC (P-256) par ključeva — standardni JDK provider
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        // 2. X.509 self-signed sertifikat, SHA256withECDSA
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + (365L * 24 * 60 * 60 * 1000));

        X500Name dnName = new X500Name("CN=localhost, OU=Banking, O=ITS, L=Novo Mesto, C=SI");
        BigInteger certSerialNumber = BigInteger.valueOf(now);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(keyPair.getPrivate());

        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(contentSigner));

        // 3. Standardni PKCS12 keystore (podrazumevani JDK provider)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(
                "classickey",
                keyPair.getPrivate(),
                "changeit".toCharArray(),
                new Certificate[]{cert}
        );

        String outputPath = "src/main/resources/keystore-classic.p12";
        try (FileOutputStream fos = new FileOutputStream(outputPath)) {
            keyStore.store(fos, "changeit".toCharArray());
        }

        System.out.println("USPEH: Klasičan (EC/ECDSA) sertifikat kreiran na lokaciji: " + outputPath);
    }
}
