package si.unm.fis.pqcdemobankingapp;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

public class PqcKeystoreGenerator {

    public static void main(String[] args) {
        try {
            // Registracija Bouncy Castle provajdera
            Security.addProvider(new BouncyCastleProvider());

            // 1. Generisanje ML-DSA-65 para ključeva
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
            KeyPair keyPair = kpg.generateKeyPair();

            // 2. Kreiranje X.509 Self-Signed sertifikata
            long now = System.currentTimeMillis();
            Date startDate = new Date(now);
            Date endDate = new Date(now + (365L * 24 * 60 * 60 * 1000)); // Trajanje: 1 godina

            X500Name dnName = new X500Name("CN=localhost, OU=Banking, O=ITS, L=Novo Mesto, C=SI");
            BigInteger certSerialNumber = BigInteger.valueOf(now);

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic()
            );

            ContentSigner contentSigner = new JcaContentSignerBuilder("ML-DSA-65")
                    .setProvider("BC")
                    .build(keyPair.getPrivate());

            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certBuilder.build(contentSigner));

            // 3. Pakovanje u PKCS12 KeyStore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry(
                    "pqckey",
                    keyPair.getPrivate(),
                    "changeit".toCharArray(),
                    new Certificate[]{cert}
            );

            // 4. Snimanje u src/main/resources/keystore-pqc.p12
            String outputPath = "src/main/resources/keystore-pqc.p12";
            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                keyStore.store(fos, "changeit".toCharArray());
            }

            System.out.println("USPEH: Sertifikat je kreiran na lokaciji: " + outputPath);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
