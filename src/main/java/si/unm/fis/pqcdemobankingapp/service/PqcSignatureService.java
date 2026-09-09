package si.unm.fis.pqcdemobankingapp.service;

import si.unm.fis.pqcdemobankingapp.dto.PublicKeyResponse;
import si.unm.fis.pqcdemobankingapp.dto.TransferResponse;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/*
 Registruje BC provajder, generiše ML-DSA-65 par ključeva pri startu servisa
 i potpisuje/verifikuje TransferResponse objekte.

 NAPOMENA: ovaj par ključeva je NEZAVISAN od ML-DSA-65 ključa u
 keystore-pqc.p12 (koji se koristi za TLS sertifikat). Ovaj ovde je za
 potpis na nivou aplikacije (integritet/autentičnost payload-a), TLS radi
 svoj deo posla nezavisno. Ključ je efemeran — generiše se iznova pri
 svakom pokretanju servera, zato klijent mora da ga preuzme preko
 /api/v1/banking/public-key pre verifikacije.
*/

@Service
public class PqcSignatureService {

    public static final String PROVIDER_NAME = "BC";
    public static final String ALGORITHM = "ML-DSA-65";

    private KeyPair keyPair;

    @PostConstruct
    public void init() throws Exception {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER_NAME);
        keyPairGenerator.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());
        this.keyPair = keyPairGenerator.generateKeyPair();
    }

    /**
     * Generiše ML-DSA-65 potpis nad kanonskim reprezentativnim nizom DTO objekta
     * i upisuje ga u Base64 formatu u polje 'signature'.
     */
    public void signResponse(TransferResponse response) {
        try {
            byte[] dataToSign = canonicalize(response);

            Signature signature = Signature.getInstance(ALGORITHM, PROVIDER_NAME);
            signature.initSign(this.keyPair.getPrivate());
            signature.update(dataToSign);

            response.setSignature(Base64.getEncoder().encodeToString(signature.sign()));
        } catch (Exception e) {
            throw new RuntimeException("Greška pri ML-DSA-65 potpisivanju odziva", e);
        }
    }

    /**
     * Verifikacija sopstvenim (server-side) javnim ključem — korisno za self-test.
     */
    public boolean verifyResponse(TransferResponse response) {
        return verify(response, this.keyPair.getPublic());
    }

    public PublicKeyResponse getPublicKeyInfo() {
        PublicKey pk = this.keyPair.getPublic();
        return new PublicKeyResponse(
                pk.getAlgorithm(),
                pk.getFormat(),
                Base64.getEncoder().encodeToString(pk.getEncoded())
        );
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    /**
     * Deterministički kanonski oblik podataka koji se potpisuje/verifikuje.
     * Static i public da bi je benchmark klijent mogao ponovo koristiti
     * bez duplirane (i potencijalno divergentne) implementacije.
     */
    public static byte[] canonicalize(TransferResponse response) {
        String payload = String.format("%s|%s|%s|%s|%s|%s|%s",
                response.getTransactionId(),
                response.getStatus(),
                response.getSourceAccount(),
                response.getDestinationAccount(),
                response.getAmount(),
                response.getCurrency(),
                response.getTimestamp()
        );
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Static verifikacija nad proizvoljnim javnim ključem — ovu koristi
     * benchmark klijent, pošto on nema pristup serverovom internom KeyPair-u,
     * već samo javnom ključu preuzetom preko /public-key endpointa.
     */
    public static boolean verify(TransferResponse response, PublicKey publicKey) {
        if (response.getSignature() == null || response.getSignature().isEmpty()) {
            return false;
        }
        try {
            byte[] dataToVerify = canonicalize(response);
            byte[] signatureBytes = Base64.getDecoder().decode(response.getSignature());

            Signature signature = Signature.getInstance(ALGORITHM, PROVIDER_NAME);
            signature.initVerify(publicKey);
            signature.update(dataToVerify);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
