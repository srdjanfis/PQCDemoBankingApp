package si.unm.fis.pqcdemobankingapp.service;

import si.unm.fis.pqcdemobankingapp.dto.TransferResponse;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/*
 This service registers the Bouncy Castle PQC provider,
 generates an ML-DSA-65 key pair at service startup,
 and provides methods for signing and verifying
 TransferResponse objects.
*/

@Service
public class PqcSignatureService {

    private static final String PROVIDER_NAME = "BC";
    private KeyPair keyPair;

    @PostConstruct
    public void init() throws Exception {
        // Registracija Bouncy Castle PQC provajdera ako već nije registrovan
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Generisanje ML-DSA-65 (FIPS 204) para ključeva
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-65", PROVIDER_NAME);
        keyPairGenerator.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());
        this.keyPair = keyPairGenerator.generateKeyPair();
    }

    /**
     * Generiše ML-DSA-65 potpis nad kanonskim reprezentativnim nizom DTO objekta
     * i upisuje ga u Base64 formatu u polje 'signature'.
     */
    public void signResponse(TransferResponse response) {
        try {
            byte[] dataToSign = prepareCanonicalData(response);

            Signature signature = Signature.getInstance("ML-DSA-65", PROVIDER_NAME);
            signature.initSign(this.keyPair.getPrivate());
            signature.update(dataToSign);

            byte[] digitalSignature = signature.sign();
            String base64Signature = Base64.getEncoder().encodeToString(digitalSignature);

            response.setSignature(base64Signature);
        } catch (Exception e) {
            throw new RuntimeException("Greška pri ML-DSA-65 potpisivanju odziva", e);
        }
    }

    /**
     * Verifikuje da li je ML-DSA-65 potpis na TransferResponse objektu validan.
     */
    public boolean verifyResponse(TransferResponse response) {
        if (response.getSignature() == null || response.getSignature().isEmpty()) {
            return false;
        }

        try {
            byte[] dataToVerify = prepareCanonicalData(response);
            byte[] signatureBytes = Base64.getDecoder().decode(response.getSignature());

            Signature signature = Signature.getInstance("ML-DSA-65", PROVIDER_NAME);
            signature.initVerify(this.keyPair.getPublic());
            signature.update(dataToVerify);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Konvertuje polja DTO objekta u deterministički determinisan string za potpisivanje.
     */
    private byte[] prepareCanonicalData(TransferResponse response) {
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

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
}
