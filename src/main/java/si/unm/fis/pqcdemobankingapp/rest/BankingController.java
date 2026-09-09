package si.unm.fis.pqcdemobankingapp.rest;

import si.unm.fis.pqcdemobankingapp.dto.PublicKeyResponse;
import si.unm.fis.pqcdemobankingapp.dto.TransferRequest;
import si.unm.fis.pqcdemobankingapp.dto.TransferResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import si.unm.fis.pqcdemobankingapp.service.PqcSignatureService;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/banking")
public class BankingController {

    private final PqcSignatureService pqcSignatureService;

    public BankingController(PqcSignatureService pqcSignatureService) {
        this.pqcSignatureService = pqcSignatureService;
    }

    @PostMapping("/transfer")
    public ResponseEntity<TransferResponse> executeTransfer(@RequestBody TransferRequest request) {
        TransferResponse response = buildResponse(request);
        pqcSignatureService.signResponse(response); // ML-DSA-65 potpis
        return ResponseEntity.ok(response);
    }

    /**
     * Identična poslovna logika kao /transfer, ali BEZ ML-DSA-65 potpisa.
     * Postoji isključivo radi benchmarka — da se izoluje trošak potpisivanja
     * (app-layer) od troška TLS transporta.
     */
    @PostMapping("/transfer-unsigned")
    public ResponseEntity<TransferResponse> executeTransferUnsigned(@RequestBody TransferRequest request) {
        TransferResponse response = buildResponse(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Javni ML-DSA-65 ključ za verifikaciju potpisa payload-a (NE TLS sertifikat).
     * Bez ovoga klijent nema odakle da preuzme ključ za verifikaciju.
     */
    @GetMapping("/public-key")
    public ResponseEntity<PublicKeyResponse> getPublicKey() {
        return ResponseEntity.ok(pqcSignatureService.getPublicKeyInfo());
    }

    private TransferResponse buildResponse(TransferRequest request) {
        String transactionId = "TX-" + UUID.randomUUID().toString().substring(0, 8);
        return new TransferResponse(
                transactionId,
                "SUCCESS",
                request.getSourceAccount(),
                request.getDestinationAccount(),
                request.getAmount(),
                request.getCurrency(),
                Instant.now(),
                null
        );
    }
}
