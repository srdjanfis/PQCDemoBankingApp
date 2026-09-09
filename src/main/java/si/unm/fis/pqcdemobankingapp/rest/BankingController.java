package si.unm.fis.pqcdemobankingapp.rest;

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

        String transactionId = "TX-" + UUID.randomUUID().toString().substring(0, 8);

        TransferResponse response = new TransferResponse(
                transactionId,
                "SUCCESS",
                request.getSourceAccount(),
                request.getDestinationAccount(),
                request.getAmount(),
                request.getCurrency(),
                Instant.now(),
                null
        );

        // ML-DSA-65 potpisivanje objekta
        pqcSignatureService.signResponse(response);

        return ResponseEntity.ok(response);
    }
}
