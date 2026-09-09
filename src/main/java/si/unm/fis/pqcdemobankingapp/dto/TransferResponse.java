package si.unm.fis.pqcdemobankingapp.dto;

import java.math.BigDecimal;
import java.time.Instant;

public class TransferResponse {
    private String transactionId;
    private String status;
    private String sourceAccount;
    private String destinationAccount;
    private BigDecimal amount;
    private String currency;
    private Instant timestamp;
    private String signature; // Holds PQC ML-DSA-65 signature later

    public TransferResponse() {}

    public TransferResponse(String transactionId, String status, String sourceAccount,
                            String destinationAccount, BigDecimal amount, String currency,
                            Instant timestamp, String signature) {
        this.transactionId = transactionId;
        this.status = status;
        this.sourceAccount = sourceAccount;
        this.destinationAccount = destinationAccount;
        this.amount = amount;
        this.currency = currency;
        this.timestamp = timestamp;
        this.signature = signature;
    }

    public String getTransactionId() { return transactionId; }
    public void setTransactionId(String transactionId) { this.transactionId = transactionId; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getSourceAccount() { return sourceAccount; }
    public void setSourceAccount(String sourceAccount) { this.sourceAccount = sourceAccount; }

    public String getDestinationAccount() { return destinationAccount; }
    public void setDestinationAccount(String destinationAccount) { this.destinationAccount = destinationAccount; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
}
