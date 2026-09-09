package si.unm.fis.pqcdemobankingapp.dto;

import java.math.BigDecimal;

public class TransferRequest {
    private String sourceAccount;
    private String destinationAccount;
    private BigDecimal amount;
    private String currency;

    public TransferRequest() {}

    public TransferRequest(String sourceAccount, String destinationAccount, BigDecimal amount, String currency) {
        this.sourceAccount = sourceAccount;
        this.destinationAccount = destinationAccount;
        this.amount = amount;
        this.currency = currency;
    }

    public String getSourceAccount() { return sourceAccount; }
    public void setSourceAccount(String sourceAccount) { this.sourceAccount = sourceAccount; }

    public String getDestinationAccount() { return destinationAccount; }
    public void setDestinationAccount(String destinationAccount) { this.destinationAccount = destinationAccount; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
}
