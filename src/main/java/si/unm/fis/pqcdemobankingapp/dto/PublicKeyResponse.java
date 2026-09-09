package si.unm.fis.pqcdemobankingapp.dto;

public class PublicKeyResponse {
    private String algorithm;
    private String format;
    private String publicKeyBase64;

    public PublicKeyResponse() {}

    public PublicKeyResponse(String algorithm, String format, String publicKeyBase64) {
        this.algorithm = algorithm;
        this.format = format;
        this.publicKeyBase64 = publicKeyBase64;
    }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public String getPublicKeyBase64() { return publicKeyBase64; }
    public void setPublicKeyBase64(String publicKeyBase64) { this.publicKeyBase64 = publicKeyBase64; }
}
