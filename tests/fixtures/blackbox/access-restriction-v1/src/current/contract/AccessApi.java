package contract;

public final class AccessApi {
    private String restrictedField = "field";

    private String restrictedMethod() {
        return "method";
    }

    private String restrictedUnreachable() {
        return "unreachable";
    }

    public String stableMethod() {
        return "stable";
    }
}
