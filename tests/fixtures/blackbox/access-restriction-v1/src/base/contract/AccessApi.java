package contract;

public final class AccessApi {
    public String restrictedField = "field";

    public String restrictedMethod() {
        return "method";
    }

    public String restrictedUnreachable() {
        return "unreachable";
    }

    public String stableMethod() {
        return "stable";
    }
}
