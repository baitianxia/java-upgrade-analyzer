package contract;

public final class OracleMain {
    private OracleMain() {}

    public static void main(String[] args) {
        AccessApi api = new AccessApi();
        switch (args[0]) {
            case "method":
                AccessApp.entryMethod(api);
                return;
            case "field":
                AccessApp.entryField(api);
                return;
            case "unreachable":
                AccessApp.deadMethod(api);
                return;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }
}
