package contract;

public final class OracleMain {
    private OracleMain() {}

    public static void main(String[] args) {
        FieldApi api = new FieldApi();
        switch (args[0]) {
            case "removedReachableField":
                FieldApp.entryRemovedField(api);
                return;
            case "removedUnreachableField":
                FieldApp.deadField(api);
                return;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }
}
