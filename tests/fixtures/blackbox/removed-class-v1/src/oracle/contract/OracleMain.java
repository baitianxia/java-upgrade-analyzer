package contract;

public final class OracleMain {
    private OracleMain() {}

    public static void main(String[] args) {
        switch (args[0]) {
            case "constructor":
                ClassRemovalApp.entryConstructor();
                return;
            case "method":
                ClassRemovalApp.entryMethod(new RemovedType());
                return;
            case "field":
                ClassRemovalApp.entryField(new RemovedType());
                return;
            case "deadMethod":
                ClassRemovalApp.deadMethod(new RemovedType());
                return;
            case "deadField":
                ClassRemovalApp.deadField(new RemovedType());
                return;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }
}
