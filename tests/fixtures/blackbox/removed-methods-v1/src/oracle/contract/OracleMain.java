package contract;

public final class OracleMain {
    private OracleMain() {}

    public static void main(String[] args) {
        Api api = new Api();
        switch (args[0]) {
            case "removedReachable":
                App.entryRemoved(api);
                return;
            case "removedUnreachable":
                App.dead(api);
                return;
            case "selectInt":
                App.entryOverload(api);
                return;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }
}
