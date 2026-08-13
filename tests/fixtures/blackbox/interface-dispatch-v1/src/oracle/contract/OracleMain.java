package contract;

public final class OracleMain {
    private OracleMain() {}

    public static void main(String[] args) {
        DefaultService service = new DefaultServiceImpl();
        switch (args[0]) {
            case "reachableDefault":
                DispatchApp.entryDefault(service);
                return;
            case "unreachableDefault":
                DispatchApp.deadDefault(service);
                return;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }
}
