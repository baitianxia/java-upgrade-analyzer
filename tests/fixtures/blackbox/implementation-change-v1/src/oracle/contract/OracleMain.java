package contract;

public class OracleMain {
    public static void main(String[] args) {
        BehaviorApi api = new BehaviorApi();
        switch (args[0]) {
            case "reachable" -> System.out.println(BehaviorApp.entry(api));
            case "unreachable" -> System.out.println(BehaviorApp.dormant(api));
            default -> throw new IllegalArgumentException(args[0]);
        }
    }
}
