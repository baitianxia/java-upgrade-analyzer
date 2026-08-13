package contract;

public final class OracleMain {
    public static void main(String[] arguments) {
        if (!"reachable".equals(arguments[0])) {
            throw new IllegalArgumentException(arguments[0]);
        }
        System.out.println(NestBusiness.Member.entry(new BehaviorApi()));
    }
}
