package contract;

public class OracleMain {
    public static void main(String[] args) {
        ChildApi child = new ChildApi();
        switch (args[0]) {
            case "reachable" -> System.out.println(InheritanceApp.entry(child));
            case "dormant" -> System.out.println(InheritanceApp.dormant(child));
            default -> throw new IllegalArgumentException(args[0]);
        }
    }
}
