package contract;

public class OracleMain {
    public static void main(String[] args) {
        System.out.println(AbstractApp.entry(new ConcreteClient()));
    }
}
