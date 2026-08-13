package contract;

public class OracleMain {
    public static void main(String[] args) {
        switch (args[0]) {
            case "instance-method" -> System.out.println(DispatchShapeApp.entryInstanceMethod());
            case "static-method" -> System.out.println(DispatchShapeApp.entryStaticMethod());
            case "instance-field" -> System.out.println(DispatchShapeApp.entryInstanceField());
            case "static-field" -> System.out.println(DispatchShapeApp.entryStaticField());
            default -> throw new IllegalArgumentException(args[0]);
        }
    }
}
