package contract;

public class OracleMain {
    public static void main(String[] args) {
        SignatureApi api = new SignatureApi();
        switch (args[0]) {
            case "return" -> System.out.println(SignatureApp.entryReturn(api));
            case "parameter" -> System.out.println(SignatureApp.entryParameter(api));
            case "field" -> System.out.println(SignatureApp.entryField(api));
            case "unreachable" -> System.out.println(SignatureApp.dormant(api));
            default -> throw new IllegalArgumentException(args[0]);
        }
    }
}
