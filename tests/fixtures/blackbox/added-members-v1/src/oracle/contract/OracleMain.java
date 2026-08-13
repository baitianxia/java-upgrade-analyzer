package contract;

public class OracleMain {
    public static void main(String[] args) throws Exception {
        AdditionApi api = new AdditionApi();
        switch (args[0]) {
            case "stable" -> System.out.println(AdditionApp.entry(api));
            case "addedMethod" -> System.out.println(
                AdditionApi.class.getMethod("addedMethod").invoke(api)
            );
            case "addedField" -> System.out.println(
                AdditionApi.class.getField("addedField").getLong(api)
            );
            case "constructor" -> {
                try {
                    System.out.println(
                        AdditionApi.class.getField("addedField").getLong(api)
                    );
                } catch (NoSuchFieldException absentOnBase) {
                    System.out.println("absent");
                }
            }
            default -> throw new IllegalArgumentException(args[0]);
        }
    }
}
