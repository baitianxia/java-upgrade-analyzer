package contract;

public final class OracleMain {
    private OracleMain() {}

    public static void main(String[] args) {
        switch (args[0]) {
            case "constructor":
                MethodShapeApp.entryConstructor();
                return;
            case "static":
                MethodShapeApp.entryStatic();
                return;
            case "array":
                MethodShapeApp.entryArray(new MethodShapes());
                return;
            case "deep":
                MethodShapeApp.entryDeep(new MethodShapes());
                return;
            case "unreachable":
                MethodShapeApp.dead(new MethodShapes());
                return;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }
}
