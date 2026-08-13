package contract;

public final class MethodShapeApp {
    private MethodShapeApp() {}

    public static String entryConstructor() {
        return new MethodShapes("shape").stableMethod();
    }

    public static String entryStatic() {
        return MethodShapes.removedStatic(7L);
    }

    public static String entryArray(MethodShapes api) {
        return api.removedArray(new String[0], new int[0][]);
    }

    public static String entryDeep(MethodShapes api) {
        return MethodShapeBridge.first(api);
    }

    public static String dead(MethodShapes api) {
        return api.removedUnreachable();
    }
}
