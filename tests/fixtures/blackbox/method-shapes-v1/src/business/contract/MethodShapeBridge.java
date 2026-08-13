package contract;

public final class MethodShapeBridge {
    private MethodShapeBridge() {}

    public static String first(MethodShapes api) {
        return second(api);
    }

    public static String second(MethodShapes api) {
        return api.removedDeep();
    }
}
