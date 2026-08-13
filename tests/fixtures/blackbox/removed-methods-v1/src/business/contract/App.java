package contract;

public final class App {
    private App() {}

    public static String entryRemoved(Api api) {
        return api.removedReachable();
    }

    public static String entryOverload(Api api) {
        return api.select(1);
    }

    public static String dead(Api api) {
        return api.removedUnreachable();
    }
}
