package contract;

public final class DispatchApp {
    private DispatchApp() {}

    public static String entryDefault(DefaultService service) {
        return service.removedReachableDefault();
    }

    public static Object entryClone(DefaultService service) {
        return service.clone();
    }

    public static String deadDefault(DefaultService service) {
        return service.removedUnreachableDefault();
    }
}
