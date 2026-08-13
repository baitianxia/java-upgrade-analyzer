package contract;

public final class DispatchApp {
    private DispatchApp() {}

    public static String entryDefault(DefaultService service) {
        return service.removedReachableDefault();
    }

    public static String deadDefault(DefaultService service) {
        return service.removedUnreachableDefault();
    }
}
