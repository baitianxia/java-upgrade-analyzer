package contract;

public final class AccessApp {
    private AccessApp() {}

    public static String entryMethod(AccessApi api) {
        return api.restrictedMethod();
    }

    public static String entryField(AccessApi api) {
        return api.restrictedField;
    }

    public static String deadMethod(AccessApi api) {
        return api.restrictedUnreachable();
    }
}
