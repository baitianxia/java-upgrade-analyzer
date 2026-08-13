package contract;

public final class FieldApp {
    private FieldApp() {}

    public static String entryRemovedField(FieldApi api) {
        return api.removedReachableField;
    }

    public static String deadField(FieldApi api) {
        return api.removedUnreachableField;
    }
}
