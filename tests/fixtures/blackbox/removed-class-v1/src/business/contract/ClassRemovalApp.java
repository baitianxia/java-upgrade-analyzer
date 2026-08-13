package contract;

public final class ClassRemovalApp {
    private ClassRemovalApp() {}

    public static RemovedType entryConstructor() {
        return new RemovedType();
    }

    public static String entryMethod(RemovedType value) {
        return value.reachableMethod();
    }

    public static String entryField(RemovedType value) {
        return value.reachableField;
    }

    public static void deadMethod(RemovedType value) {
        value.deadMethod();
    }

    public static int deadField(RemovedType value) {
        return value.deadField;
    }
}
