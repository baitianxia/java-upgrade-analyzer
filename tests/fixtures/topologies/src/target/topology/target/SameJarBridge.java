package topology.target;

public final class SameJarBridge {
    private SameJarBridge() {}

    public static void bridge() {
        TargetApi.changed();
    }
}
