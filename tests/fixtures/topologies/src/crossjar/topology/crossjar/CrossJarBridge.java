package topology.crossjar;

import topology.target.TargetApi;

public final class CrossJarBridge {
    private CrossJarBridge() {}

    public static void bridge() {
        TargetApi.changed();
    }
}
