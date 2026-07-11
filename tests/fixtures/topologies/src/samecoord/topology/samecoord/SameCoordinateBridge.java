package topology.samecoord;

import topology.target.TargetApi;

public final class SameCoordinateBridge {
    private SameCoordinateBridge() {}

    public static void bridge() {
        TargetApi.changed();
    }
}
