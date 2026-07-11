package topology.business;

import topology.target.TargetApi;

public final class ConflictCaller {
    private ConflictCaller() {}

    public static void conflict() {
        TargetApi.overloaded(7);
    }
}
