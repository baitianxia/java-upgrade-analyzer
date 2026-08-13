package contract;

public class BehaviorApp {
    public static int entry(BehaviorApi api) { return api.reachableBehavior(); }
    public static int dormant(BehaviorApi api) { return api.unreachableBehavior(); }
}
