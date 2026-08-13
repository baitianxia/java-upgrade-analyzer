package contract;

public final class NestBusiness {
    private static int bridge(BehaviorApi api) {
        return api.changed();
    }

    public static final class Member {
        public static int entry(BehaviorApi api) {
            return bridge(api);
        }
    }
}
