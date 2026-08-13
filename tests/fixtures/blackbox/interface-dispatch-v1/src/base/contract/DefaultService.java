package contract;

public interface DefaultService {
    default String removedReachableDefault() {
        return "reachable";
    }

    default String removedUnreachableDefault() {
        return "unreachable";
    }

    default String stableDefault() {
        return "stable";
    }
}
