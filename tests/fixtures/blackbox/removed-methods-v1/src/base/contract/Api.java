package contract;

public final class Api {
    public String removedReachable() {
        return "reachable";
    }

    public String removedUnreachable() {
        return "unreachable";
    }

    public String select() {
        return "stable-overload";
    }

    public String select(int value) {
        return Integer.toString(value);
    }
}
