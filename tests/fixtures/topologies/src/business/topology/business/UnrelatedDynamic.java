package topology.business;

import java.util.function.Function;

public final class UnrelatedDynamic {
    private UnrelatedDynamic() {}

    public static String invoke(String value) {
        Function<String, String> trim = String::trim;
        return trim.apply(value);
    }
}
