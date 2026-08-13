package contract;

public interface DefaultService {
    default String stableDefault() {
        return "stable";
    }
}
