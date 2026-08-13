package contract;

public class AbstractApp {
    public static String entry(AbstractApi api) {
        return api.changedAbstract();
    }
}
