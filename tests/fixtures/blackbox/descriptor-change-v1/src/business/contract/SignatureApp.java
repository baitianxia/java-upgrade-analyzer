package contract;

public class SignatureApp {
    public static String entryReturn(SignatureApi api) {
        return api.changedReturn();
    }

    public static String entryParameter(SignatureApi api) {
        return api.changedParameter("value");
    }

    public static String entryField(SignatureApi api) {
        return api.changedField;
    }

    public static String dormant(SignatureApi api) {
        return api.unreachableChanged(7);
    }
}
