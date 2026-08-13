package contract;

public class SignatureApi {
    public String changedReturn() { return "base"; }
    public String changedParameter(String value) { return value; }
    public String changedField;
    public String unreachableChanged(int value) { return Integer.toString(value); }
    public String stable(String value) { return value; }
}
