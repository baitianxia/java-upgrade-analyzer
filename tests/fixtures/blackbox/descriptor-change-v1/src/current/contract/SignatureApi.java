package contract;

public class SignatureApi {
    public Object changedReturn() { return "current"; }
    public String changedParameter(Object value) { return String.valueOf(value); }
    public Object changedField;
    public String unreachableChanged(long value) { return Long.toString(value); }
    public String stable(String value) { return value; }
}
