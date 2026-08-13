package contract;

public final class RemovedType {
    public String reachableField = "field";
    public int deadField = 1;

    public RemovedType() {}

    public String reachableMethod() {
        return "method";
    }

    public void deadMethod() {}
}
