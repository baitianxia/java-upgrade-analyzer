package lib;

public class AccessApi {
    protected String protectedForSubclass() { return "protected"; }
    protected String protectedForForeignReceiver() { return "protected-foreign"; }
    String packageForOutsider() { return "package"; }
    String packageForPeer() { return "package-peer"; }
    private String privateForOutsider() { return "private"; }
    public String stable() { return "stable"; }
}
