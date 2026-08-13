package oracle;

public class OracleMain {
    public static void main(String[] args) {
        switch (args[0]) {
            case "protected" -> System.out.println(
                client.Child.entryProtected(new client.Child())
            );
            case "protected-foreign" -> System.out.println(
                client.ForeignChild.entryProtectedForeign(
                    new client.ForeignChild(), new lib.AccessApi()
                )
            );
            case "package" -> System.out.println(
                client.AccessApp.entryPackage(new lib.AccessApi())
            );
            case "package-peer" -> System.out.println(
                lib.Peer.entryPackagePeer(new lib.AccessApi())
            );
            case "private" -> System.out.println(
                client.AccessApp.entryPrivate(new lib.AccessApi())
            );
            default -> throw new IllegalArgumentException(args[0]);
        }
    }
}
