package oracle;

public final class DefinitionMain {
    private DefinitionMain() {}

    public static void main(String[] args) throws Exception {
        Class<?> type = Class.forName(
            args[0], false, DefinitionMain.class.getClassLoader()
        );
        type.getDeclaredConstructors();
        type.getDeclaredMethods();
        type.getDeclaredFields();
    }
}
