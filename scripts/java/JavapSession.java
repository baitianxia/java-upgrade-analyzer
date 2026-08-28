import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.spi.ToolProvider;

/**
 * Reusable, length-framed transport for the JDK's own javap ToolProvider.
 *
 * <p>The Python Oracle still supplies every javap option and parses exactly
 * the same javap text.  Keeping this transport alive only removes repeated JVM
 * launcher/bootstrap work; it does not implement or reinterpret bytecode.</p>
 */
public final class JavapSession {
    private static final int RESPONSE_MAGIC = 0x4a565031; // "JVP1"
    private static final int MAX_ARGUMENTS = 4096;
    private static final int MAX_ARGUMENT_BYTES = 4 * 1024 * 1024;

    private JavapSession() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            throw new IllegalArgumentException("JavapSession accepts framed stdin only");
        }
        Optional<ToolProvider> candidate = ToolProvider.findFirst("javap");
        if (!candidate.isPresent()) {
            throw new IllegalStateException("JDK javap ToolProvider is unavailable");
        }
        ToolProvider javap = candidate.get();
        DataInputStream input = new DataInputStream(System.in);
        DataOutputStream output = new DataOutputStream(System.out);
        while (true) {
            final int argumentCount;
            try {
                argumentCount = input.readInt();
            } catch (EOFException end) {
                return;
            }
            if (argumentCount < 0 || argumentCount > MAX_ARGUMENTS) {
                throw new IllegalArgumentException(
                    "invalid javap argument count: " + argumentCount
                );
            }
            String[] arguments = new String[argumentCount];
            for (int index = 0; index < argumentCount; index++) {
                int length = input.readInt();
                if (length < 0 || length > MAX_ARGUMENT_BYTES) {
                    throw new IllegalArgumentException(
                        "invalid javap argument byte length: " + length
                    );
                }
                byte[] encoded = new byte[length];
                input.readFully(encoded);
                arguments[index] = new String(encoded, StandardCharsets.UTF_8);
            }

            ByteArrayOutputStream stdoutBytes = new ByteArrayOutputStream();
            ByteArrayOutputStream stderrBytes = new ByteArrayOutputStream();
            int exitCode;
            try (
                PrintWriter stdout = new PrintWriter(
                    new OutputStreamWriter(stdoutBytes, StandardCharsets.UTF_8)
                );
                PrintWriter stderr = new PrintWriter(
                    new OutputStreamWriter(stderrBytes, StandardCharsets.UTF_8)
                )
            ) {
                try {
                    exitCode = javap.run(stdout, stderr, arguments);
                } catch (Throwable failure) {
                    exitCode = 125;
                    stderr.print(failure.getClass().getName());
                    String message = failure.getMessage();
                    if (message != null && !message.isEmpty()) {
                        stderr.print(": ");
                        stderr.print(message);
                    }
                    stderr.println();
                }
                stdout.flush();
                stderr.flush();
            }
            byte[] stdout = stdoutBytes.toByteArray();
            byte[] stderr = stderrBytes.toByteArray();
            output.writeInt(RESPONSE_MAGIC);
            output.writeInt(exitCode);
            output.writeInt(stdout.length);
            output.write(stdout);
            output.writeInt(stderr.length);
            output.write(stderr);
            output.flush();
        }
    }
}
