/* Target-JVM class-definition verifier. Never initializes analyzed classes. */
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.Base64;

public final class ClassDefinitionVerifier {
    private static Map<String,Object> map(Object... values) {
        LinkedHashMap<String,Object> result = new LinkedHashMap<>();
        for (int i=0;i<values.length;i+=2) result.put((String)values[i], values[i+1]);
        return result;
    }
    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte value: bytes) result.append(String.format(Locale.ROOT,"%02x",value&255));
        return result.toString();
    }
    private static String sha(byte[] bytes) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static byte[] frame(DataInputStream in) throws Exception {
        int length;
        try { length=in.readInt(); } catch (EOFException eof) { return null; }
        if (length<2 || length>4*1024*1024) throw new IOException("invalid frame length");
        byte[] payload=new byte[length]; in.readFully(payload); return payload;
    }
    private static String field(String json,String key) throws Exception {
        String marker="\""+key+"\":\""; int start=json.indexOf(marker);
        if(start<0) throw new IOException("missing "+key); start+=marker.length(); int end=json.indexOf('"',start);
        if(end<0) throw new IOException("unterminated "+key); return json.substring(start,end);
    }
    private static void write(DataOutputStream out,Map<String,Object> value) throws Exception {
        byte[] payload=Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        out.writeInt(payload.length); out.write(payload); out.flush();
    }
    public static void main(String[] args) {
        if(args.length!=1){System.err.println("usage: ClassDefinitionVerifier <class-root>");System.exit(64);}
        try{run(Paths.get(args[0]));}catch(Throwable error){error.printStackTrace(System.err);System.exit(2);}
    }
    private static void run(Path root) throws Exception {
        root=root.toRealPath();
        DataInputStream in=new DataInputStream(new BufferedInputStream(System.in));
        DataOutputStream out=new DataOutputStream(new BufferedOutputStream(System.out));
        byte[] headerBytes=frame(in); if(headerBytes==null)throw new IOException("header missing");
        String header=new String(headerBytes,StandardCharsets.UTF_8);
        if(!"definition_input_header".equals(field(header,"frame_type")))throw new IOException("bad header");
        int expected=Integer.parseInt(field(header,"class_count"));
        List<String> names=new ArrayList<>();
        while(true){
            byte[] bytes=frame(in); if(bytes==null)throw new IOException("footer missing");
            String json=new String(bytes,StandardCharsets.UTF_8); String type=field(json,"frame_type");
            if("definition_input_footer".equals(type))break;
            if(!"class_name".equals(type))throw new IOException("bad frame type");
            String name=new String(Base64.getDecoder().decode(field(json,"class_name_b64")),StandardCharsets.UTF_8);
            if(!name.matches("[A-Za-z_$][A-Za-z0-9_$]*(?:/[A-Za-z_$][A-Za-z0-9_$]*)*"))throw new IOException("unsafe class name");
            names.add(name);
        }
        if(names.size()!=expected || frame(in)!=null)throw new IOException("input count/trailing bytes");
        write(out,map("frame_type","definition_output_header","schema","target-jvm-definition-v1","class_count",names.size()));
        int ready=0,failed=0;
        ClassLoader parent=ClassLoader.getSystemClassLoader().getParent();
        try(URLClassLoader loader=new URLClassLoader(new URL[]{root.toUri().toURL()},parent)){
            for(String internal:names){
                Path path=root.resolve(internal+".class").normalize();
                if(!path.startsWith(root))throw new IOException("class path escaped root");
                byte[] bytes=Files.readAllBytes(path);
                try{
                    Class<?> type=Class.forName(internal.replace('/','.'),false,loader);
                    type.getDeclaredConstructors(); type.getDeclaredMethods(); type.getDeclaredFields();
                    type.getDeclaredClasses();
                    write(out,map("frame_type","class_definition","class_name",internal,"class_bytes_sha256",sha(bytes),"status","definition_ready"));
                    ready++;
                }catch(Throwable error){
                    write(out,map("frame_type","class_definition","class_name",internal,"class_bytes_sha256",sha(bytes),"status","verification_failed","failure_kind",error.getClass().getName(),"failure_message",String.valueOf(error.getMessage())));
                    failed++;
                }
            }
        }
        write(out,map("frame_type","definition_output_footer","class_count",names.size(),"definition_ready_count",ready,"failure_count",failed));
    }
    private static final class Json {
        static String stringify(Object value){StringBuilder out=new StringBuilder();append(out,value);return out.toString();}
        static void append(StringBuilder out,Object value){
            if(value==null)out.append("null"); else if(value instanceof String)quote(out,(String)value);
            else if(value instanceof Number||value instanceof Boolean)out.append(value);
            else if(value instanceof Map<?,?>){Map<?,?> m=(Map<?,?>)value;out.append('{');boolean first=true;for(Map.Entry<?,?> e:m.entrySet()){if(!first)out.append(',');first=false;quote(out,String.valueOf(e.getKey()));out.append(':');append(out,e.getValue());}out.append('}');}
            else if(value instanceof Iterable<?>){Iterable<?> items=(Iterable<?>)value;out.append('[');boolean first=true;for(Object item:items){if(!first)out.append(',');first=false;append(out,item);}out.append(']');}
            else quote(out,String.valueOf(value));
        }
        static void quote(StringBuilder out,String value){out.append('"');for(int i=0;i<value.length();i++){char c=value.charAt(i);switch(c){case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;default:if(c<32)out.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else out.append(c);}}out.append('"');}
    }
}
