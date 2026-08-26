/* Target-JVM class-definition verifier. Never initializes analyzed classes. */
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public final class ClassDefinitionVerifier {
    private static final byte[] BUNDLE_MAGIC = new byte[]{'J','U','A','C','L','S','B','2'};
    private static final int MAX_CLASS_NAME_BYTES = 1024 * 1024;
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
    private static void write(DataOutputStream out,Map<String,Object> value) throws Exception {
        byte[] payload=Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        out.writeInt(payload.length); out.write(payload); out.flush();
    }
    private static boolean validInternalClassName(String name) {
        if(name.isEmpty()||name.charAt(0)=='/'||name.charAt(name.length()-1)=='/')return false;
        boolean componentHasCharacter=false;
        for(int index=0;index<name.length();index++){
            char value=name.charAt(index);
            if(value=='/'){
                if(!componentHasCharacter)return false;
                componentHasCharacter=false;
            }else{
                if(value=='.'||value==';'||value=='[')return false;
                componentHasCharacter=true;
            }
        }
        return componentHasCharacter;
    }
    public static void main(String[] args) {
        if(args.length!=1&&args.length!=3){System.err.println("usage: ClassDefinitionVerifier <class-bundle> [start-index end-index]");System.exit(64);}
        try{
            int start=args.length==3?Integer.parseInt(args[1]):0;
            int end=args.length==3?Integer.parseInt(args[2]):-1;
            run(Paths.get(args[0]),start,end);
        }catch(Throwable error){error.printStackTrace(System.err);System.exit(2);}
    }
    private static void run(Path bundlePath,int start,int end) throws Exception {
        bundlePath=bundlePath.toRealPath();
        if(!Files.isRegularFile(bundlePath))throw new IOException("class bundle is not a regular file");
        DataOutputStream out=new DataOutputStream(new BufferedOutputStream(System.out));
        try(ClassBundle bundle=new ClassBundle(bundlePath)){
            List<String> allNames=bundle.names();
            if(end<0)end=allNames.size();
            if(start<0||end<start||end>allNames.size())throw new IOException("invalid verification range");
            List<String> names=allNames.subList(start,end);
            write(out,map("frame_type","definition_output_header","schema","target-jvm-definition-v2","class_count",names.size()));
            int ready=0,failed=0;
            ClassLoader parent=ClassLoader.getSystemClassLoader().getParent();
            BundleClassLoader loader=new BundleClassLoader(bundle,parent);
            for(String internal:names){
                byte[] bytes=bundle.read(internal);
                loader.prime(internal,bytes);
                boolean classLoaded=false;
                try{
                    Class<?> type=Class.forName(internal.replace('/','.'),false,loader);
                    classLoaded=true;
                    // Resolve the class's own executable/field descriptors. Do
                    // not enumerate InnerClasses: a loadable outer class may
                    // legitimately advertise optional nested implementations
                    // whose dependencies are absent until that feature is used.
                    type.getDeclaredConstructors(); type.getDeclaredMethods(); type.getDeclaredFields();
                    write(out,map("frame_type","class_definition","class_name",internal,"class_bytes_sha256",sha(bytes),"status","definition_ready"));
                    ready++;
                }catch(Throwable error){
                    write(out,map("frame_type","class_definition","class_name",internal,"class_bytes_sha256",sha(bytes),"status","verification_failed","failure_phase",classLoaded?"member_linkage":"class_load","failure_kind",error.getClass().getName(),"failure_message",String.valueOf(error.getMessage())));
                    failed++;
                }finally{
                    loader.clearPrime(internal);
                }
            }
            write(out,map("frame_type","definition_output_footer","class_count",names.size(),"definition_ready_count",ready,"failure_count",failed));
        }
    }
    private static final class BundleEntry {
        final long offset; final int length;
        BundleEntry(long offset,int length){this.offset=offset;this.length=length;}
    }
    private static final class ClassBundle implements Closeable {
        private final RandomAccessFile file;
        private final LinkedHashMap<String,BundleEntry> entries=new LinkedHashMap<>();
        ClassBundle(Path path) throws Exception {
            file=new RandomAccessFile(path.toFile(),"r");
            try{
                byte[] magic=new byte[BUNDLE_MAGIC.length]; file.readFully(magic);
                if(!Arrays.equals(magic,BUNDLE_MAGIC))throw new IOException("invalid class bundle magic");
                long unsignedCount=Integer.toUnsignedLong(file.readInt());
                if(unsignedCount>Integer.MAX_VALUE)throw new IOException("invalid class bundle count");
                int count=(int)unsignedCount; String previous=null;
                for(int index=0;index<count;index++){
                    long unsignedNameLength=Integer.toUnsignedLong(file.readInt());
                    long unsignedClassLength=Integer.toUnsignedLong(file.readInt());
                    if(unsignedNameLength<1||unsignedNameLength>MAX_CLASS_NAME_BYTES||unsignedClassLength<1||unsignedClassLength>Integer.MAX_VALUE)throw new IOException("invalid class bundle record length");
                    byte[] nameBytes=new byte[(int)unsignedNameLength]; file.readFully(nameBytes);
                    String name=new String(nameBytes,StandardCharsets.UTF_8);
                    if(!Arrays.equals(nameBytes,name.getBytes(StandardCharsets.UTF_8)))throw new IOException("invalid UTF-8 class name");
                    if(!validInternalClassName(name))throw new IOException("invalid internal class name");
                    if(previous!=null&&previous.compareTo(name)>=0)throw new IOException("class bundle names are not strictly sorted");
                    long offset=file.getFilePointer(); long end=offset+unsignedClassLength;
                    if(end<offset||end>file.length())throw new IOException("class bundle record exceeds file");
                    entries.put(name,new BundleEntry(offset,(int)unsignedClassLength));
                    file.seek(end); previous=name;
                }
                if(file.getFilePointer()!=file.length())throw new IOException("trailing class bundle bytes");
            }catch(Throwable error){file.close();throw error;}
        }
        List<String> names(){return new ArrayList<>(entries.keySet());}
        synchronized byte[] read(String name) throws IOException {
            BundleEntry entry=entries.get(name); if(entry==null)throw new FileNotFoundException(name);
            byte[] bytes=new byte[entry.length]; file.seek(entry.offset); file.readFully(bytes); return bytes;
        }
        public void close() throws IOException {file.close();}
    }
    private static final class BundleClassLoader extends ClassLoader {
        private final ClassBundle bundle;
        private String primedName;
        private byte[] primedBytes;
        BundleClassLoader(ClassBundle bundle,ClassLoader parent){super(parent);this.bundle=bundle;}
        void prime(String name,byte[] bytes){primedName=name;primedBytes=bytes;}
        void clearPrime(String name){if(name.equals(primedName)){primedName=null;primedBytes=null;}}
        protected Class<?> findClass(String binaryName) throws ClassNotFoundException {
            String internal=binaryName.replace('.','/');
            try{
                byte[] bytes=internal.equals(primedName)?primedBytes:bundle.read(internal);
                if(bytes==null)throw new FileNotFoundException(internal);
                return defineClass(binaryName,bytes,0,bytes.length);
            }catch(IOException error){throw new ClassNotFoundException(binaryName,error);}
        }
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
        static void quote(StringBuilder out,String value){out.append('"');for(int i=0;i<value.length();i++){char c=value.charAt(i);switch(c){case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;default:if(c<32||Character.isSurrogate(c))out.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else out.append(c);}}out.append('"');}
    }
}
