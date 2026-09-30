package hev.htproxy;

/**
 * JNI binding for hev-socks5-tunnel. This exact package/class is baked into
 * the native library at build time (PKGNAME=hev/htproxy, CLSNAME=TProxyService
 * in src/hev-jni.c). Renaming it without rebuilding the .so makes
 * JNI_OnLoad fail to FindClass and every call return JNI_ERR.
 */
public final class TProxyService {
    private TProxyService() {}

    static {
        try { System.loadLibrary("hev-socks5-tunnel"); } catch (Throwable ignored) {}
    }

    public static native boolean TProxyStartService(String configPath, int fd);
    public static native boolean TProxyStopService();
    public static native boolean TProxyIsRunning();
    public static native long[] TProxyGetStats();
}
