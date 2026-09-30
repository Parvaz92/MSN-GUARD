package dev.zeptun;

/**
 * Exact class name the prebuilt libzeptun-jni.so registers against
 * (ZEPTUN_JNI_CLASS = "dev/zeptun/Zeptun" in src/jni/zeptun_jni.c).
 * Renaming this class requires rebuilding the .so with a different
 * ZEPTUN_JNI_CLASS — do not rename without it.
 */
public final class Zeptun {
    private Zeptun() {}

    // Loaded eagerly so that nativeStart is resolvable before any VpnService
    // calls it — lazier init would race the first connect.
    static {
        try { System.loadLibrary("zeptun"); } catch (Throwable ignored) {}
        try { System.loadLibrary("zeptun-jni"); } catch (Throwable ignored) {}
    }

    /**
     * @param service VpnService instance whose protect(int) is called for
     *                every upstream socket (bypass the TUN). Null is allowed
     *                and means "no protect" — upstream then routes via system.
     * @param fd      TUN fd from VpnService.Builder.establish()
     * @param toml    optional TOML config; null uses mobile preset
     * @return 0 on success, negative Zeptun error code otherwise
     */
    public static native int nativeStart(Object service, int fd, String toml);
    public static native void nativeStop();
    public static native String nativeVersion();
    public static native long nativeCounter(int index);

    // Convenience: expose version string without touching native state.
    public static String version() {
        try { return nativeVersion(); } catch (Throwable e) { return "unknown"; }
    }
}
