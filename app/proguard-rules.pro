# The JNI entry points are looked up by name from C, so they must survive
# shrinking with their exact signatures.
-keepclasseswithmembernames,includedescriptorclasses class com.veil.core.VeilNative {
    native <methods>;
}
-keep class com.veil.core.VeilNative { *; }

# The relay wire codec and the native bridge are reached reflexively by the JVM
# (JNI name mangling) and must keep their shapes.
-keep class com.veil.core.VeilEngine { *; }
-keep class com.veil.core.Handshake { *; }
-keep class com.veil.core.DecryptOutcome { *; }
-keep class com.veil.core.SessionState { *; }

# OkHttp ships optional platform hooks that are absent on Android.
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# R8 keeps annotation attributes by default; nothing else in this app relies on
# reflection, and the kotlinx.serialization rules that used to live here were
# for a library that is no longer on the classpath.
