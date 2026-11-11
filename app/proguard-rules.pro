# The JNI entry points are looked up by name from C, so they must survive
# shrinking with their exact signatures.
-keepclasseswithmembernames,includedescriptorclasses class com.veil.core.VeilNative {
    native <methods>;
}
-keep class com.veil.core.VeilNative { *; }

# kotlinx.serialization generates serializers reflectively.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class com.veil.app.data.** {
    *** Companion;
}
-keepclasseswithmembers class com.veil.app.data.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# OkHttp ships optional platform hooks that are absent on Android.
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
