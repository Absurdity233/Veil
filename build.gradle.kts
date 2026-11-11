plugins {
    id("com.android.application") version "9.0.1" apply false
    id("com.android.library") version "9.0.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
    // The desktop client is a plain JVM application: no Android, no Compose,
    // no native compilation. It reaches the C ABI through JNA.
    kotlin("jvm") version "2.2.10" apply false
}
