plugins {
    kotlin("jvm")
    application
}

// The desktop client.
//
// It has no Compose, no Android and no native compilation: it talks to the C
// ABI in core-native through JNA, and to the relay over the same WebSocket
// protocol as the phone. That is the point of the exercise - if the protocol
// engine is genuinely portable, a third client is a transport and a window.

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("com.veil.desktop.MainKt")
}

dependencies {
    // JNA is how a JVM reaches a C ABI without writing any native code of its
    // own, which is exactly the property being demonstrated.
    implementation("net.java.dev.jna:jna:5.14.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

// The native library is built by core-native's CMake, not by Gradle. Copy it
// next to the classes so `gradle run` works without a manual step, and so the
// failure mode is "file not found, run the build" rather than a JNA stack
// trace about a missing symbol table.
val nativeLibDir = layout.buildDirectory.dir("native").get().asFile

tasks.register<Copy>("stageNativeLibrary") {
    group = "build"
    description = "Copies the C ABI shared library next to the desktop classes"

    // Candidate locations, in the order a developer is likely to have them:
    // the CMake build tree, then a manual build under core-native/build.
    val candidates = listOf(
        rootProject.file("build/abi"),
        rootProject.file("core-native/build/abi"),
        rootProject.file("core-native/src/main/cpp/build"),
    )

    from(candidates.filter { it.exists() })
    include("libveilc.so", "libveilc.dylib", "veilc.dll", "veil.dll")
    into(nativeLibDir)
}

tasks.named<JavaExec>("run") {
    dependsOn("stageNativeLibrary")
    systemProperty("jna.library.path", nativeLibDir.absolutePath)
    systemProperty("veil.library.path", nativeLibDir.absolutePath)
}

tasks.named<Test>("test") {
    dependsOn("stageNativeLibrary")
    systemProperty("jna.library.path", nativeLibDir.absolutePath)
    systemProperty("veil.library.path", nativeLibDir.absolutePath)
}

tasks.named<Jar>("jar") {
    dependsOn("stageNativeLibrary")
    from(nativeLibDir) { into("native") }
    manifest {
        attributes(
            "Main-Class" to "com.veil.desktop.MainKt",
            "Implementation-Title" to "Veil desktop",
        )
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}