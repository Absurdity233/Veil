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
    //
    // The list is scanned at execution time rather than at configuration time.
    // Filtering at configuration time was the bug that made CI fail on every
    // push while passing locally: on a fresh checkout the CMake output does not
    // exist yet when Gradle configures, so `from()` was given an empty list and
    // the copy silently staged nothing. Windows hid it because
    // `cmake --build` had already run in the same working tree from an earlier
    // local build; a CI runner starts clean.
    val candidates = listOf(
        rootProject.file("build/abi"),
        rootProject.file("build/abi/Release"),
        rootProject.file("core-native/build/abi"),
        rootProject.file("core-native/src/main/cpp/build"),
    )

    doFirst {
        candidates.filter { it.exists() }.forEach { dir ->
            logger.lifecycle("staging native libraries from $dir")
        }
    }

    from(candidates) {
        include("libveilc.so", "libveilc.dylib", "veilc.dll", "veil.dll", "libveilc.dylib")
        // A missing candidate directory is normal, not an error: the copy task
        // is asked to look in several places and only one of them will have run.
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
    into(nativeLibDir)

    // JNA is asked for "veilc", which becomes veilc.dll / libveilc.so. Moving
    // the library to exactly that name is what makes the loader find the staged
    // copy; the same platform difference that hid the configuration-time bug
    // also means the file on disk is not always named what JNA looks for.
    doLast {
        val staged = nativeLibDir.listFiles() ?: return@doLast
        for (file in staged) {
            val wanted = when (file.extension.lowercase()) {
                "so" -> "libveilc.so"
                "dylib" -> "libveilc.dylib"
                "dll" -> "veilc.dll"
                else -> continue
            }
            if (file.name != wanted) {
                val target = File(nativeLibDir, wanted)
                file.copyTo(target, overwrite = true)
                file.delete()
                logger.lifecycle("renamed ${file.name} -> $wanted")
            }
        }

        if (staged.none { it.extension.lowercase() in setOf("so", "dylib", "dll") }) {
            // Loud rather than silent: the failure mode this replaces was a JNA
            // UnsatisfiedLinkError forty seconds later, which said nothing about
            // why the file was missing.
            logger.warn(
                "no native library was staged into $nativeLibDir - run the CMake " +
                    "build for :desktop, or the JNA test will fail with a link error",
            )
        }
    }
}

tasks.named<JavaExec>("run") {
    dependsOn("stageNativeLibrary")
    systemProperty("jna.library.path", nativeLibDir.absolutePath)
    systemProperty("veil.library.path", nativeLibDir.absolutePath)
}

// Every Test task, not just "test".
//
// `tasks.named<Test>("test")` configured one task by name. That worked locally
// because the default task happens to be the one that runs; on CI the same task
// ran without the system properties, and JNA fell back to the platform loader,
// which does not search the staged directory. Applying to `withType<Test>()`
// cannot miss a task that was added or renamed.
tasks.withType<Test>().configureEach {
    dependsOn("stageNativeLibrary")
    systemProperty("jna.library.path", nativeLibDir.absolutePath)
    systemProperty("veil.library.path", nativeLibDir.absolutePath)

    // The path is in the log so a link failure can be read against it instead of
    // guessed at. This is the diagnostic that would have saved a CI round trip.
    doFirst {
        logger.lifecycle("test JNA path: $nativeLibDir")
        nativeLibDir.listFiles()?.forEach { logger.lifecycle("  ${it.name}") }
    }

    // The JNA error is one line with a stack trace that points at the call site
    // rather than at the loader. The actual message ("no libveilc in java.library.path"
    // or "undefined symbol: ...") is what says which of the three possible failures
    // happened, so it is printed in full.
    testLogging {
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStackTraces = true
        events("failed")
    }
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