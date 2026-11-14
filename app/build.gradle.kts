plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.veil.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.veil.app"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    packaging {
        resources.excludes += setOf(
            "/META-INF/{AL2.0,LGPL2.1}",
            "/META-INF/INDEX.LIST",
        )
    }
}

dependencies {
    implementation(project(":core-native"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")

    // Coroutines only. kotlinx-serialization-json and
    // lifecycle-viewmodel-compose were listed here with no reference in the
    // source at all; the ProGuard file carried keep rules for a serializer
    // that does not exist. Both are removed rather than left as a promise
    // nobody is keeping.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

// Lint treats `local.properties` as project input, and on Windows that file holds
// an unescaped SDK path (`C:\Users\...`) which the PropertyEscape rule flags as an
// error. The file is gitignored - it is machine-local by design - so on CI it does
// not exist and the rule cannot fire. Failing a local build for a file the
// repository deliberately does not contain would mean the check only works on the
// machines that do not need it.
//
// The rule is disabled rather than the filename excluded, because lint has no
// per-file exclusion for a file outside the source sets, and the property it
// enforces (escaping in .properties) is not something this project reads.
android {
    lint {
        disable += "PropertyEscape"
        // Report but do not fail on the warning-level checks: the build should
        // break for correctness, not for a suggestion.
        warningsAsErrors = false
        abortOnError = true
    }
}
