// Veil - JNI bridge.
//
// Deliberately thin: every entry point validates its inputs, converts to the
// C++ types, calls the engine, and converts back. No protocol logic lives
// here, and no exception is allowed to cross the boundary.
#include <jni.h>

#include <cstring>
#include <new>
#include <string>
#include <vector>

#include "veil/engine.h"

namespace {

veil::Engine* toEngine(jlong handle) {
    return reinterpret_cast<veil::Engine*>(handle);
}

std::string toStd(JNIEnv* env, jstring s) {
    if (s == nullptr) return {};
    const char* chars = env->GetStringUTFChars(s, nullptr);
    if (chars == nullptr) return {};
    std::string out(chars);
    env->ReleaseStringUTFChars(s, chars);
    return out;
}

jbyteArray toArray(JNIEnv* env, const veil::Bytes& bytes) {
    if (bytes.empty()) return nullptr;
    jbyteArray out = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (out == nullptr) return nullptr;
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(bytes.size()),
                            reinterpret_cast<const jbyte*>(bytes.data()));
    return out;
}

veil::Bytes fromArray(JNIEnv* env, jbyteArray array) {
    veil::Bytes out;
    if (array == nullptr) return out;
    const jsize size = env->GetArrayLength(array);
    if (size <= 0) return out;
    out.resize(static_cast<size_t>(size));
    env->GetByteArrayRegion(array, 0, size, reinterpret_cast<jbyte*>(out.data()));
    return out;
}

// Throws a Java exception so Kotlin callers see a real error rather than a
// silent null.
void throwIllegal(JNIEnv* env, const char* message) {
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != nullptr) env->ThrowNew(cls, message);
}

}  // namespace

extern "C" {

JNIEXPORT jlong JNICALL
Java_com_veil_core_VeilNative_nativeCreate(JNIEnv* env, jobject /*thiz*/) {
    auto* engine = new (std::nothrow) veil::Engine();
    if (engine == nullptr) {
        throwIllegal(env, "out of memory");
        return 0;
    }
    if (!engine->createIdentity()) {
        delete engine;
        throwIllegal(env, "no secure random source");
        return 0;
    }
    return reinterpret_cast<jlong>(engine);
}

JNIEXPORT jlong JNICALL
Java_com_veil_core_VeilNative_nativeRestore(JNIEnv* env, jobject /*thiz*/,
                                            jbyteArray identitySecrets) {
    veil::Bytes secrets = fromArray(env, identitySecrets);
    if (secrets.size() != veil::kKeySize + 64) {
        throwIllegal(env, "identity secrets must be 96 bytes");
        return 0;
    }

    auto* engine = new (std::nothrow) veil::Engine();
    if (engine == nullptr) {
        throwIllegal(env, "out of memory");
        return 0;
    }
    if (!engine->restoreIdentity(secrets.data(), secrets.data() + veil::kKeySize)) {
        delete engine;
        throwIllegal(env, "identity restore failed");
        return 0;
    }
    return reinterpret_cast<jlong>(engine);
}

JNIEXPORT void JNICALL
Java_com_veil_core_VeilNative_nativeDestroy(JNIEnv*, jobject /*thiz*/, jlong handle) {
    delete toEngine(handle);
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeExportIdentity(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportIdentitySecrets());
}

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeEstablishOutbound(JNIEnv* env, jobject /*thiz*/,
                                                      jlong handle, jstring peerId,
                                                      jbyteArray bundle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return static_cast<jint>(veil::Engine::Result::NoSession);

    veil::Bytes bytes = fromArray(env, bundle);
    const std::string peer = toStd(env, peerId);
    return static_cast<jint>(engine->establishOutboundStatus(peer, bytes.data(), bytes.size()));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativePeerIdentity(JNIEnv* env, jobject /*thiz*/,
                                                 jlong handle, jstring peerId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->peerIdentity(toStd(env, peerId)));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeIdentityBinding(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportIdentityBinding());
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeVerifyIdentityBinding(JNIEnv* env, jobject /*thiz*/,
                                                          jbyteArray identity,
                                                          jbyteArray binding) {
    veil::Bytes id = fromArray(env, identity);
    veil::Bytes sig = fromArray(env, binding);
    if (id.size() != veil::kIdentitySize || sig.size() != veil::kBindingSize) return JNI_FALSE;
    return veil::Engine::verifyIdentityBinding(id.data(), sig.data()) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeSignChallenge(JNIEnv* env, jobject /*thiz*/,
                                                  jlong handle, jbyteArray challenge) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    veil::Bytes data = fromArray(env, challenge);
    return toArray(env, engine->signChallenge(data.data(), data.size()));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeExportPeerRegistry(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportPeerRegistry());
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeImportPeerRegistry(JNIEnv* env, jobject /*thiz*/,
                                                       jlong handle, jbyteArray registry) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;
    veil::Bytes bytes = fromArray(env, registry);
    return engine->importPeerRegistry(bytes.data(), bytes.size()) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativePublicIdentity(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportIdentityPublic());
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeGeneratePreKeys(JNIEnv* env, jobject /*thiz*/,
                                                    jlong handle,
                                                    jint signedId,
                                                    jint oneTimeCount) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    if (oneTimeCount < 0 || oneTimeCount > 1000) {
        throwIllegal(env, "one-time prekey count out of range");
        return nullptr;
    }
    if (!engine->generatePreKeys(static_cast<uint32_t>(signedId),
                                 static_cast<uint32_t>(oneTimeCount))) {
        return nullptr;
    }
    return toArray(env, engine->exportPreKeySet());
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativePublishBundle(JNIEnv* env, jobject /*thiz*/,
                                                  jlong handle, jint oneTimeIndex) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->publishBundle(oneTimeIndex));
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeHasSession(JNIEnv* env, jobject /*thiz*/,
                                               jlong handle, jstring peerId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;
    return engine->hasSession(toStd(env, peerId)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeEncrypt(JNIEnv* env, jobject /*thiz*/,
                                            jlong handle, jstring peerId, jbyteArray plain) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    veil::Bytes data = fromArray(env, plain);
    return toArray(env, engine->encrypt(toStd(env, peerId), data.data(), data.size()));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeDecrypt(JNIEnv* env, jobject /*thiz*/,
                                            jlong handle, jstring peerId, jbyteArray frame) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    veil::Bytes data = fromArray(env, frame);
    veil::Bytes out;
    if (!engine->decrypt(toStd(env, peerId), data.data(), data.size(), out)) {
        return nullptr;  // authentication failure; caller treats null as reject
    }
    return toArray(env, out);
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeExportSession(JNIEnv* env, jobject /*thiz*/,
                                                  jlong handle, jstring peerId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportSession(toStd(env, peerId)));
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeImportSession(JNIEnv* env, jobject /*thiz*/,
                                                  jlong handle, jstring peerId,
                                                  jbyteArray blob) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;
    veil::Bytes data = fromArray(env, blob);
    if (data.empty()) return JNI_FALSE;
    return engine->importSession(toStd(env, peerId), data.data(), data.size())
               ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_veil_core_VeilNative_nativeDropSession(JNIEnv* env, jobject /*thiz*/,
                                                jlong handle, jstring peerId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return;
    engine->dropSession(toStd(env, peerId));
}

JNIEXPORT jstring JNICALL
Java_com_veil_core_VeilNative_nativeSafetyNumber(JNIEnv* env, jobject /*thiz*/,
                                                 jlong handle, jstring peerId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    std::string number = engine->safetyNumber(toStd(env, peerId));
    if (number.empty()) return nullptr;
    return env->NewStringUTF(number.c_str());
}

}  // extern "C"
