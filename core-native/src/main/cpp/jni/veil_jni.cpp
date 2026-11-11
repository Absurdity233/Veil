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

jstring toJString(JNIEnv* env, const std::string& s) {
    return env->NewStringUTF(s.c_str());
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
Java_com_veil_core_VeilNative_nativeRotatePreKeys(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    if (!engine->rotatePreKeys()) {
        throwIllegal(env, "no secure random source");
        return nullptr;
    }
    return toArray(env, engine->exportPreKeySet());
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeNeedsPreKeyRefill(JNIEnv*, jobject /*thiz*/,
                                                      jlong handle, jint lowWater) {
    auto* engine = toEngine(handle);
    if (engine == nullptr || lowWater < 0) return JNI_FALSE;
    return engine->needsPreKeyRefill(static_cast<size_t>(lowWater)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeExportPreKeyState(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportPreKeyState());
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeImportPreKeyState(JNIEnv* env, jobject /*thiz*/,
                                                      jlong handle, jbyteArray state) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;
    veil::Bytes bytes = fromArray(env, state);
    return engine->importPreKeyState(bytes.data(), bytes.size()) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeSessionState(JNIEnv* env, jobject /*thiz*/,
                                                 jlong handle, jstring peerId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return static_cast<jint>(veil::Engine::NoPeer);
    return static_cast<jint>(engine->sessionState(toStd(env, peerId)));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativePublicIdentity(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportIdentityPublic());
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

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeDecrypt(JNIEnv* env, jobject /*thiz*/,
                                            jlong handle, jstring peerId, jbyteArray frame,
                                            jobjectArray outPlain) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return static_cast<jint>(veil::Engine::NoSession);

    veil::Bytes data = fromArray(env, frame);
    veil::Bytes plain;
    veil::Engine::Result r =
        engine->decryptStatus(toStd(env, peerId), data.data(), data.size(), plain);

    if (r == veil::Engine::Result::Ok) {
        jbyteArray arr = toArray(env, plain);
        if (arr != nullptr) env->SetObjectArrayElement(outPlain, 0, arr);
    }
    veil::wipe(plain.data(), plain.size());
    return static_cast<jint>(r);
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
Java_com_veil_core_VeilNative_nativeExportSession(JNIEnv* env, jobject /*thiz*/,
                                                  jlong handle, jstring peerId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportSession(toStd(env, peerId)));
}

// ---- Multi-device ------------------------------------------------------
//
// The phone is normally the *first* device of an account, so the operations it
// needs are the ones that create and publish its own credential. Linking a
// second device happens on the device being linked, which is what the C ABI is
// for; these exist so the phone can at least join a fan-out conversation.

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeInitDevice(JNIEnv* env, jobject /*thiz*/,
                                               jlong handle, jstring userId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;
    return engine->initDevice(toStd(env, userId)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeDeviceId(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->ownDeviceId());
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeDeviceCredential(JNIEnv* env, jobject /*thiz*/,
                                                     jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->ownDeviceCredential());
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeAdoptDeviceCredential(
    JNIEnv* env, jobject /*thiz*/, jlong handle, jbyteArray credential,
    jbyteArray accountDhPub, jbyteArray accountSignPub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;

    veil::Bytes cred = fromArray(env, credential);
    veil::Bytes dh = fromArray(env, accountDhPub);
    veil::Bytes sign = fromArray(env, accountSignPub);
    if (dh.size() != veil::kKeySize || sign.size() != 32) return JNI_FALSE;

    return engine->adoptDeviceCredential(cred.data(), cred.size(), dh.data(), sign.data())
               ? JNI_TRUE
               : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeAdoptDeviceList(
    JNIEnv* env, jobject /*thiz*/, jlong handle, jstring userId, jint version,
    jbyteArray data, jbyteArray accountDhPub, jbyteArray accountSignPub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return veil::Engine::Result::BadBundle;

    veil::Bytes entries = fromArray(env, data);
    veil::Bytes dh = fromArray(env, accountDhPub);
    veil::Bytes sign = fromArray(env, accountSignPub);
    if (dh.size() != veil::kKeySize || sign.size() != 32) {
        return veil::Engine::Result::BadBundle;
    }

    return static_cast<jint>(
        engine->adoptDeviceList(toStd(env, userId), static_cast<uint32_t>(version),
                                entries.data(), entries.size(), dh.data(), sign.data()));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeEncryptToAccount(JNIEnv* env, jobject /*thiz*/,
                                                      jlong handle, jstring userId,
                                                      jbyteArray plain) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;

    veil::Bytes data = fromArray(env, plain);
    const auto frames = engine->encryptToAccount(toStd(env, userId),
                                                 data.data(), data.size());

    // Same record sequence the C ABI produces, so a caller parsing one can parse
    // the other: a length prefix, then the id length, the id, and the frame.
    veil::Bytes out;
    for (const auto& item : frames) {
        out.resize(out.size() + 4);
        veil::put_u32(out.data() + out.size() - 4,
                      static_cast<uint32_t>(1 + item.device_id.size() + 4 + item.frame.size()));

        out.push_back(static_cast<uint8_t>(item.device_id.size()));
        out.insert(out.end(), item.device_id.begin(), item.device_id.end());

        out.resize(out.size() + 4);
        veil::put_u32(out.data() + out.size() - 4, static_cast<uint32_t>(item.frame.size()));
        out.insert(out.end(), item.frame.begin(), item.frame.end());
    }
    return toArray(env, out);
}

// ---- Groups ------------------------------------------------------------

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeCreateGroup(JNIEnv* env, jobject /*thiz*/,
                                                jlong handle, jstring groupId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;
    return engine->createGroup(toStd(env, groupId)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeSetGroupMembers(JNIEnv* env, jobject /*thiz*/,
                                                    jlong handle, jstring groupId,
                                                    jobjectArray members) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return 0;

    std::vector<std::string> list;
    const jsize count = env->GetArrayLength(members);
    list.reserve(static_cast<size_t>(count));
    for (jsize i = 0; i < count; ++i) {
        auto item = static_cast<jstring>(env->GetObjectArrayElement(members, i));
        list.push_back(toStd(env, item));
        env->DeleteLocalRef(item);
    }

    return static_cast<jint>(engine->setGroupMembers(toStd(env, groupId), list));
}

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeGroupEpoch(JNIEnv* env, jobject /*thiz*/,
                                               jlong handle, jstring groupId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return 0;
    return static_cast<jint>(engine->groupEpoch(toStd(env, groupId)));
}

JNIEXPORT jobjectArray JNICALL
Java_com_veil_core_VeilNative_nativeGroupMembers(JNIEnv* env, jobject /*thiz*/,
                                                 jlong handle, jstring groupId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;

    const std::vector<std::string> members = engine->groupMembers(toStd(env, groupId));

    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(members.size()),
                                           stringClass, nullptr);
    for (size_t i = 0; i < members.size(); ++i) {
        env->SetObjectArrayElement(out, static_cast<jsize>(i), toJString(env, members[i]));
    }
    return out;
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeIsGroupMember(JNIEnv* env, jobject /*thiz*/,
                                                  jlong handle, jstring groupId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;
    return engine->isGroupMember(toStd(env, groupId)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeExportMembership(JNIEnv* env, jobject /*thiz*/,
                                                     jlong handle, jstring groupId) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportMembership(toStd(env, groupId)));
}

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeAdoptMembership(JNIEnv* env, jobject /*thiz*/,
                                                    jlong handle, jbyteArray data,
                                                    jbyteArray founderSignPub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return veil::Engine::Result::BadBundle;

    veil::Bytes blob = fromArray(env, data);
    veil::Bytes key = fromArray(env, founderSignPub);
    if (key.size() != 32) return veil::Engine::Result::BadSignature;

    return static_cast<jint>(
        engine->adoptMembership(blob.data(), blob.size(), key.data()));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeExportSenderKey(JNIEnv* env, jobject /*thiz*/,
                                                    jlong handle, jstring groupId,
                                                    jint epoch) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;
    return toArray(env, engine->exportSenderKey(toStd(env, groupId),
                                                static_cast<uint32_t>(epoch)));
}

JNIEXPORT jint JNICALL
Java_com_veil_core_VeilNative_nativeAdoptSenderKey(JNIEnv* env, jobject /*thiz*/,
                                                   jlong handle, jbyteArray data,
                                                   jstring senderId,
                                                   jbyteArray senderSignPub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return veil::Engine::Result::BadBundle;

    veil::Bytes blob = fromArray(env, data);
    veil::Bytes key = fromArray(env, senderSignPub);
    if (key.size() != 32) return veil::Engine::Result::BadSignature;

    return static_cast<jint>(
        engine->adoptSenderKey(blob.data(), blob.size(), toStd(env, senderId), key.data()));
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeEncryptToGroup(JNIEnv* env, jobject /*thiz*/,
                                                   jlong handle, jstring groupId,
                                                   jbyteArray plain) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;

    veil::Bytes data = fromArray(env, plain);
    veil::GroupMessage message;
    if (!engine->encryptToGroup(toStd(env, groupId), data.data(), data.size(), message)) {
        return nullptr;
    }

    // [2] sender len | sender | [4] epoch | [4] iteration | [4] len | ciphertext
    veil::Bytes out;
    out.reserve(2 + message.sender_id.size() + 12 + message.ciphertext.size());

    out.push_back(static_cast<uint8_t>((message.sender_id.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(message.sender_id.size() & 0xFF));
    out.insert(out.end(), message.sender_id.begin(), message.sender_id.end());

    for (uint32_t value : {message.epoch, message.iteration,
                           static_cast<uint32_t>(message.ciphertext.size())}) {
        uint8_t num[4];
        veil::put_u32(num, value);
        out.insert(out.end(), num, num + 4);
    }
    out.insert(out.end(), message.ciphertext.begin(), message.ciphertext.end());
    return toArray(env, out);
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeDecryptFromGroup(JNIEnv* env, jobject /*thiz*/,
                                                     jlong handle, jstring groupId,
                                                     jbyteArray record) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;

    veil::Bytes blob = fromArray(env, record);
    if (blob.size() < 14) return nullptr;

    size_t off = 0;
    const size_t senderLen = (static_cast<size_t>(blob[off]) << 8) | blob[off + 1];
    off += 2;
    if (blob.size() - off < senderLen + 12) return nullptr;

    veil::GroupMessage message;
    message.sender_id.assign(reinterpret_cast<const char*>(blob.data() + off), senderLen);
    off += senderLen;

    message.epoch = veil::get_u32(blob.data() + off); off += 4;
    message.iteration = veil::get_u32(blob.data() + off); off += 4;
    const uint32_t cipherLen = veil::get_u32(blob.data() + off); off += 4;
    if (blob.size() - off < cipherLen) return nullptr;
    message.ciphertext.assign(blob.begin() + off, blob.begin() + off + cipherLen);

    veil::Bytes plain;
    if (engine->decryptFromGroup(toStd(env, groupId), message, plain) !=
        veil::Engine::Result::Ok) {
        veil::wipe(plain);
        return nullptr;
    }
    return toArray(env, plain);
}

JNIEXPORT jbyteArray JNICALL
Java_com_veil_core_VeilNative_nativeExportGroupState(JNIEnv* env, jobject /*thiz*/,
                                                     jlong handle) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return nullptr;

    // The blob carries chain keys, so it is wiped here rather than left in a
    // temporary that only looks short-lived.
    veil::Bytes state = engine->exportGroupState();
    jbyteArray out = toArray(env, state);
    veil::wipe(state);
    return out;
}

JNIEXPORT jboolean JNICALL
Java_com_veil_core_VeilNative_nativeImportGroupState(JNIEnv* env, jobject /*thiz*/,
                                                     jlong handle, jbyteArray blob) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return JNI_FALSE;

    veil::Bytes data = fromArray(env, blob);
    const bool ok = engine->importGroupState(data.data(), data.size());
    veil::wipe(data);
    return ok ? JNI_TRUE : JNI_FALSE;
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
