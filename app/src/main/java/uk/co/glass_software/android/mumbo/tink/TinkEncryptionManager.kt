package uk.co.glass_software.android.mumbo.tink

import android.content.Context
import androidx.security.crypto.MasterKeys
import com.google.common.base.Charsets.UTF_8
import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.AeadFactory
import com.google.crypto.tink.aead.AeadKeyTemplates
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.subtle.Base64
import uk.co.glass_software.android.mumbo.base.EncryptionManager
import uk.co.glass_software.android.mumbo.base.EncryptionManager.KeyPolicy.ANDROIDX
import java.nio.ByteBuffer
import java.security.GeneralSecurityException

class TinkEncryptionManager(context: Context) : EncryptionManager {

    companion object {
        private const val SHARED_PREFS_FILE_NAME = "mumbo_tink_shared_prefs"
        private const val VALUE_KEYSET_ALIAS = "__mumbo_tink_value_keyset__"
        private const val KEYSTORE_PATH_URI = "android-keystore://"
        private const val INTEGER_SIZE = 32
        private const val BYTE_SIZE = 8
        private const val INTEGER_BYTES = INTEGER_SIZE / BYTE_SIZE
    }

    private val aead: Aead?
    override val isEncryptionAvailable: Boolean
    override val keyPolicy = ANDROIDX

    init {
        val isAvailable = try {
            TinkConfig.register()
            true
        } catch (e: GeneralSecurityException) {
            false
        }
        isEncryptionAvailable = isAvailable

        if (isAvailable) {
            val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
            val masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec)

            val aeadKeysetHandle = AndroidKeysetManager.Builder()
                    .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
                    .withSharedPref(context, VALUE_KEYSET_ALIAS, SHARED_PREFS_FILE_NAME)
                    .withMasterKeyUri(KEYSTORE_PATH_URI + masterKeyAlias)
                    .build().keysetHandle

            aead = AeadFactory.getPrimitive(aeadKeysetHandle)
        } else {
            aead = null
        }
    }

    override fun encrypt(toEncrypt: String?,
                         dataTag: String,
                         password: String?) =
            if (isEncryptionAvailable && toEncrypt != null) {
                Base64.encode(encryptBytes(
                        toEncrypt.toByteArray(UTF_8),
                        dataTag,
                        password
                ))
            } else null

    override fun encryptBytes(toEncrypt: ByteArray?,
                              dataTag: String,
                              password: String?) =
            if (isEncryptionAvailable && toEncrypt != null) {
                val stringByteLength = toEncrypt.size

                val buffer = ByteBuffer.allocate(
                        INTEGER_BYTES
                                + INTEGER_BYTES
                                + stringByteLength
                )

                buffer.putInt(stringByteLength)
                buffer.put(toEncrypt)

                aead?.encrypt(
                        buffer.array(),
                        dataTag.toByteArray(UTF_8)
                )
            } else null

    override fun decrypt(toDecrypt: String?,
                         dataTag: String,
                         password: String?) =
            try {
                if (isEncryptionAvailable && toDecrypt != null) {
                    val cipherText = Base64.decode(toDecrypt, Base64.DEFAULT)

                    decryptBytesToByteBuffer(cipherText, dataTag).let {
                        UTF_8.decode(it).toString()
                    }
                } else null
            } catch (ex: GeneralSecurityException) {
                throw SecurityException("Could not decrypt value. " + ex.message, ex)
            }

    override fun decryptBytes(toDecrypt: ByteArray?,
                              dataTag: String,
                              password: String?) =
            if (isEncryptionAvailable && toDecrypt != null) {
                decryptBytesToByteBuffer(toDecrypt, dataTag)?.let {
                    ByteArray(it.capacity()).apply {
                        it.get(this)
                    }
                }
            } else null

    private fun decryptBytesToByteBuffer(toDecrypt: ByteArray?,
                                         dataTag: String) =
            if (isEncryptionAvailable && toDecrypt != null) {
                val value = aead?.decrypt(toDecrypt, dataTag.toByteArray(UTF_8))
                val buffer = ByteBuffer.wrap(value)

                buffer.position(0)
                val stringLength = buffer.int
                val stringSlice = buffer.slice()
                buffer.limit(stringLength)
                stringSlice
            } else null

}