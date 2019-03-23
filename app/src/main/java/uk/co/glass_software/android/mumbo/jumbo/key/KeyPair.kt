package uk.co.glass_software.android.mumbo.jumbo.key

internal data class KeyPair(
    val cipherKey: ByteArray?,
    val macKey: ByteArray?,
    val encryptedCipherKey: ByteArray?,
    val encryptedMacKey: ByteArray?,
    val isEncrypted: Boolean
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyPair

        if (cipherKey != null) {
            if (other.cipherKey == null) return false
            if (!cipherKey.contentEquals(other.cipherKey)) return false
        } else if (other.cipherKey != null) return false
        if (macKey != null) {
            if (other.macKey == null) return false
            if (!macKey.contentEquals(other.macKey)) return false
        } else if (other.macKey != null) return false
        if (encryptedCipherKey != null) {
            if (other.encryptedCipherKey == null) return false
            if (!encryptedCipherKey.contentEquals(other.encryptedCipherKey)) return false
        } else if (other.encryptedCipherKey != null) return false
        if (encryptedMacKey != null) {
            if (other.encryptedMacKey == null) return false
            if (!encryptedMacKey.contentEquals(other.encryptedMacKey)) return false
        } else if (other.encryptedMacKey != null) return false
        if (isEncrypted != other.isEncrypted) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cipherKey?.contentHashCode() ?: 0
        result = 31 * result + (macKey?.contentHashCode() ?: 0)
        result = 31 * result + (encryptedCipherKey?.contentHashCode() ?: 0)
        result = 31 * result + (encryptedMacKey?.contentHashCode() ?: 0)
        result = 31 * result + isEncrypted.hashCode()
        return result
    }
}
