package org.springframework.security.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;

/**
 * Provides SHA512 digest methods.
 * 
 * <p>
 * Based on Commons Codec, which does not presently provide SHA512 support.
 * </p>
 * 
 * @author Ben Alex
 * @since 2.0.1
 *
 */
public abstract class Sha512DigestUtils  {
    /**
     * Returns a MessageDigest for the given <code>algorithm</code>.
     *
     * @param algorithm The MessageDigest algorithm name.
     * @return An MD5 digest instance.
     * @throws RuntimeException when a {@link java.security.NoSuchAlgorithmException} is caught,
     */
    static MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * Returns an SHA digest.
     *
     * @return An SHA digest instance.
     * @throws RuntimeException when a {@link java.security.NoSuchAlgorithmException} is caught,
     */
    private static MessageDigest getSha512Digest() {
        return getDigest("SHA-512");
    }

    /**
     * Calculates the SHA digest and returns the value as a 
     * <code>byte[]</code>.
     *
     * @param data Data to digest
     * @return SHA digest
     */
    public static byte[] sha(byte[] data) {
        return getSha512Digest().digest(data);
    }

    /**
     * Calculates the SHA digest and returns the value as a 
     * <code>byte[]</code>.
     *
     * @param data Data to digest
     * @return SHA digest
     */
    public static byte[] sha(String data) {
        return sha(data.getBytes());
    }

    /**
     * Calculates the SHA digest and returns the value as a hex string.
     *
     * @param data Data to digest
     * @return SHA digest as a hex string
     */
    public static String shaHex(byte[] data) {
        return new String(Hex.encodeHex(sha(data)));
    }

    /**
     * Calculates the SHA digest and returns the value as a hex string.
     *
     * @param data Data to digest
     * @return SHA digest as a hex string
     */
    public static String shaHex(String data) {
        return new String(Hex.encodeHex(sha(data)));
    }

}
