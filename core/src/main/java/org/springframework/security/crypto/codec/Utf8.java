package org.springframework.security.crypto.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;

/**
 * UTF-8 Charset encoder/decoder.
 * <p>
 * For internal use only.
 *
 * @author Luke Taylor
 */
public final class Utf8 {
    private static final Charset CHARSET = Charset.forName("UTF-8");

    /**
     * Get the bytes of the String in UTF-8 encoded form.
     */
    public static byte[] encode(CharSequence string) {
        try {
            return CHARSET.newEncoder().encode(CharBuffer.wrap(string)).array();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Encoding failed", e);
        }
    }

    /**
     * Decode the bytes in UTF-8 form into a String.
     */
    public static String decode(byte[] bytes) {
        try {
            return new String(CHARSET.newDecoder().decode(ByteBuffer.wrap(bytes)).array());
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Encoding failed", e);
        }
    }
}
