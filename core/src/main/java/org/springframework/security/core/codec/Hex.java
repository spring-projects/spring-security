package org.springframework.security.core.codec;

/**
 * Hex data encoder. Converts byte arrays (such as those obtained from message digests)
 * into hexadecimal string representation.
 * <p>
 * For internal use only.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public final class Hex {

    private static final char[] HEX = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    public static char[] encode(byte[] bytes) {
        final int nBytes = bytes.length;
        char[] result = new char[2*nBytes];

        int j = 0;
        for (int i=0; i < nBytes; i++) {
            // Char for top 4 bits
            result[j++] = HEX[(0xF0 & bytes[i]) >>> 4 ];
            // Bottom 4
            result[j++] = HEX[(0x0F & bytes[i])];
        }

        return result;
    }

//    public static byte[] decode(char[] hex) {
//
//    }
}
