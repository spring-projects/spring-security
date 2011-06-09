package org.springframework.security.crypto.codec;

import static org.junit.Assert.*;

import org.junit.*;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class Utf8Tests {

    // SEC-1752
    @Test
    public void utf8EncodesAndDecodesCorrectly() throws Exception {
        byte[] bytes = Utf8.encode("6048b75ed560785c");
        assertEquals(16, bytes.length);
        assertTrue(Arrays.equals("6048b75ed560785c".getBytes("UTF-8"), bytes));

        String decoded = Utf8.decode(bytes);

        assertEquals("6048b75ed560785c", decoded);
    }
}
