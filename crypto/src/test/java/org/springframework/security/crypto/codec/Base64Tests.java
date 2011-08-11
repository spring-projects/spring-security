package org.springframework.security.crypto.codec;

import static org.junit.Assert.*;

import org.junit.*;

/**
 * @author Luke Taylor
 */
public class Base64Tests {

    @Test
    public void isBase64ReturnsTrueForValidBase64() {
        new Base64(); // unused

        assertTrue(Base64.isBase64(new byte[]{ (byte)'A',(byte)'B',(byte)'C',(byte)'D'}));
    }

    @Test
    public void isBase64ReturnsFalseForInvalidBase64() throws Exception {
        // Include invalid '`' character
        assertFalse(Base64.isBase64(new byte[]{ (byte)'A',(byte)'B',(byte)'C',(byte)'`'}));
    }

    @Test(expected = NullPointerException.class)
    public void isBase64RejectsNull() {
        Base64.isBase64(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void isBase64RejectsInvalidLength() {
        Base64.isBase64(new byte[]{ (byte)'A'});
    }
}
