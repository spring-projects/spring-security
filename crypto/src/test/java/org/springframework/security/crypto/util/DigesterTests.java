package org.springframework.security.crypto.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

public class DigesterTests {

    private Digester digester = new Digester("SHA-1", "SUN");

    @Test
    public void digest() {
        byte[] result = digester.digest("text".getBytes());
        assertEquals(20, result.length);
        assertFalse(new String(result).equals("text"));
    }

}
