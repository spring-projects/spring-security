package org.springframework.security.crypto.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.Test;

public class DigesterTests {

    private Digester digester = new Digester("SHA-1", "SUN");

    @Test
    public void digest() {
        byte[] result = digester.digest("text".getBytes());
        assertEquals(20, result.length);
        assertFalse(new String(result).equals("text"));
    }

    @Test
    public void multiPassDigest() throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-1","SUN");
        d.reset();
        byte[] value = "text".getBytes("UTF-8");
        byte[] singlePass = d.digest(value);
        byte[] multiPass = digester.digest(value);
        assertFalse(Arrays.toString(singlePass) + " should not be equal to "
                + Arrays.toString(multiPass),
                Arrays.equals(singlePass, multiPass));
    }
}
