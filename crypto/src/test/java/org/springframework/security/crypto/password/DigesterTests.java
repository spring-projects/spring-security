package org.springframework.security.crypto.password;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.Test;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.password.Digester;

public class DigesterTests {

    @Test
    public void digestIsCorrectFor3Iterations() {
        Digester digester = new Digester("SHA-1", 3);
        byte[] result = digester.digest(Utf8.encode("text"));
        // echo -n text | openssl sha1 -binary | openssl sha1 -binary | openssl sha1
        assertEquals("3cfa28da425eca5b894f0af2b158adf7001e000f", new String(Hex.encode(result)));
    }

}
