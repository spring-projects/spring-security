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
    public void digestIsCorrectFor2Iterations() {
        Digester digester = new Digester("SHA-1", 2);
        byte[] result = digester.digest(Utf8.encode("text"));
        // echo -n text | openssl sha1 -binary | openssl sha1
        assertEquals("cdcefc6a573f294e60e1d633bca3aeba450954a3", new String(Hex.encode(result)));
    }

}
