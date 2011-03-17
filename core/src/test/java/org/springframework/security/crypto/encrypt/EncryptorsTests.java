package org.springframework.security.crypto.encrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class EncryptorsTests {

    @Test
    public void standard() throws Exception {
        BytesEncryptor encryptor = Encryptors.standard("password", "5c0744940b5c369b");
        byte[] result = encryptor.encrypt("text".getBytes("UTF-8"));
        assertNotNull(result);
        assertFalse(new String(result).equals("text"));
        assertEquals("text", new String(encryptor.decrypt(result)));
        assertFalse(new String(result).equals(new String(encryptor.encrypt("text".getBytes()))));
    }

    @Test
    public void text() {
        TextEncryptor encryptor = Encryptors.text("password", "5c0744940b5c369b");
        String result = encryptor.encrypt("text");
        assertNotNull(result);
        assertFalse(result.equals("text"));
        assertEquals("text", encryptor.decrypt(result));
        assertFalse(result.equals(encryptor.encrypt("text")));
    }

    @Test
    public void queryableText() {
        TextEncryptor encryptor = Encryptors.queryableText("password", "5c0744940b5c369b");
        String result = encryptor.encrypt("text");
        assertNotNull(result);
        assertFalse(result.equals("text"));
        assertEquals("text", encryptor.decrypt(result));
        assertTrue(result.equals(encryptor.encrypt("text")));
    }

    @Test
    public void noOpText() {
        TextEncryptor encryptor = Encryptors.noOpText();
        assertEquals("text", encryptor.encrypt("text"));
        assertEquals("text", encryptor.decrypt("text"));
    }
}
