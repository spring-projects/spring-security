package org.springframework.security.crypto.encrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

import org.junit.Assume;
import org.junit.Test;

public class EncryptorsTests {

    @Test
    public void stronger() throws Exception {
        Assume.assumeTrue("GCM must be available for this test", isAesGcmAvailable());

        BytesEncryptor encryptor = Encryptors.stronger("password", "5c0744940b5c369b");
        byte[] result = encryptor.encrypt("text".getBytes("UTF-8"));
        assertNotNull(result);
        assertFalse(new String(result).equals("text"));
        assertEquals("text", new String(encryptor.decrypt(result)));
        assertFalse(new String(result).equals(new String(encryptor.encrypt("text"
                .getBytes()))));
    }

    @Test
    public void standard() throws Exception {
        BytesEncryptor encryptor = Encryptors.standard("password", "5c0744940b5c369b");
        byte[] result = encryptor.encrypt("text".getBytes("UTF-8"));
        assertNotNull(result);
        assertFalse(new String(result).equals("text"));
        assertEquals("text", new String(encryptor.decrypt(result)));
        assertFalse(new String(result).equals(new String(encryptor.encrypt("text"
                .getBytes()))));
    }

    @Test
    public void preferred() {
        Assume.assumeTrue("GCM must be available for this test", isAesGcmAvailable());

        TextEncryptor encryptor = Encryptors.delux("password", "5c0744940b5c369b");
        String result = encryptor.encrypt("text");
        assertNotNull(result);
        assertFalse(result.equals("text"));
        assertEquals("text", encryptor.decrypt(result));
        assertFalse(result.equals(encryptor.encrypt("text")));
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
        TextEncryptor encryptor = Encryptors
                .queryableText("password", "5c0744940b5c369b");
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

    private boolean isAesGcmAvailable() {
        try {
            Cipher.getInstance("AES/GCM/NoPadding");
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
