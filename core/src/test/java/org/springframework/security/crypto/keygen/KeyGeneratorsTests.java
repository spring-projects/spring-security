package org.springframework.security.crypto.keygen;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.security.crypto.codec.Hex;

public class KeyGeneratorsTests {

    @Test
    public void secureRandom() {
        BytesKeyGenerator keyGenerator = KeyGenerators.secureRandom();
        assertEquals(8, keyGenerator.getKeyLength());
        byte[] key = keyGenerator.generateKey();
        assertEquals(8, key.length);
        byte[] key2 = keyGenerator.generateKey();
        assertFalse(Arrays.equals(key, key2));
    }

    @Test
    public void secureRandomCustomLength() {
        BytesKeyGenerator keyGenerator = KeyGenerators.secureRandom(16);
        assertEquals(16, keyGenerator.getKeyLength());
        byte[] key = keyGenerator.generateKey();
        assertEquals(16, key.length);
        byte[] key2 = keyGenerator.generateKey();
        assertFalse(Arrays.equals(key, key2));
    }

    @Test
    public void string() {
        StringKeyGenerator keyGenerator = KeyGenerators.string();
        String hexStringKey = keyGenerator.generateKey();
        assertEquals(16, hexStringKey.length());
        assertEquals(8, Hex.decode(hexStringKey).length);
        String hexStringKey2 = keyGenerator.generateKey();
        assertFalse(hexStringKey.equals(hexStringKey2));
    }

}
