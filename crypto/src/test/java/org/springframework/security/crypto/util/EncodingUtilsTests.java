package org.springframework.security.crypto.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

public class EncodingUtilsTests {

    @Test
    public void hexEncode() {
        byte[] bytes = new byte[] { (byte)0x01, (byte)0xFF, (byte)65, (byte)66, (byte)67, (byte)0xC0, (byte)0xC1, (byte)0xC2 };
        String result = EncodingUtils.hexEncode(bytes);
        assertEquals("01ff414243c0c1c2", result);
    }

    @Test
    public void hexDecode() {
        byte[] bytes = new byte[] { (byte)0x01, (byte)0xFF, (byte)65, (byte)66, (byte)67, (byte)0xC0, (byte)0xC1, (byte)0xC2 };
        byte[] result = EncodingUtils.hexDecode("01ff414243c0c1c2");
        assertTrue(Arrays.equals(bytes, result));
    }

    @Test
    public void concatenate() {
        byte[] bytes = new byte[] { (byte)0x01, (byte)0xFF, (byte)65, (byte)66, (byte)67, (byte)0xC0, (byte)0xC1, (byte)0xC2 };
        byte[] one = new byte[] { (byte)0x01 };
        byte[] two = new byte[] { (byte)0xFF, (byte)65, (byte)66 };
        byte[] three = new byte[] { (byte)67, (byte)0xC0, (byte)0xC1, (byte)0xC2 };
        assertTrue(Arrays.equals(bytes, EncodingUtils.concatenate(one, two, three)));
    }

    @Test
    public void subArray() {
        byte[] bytes = new byte[] { (byte)0x01, (byte)0xFF, (byte)65, (byte)66, (byte)67, (byte)0xC0, (byte)0xC1, (byte)0xC2 };
        byte[] two = new byte[] { (byte)0xFF, (byte)65, (byte)66 };
        byte[] subArray = EncodingUtils.subArray(bytes, 1, 4);
        assertEquals(3, subArray.length);
        assertTrue(Arrays.equals(two, subArray));
    }

}
