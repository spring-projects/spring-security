package org.springframework.security.authentication.encoding;

import static org.junit.Assert.*;

import org.junit.Test;
/**
 * @author Rob Winch
 */
public class PasswordEncoderUtilsTests {

    @Test
    public void differentLength() {
        assertFalse(PasswordEncoderUtils.equals("abc", "a"));
        assertFalse(PasswordEncoderUtils.equals("a", "abc"));
    }

    @Test
    public void equalsNull() {
        assertFalse(PasswordEncoderUtils.equals(null, "a"));
        assertFalse(PasswordEncoderUtils.equals("a", null));
        assertTrue(PasswordEncoderUtils.equals(null, null));
    }

    @Test
    public void equalsCaseSensitive() {
        assertFalse(PasswordEncoderUtils.equals("aBc", "abc"));
    }

    @Test
    public void equalsSuccess() {
        assertTrue(PasswordEncoderUtils.equals("abcdef", "abcdef"));
    }
}
