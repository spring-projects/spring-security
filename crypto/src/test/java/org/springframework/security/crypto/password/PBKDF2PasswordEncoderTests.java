package org.springframework.security.crypto.password;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class PBKDF2PasswordEncoderTests {
    private PBKDF2PasswordEncoder encoder = new PBKDF2PasswordEncoder("secret");

    @Test
    public void matches() {
        String result = encoder.encode("password");
        assertFalse(result.equals("password"));
        assertTrue(encoder.matches("password", result));
    }

    @Test
    public void matchesLengthChecked() {
        String result = encoder.encode("password");
        assertFalse(encoder.matches("password", result.substring(0,result.length()-2)));
    }

    @Test
    public void notMatches() {
        String result = encoder.encode("password");
        assertFalse(encoder.matches("bogus", result));
    }

}