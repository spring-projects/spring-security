package org.springframework.security.crypto.password;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class StandardPasswordEncoderTests {

    private StandardPasswordEncoder encoder = new StandardPasswordEncoder("secret");

    @Test
    public void matches() {
        String result = encoder.encode("password");
        assertFalse(result.equals("password"));
        assertTrue(encoder.matches("password", result));
    }

    @Test
    public void notMatches() {
        String result = encoder.encode("password");
        assertFalse(encoder.matches("bogus", result));
    }

}
