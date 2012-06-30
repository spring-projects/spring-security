// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package org.springframework.security.crypto.bcrypt;

import java.util.Arrays;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * JUnit unit tests for BCrypt routines
 * @author Damien Miller
 */
public class BCryptTests {

    private static void print(String s) {
        // System.out.print(s);
    }

    private static void println(String s) {
        // System.out.println(s);
    }

    String test_vectors[][] = {
        {"",
            "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
            "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
        {"",
            "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
            "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"},
        {"",
            "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
            "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"},
        {"",
            "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
            "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"},
        {"a",
            "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
            "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"},
        {"a",
            "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
            "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."},
        {"a",
            "$2a$10$k87L/MF28Q673VKh8/cPi.",
            "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"},
        {"a",
            "$2a$12$8NJH3LsPrANStV6XtBakCe",
            "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"},
        {"abc",
            "$2a$06$If6bvum7DFjUnE9p2uDeDu",
            "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
        {"abc",
            "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
            "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"},
        {"abc",
            "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
            "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"},
        {"abc",
            "$2a$12$EXRkfkdmXn2gzds2SSitu.",
            "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"},
        {"abcdefghijklmnopqrstuvwxyz",
            "$2a$06$.rCVZVOThsIa97pEDOxvGu",
            "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
        {"abcdefghijklmnopqrstuvwxyz",
            "$2a$08$aTsUwsyowQuzRrDqFflhge",
            "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."},
        {"abcdefghijklmnopqrstuvwxyz",
            "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
            "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"},
        {"abcdefghijklmnopqrstuvwxyz",
            "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
            "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"},
        {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$06$fPIsBO8qRqkjj273rfaOI.",
            "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"},
        {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$08$Eq2r4G/76Wv39MzSX262hu",
            "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"},
        {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
            "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"},
        {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$12$WApznUOJfkEGSmYRfnkrPO",
            "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"}
    };

    /**
     * Test method for 'BCrypt.hashpw(String, String)'
     */
    @Test
    public void testHashpw() {
        print("BCrypt.hashpw(): ");
        for (int i = 0; i < test_vectors.length; i++) {
            String plain = test_vectors[i][0];
            String salt = test_vectors[i][1];
            String expected = test_vectors[i][2];
            String hashed = BCrypt.hashpw(plain, salt);
            assertEquals(hashed, expected);
            print(".");
        }
        println("");
    }

    /**
     * Test method for 'BCrypt.gensalt(int)'
     */
    @Test
    public void testGensaltInt() {
        print("BCrypt.gensalt(log_rounds):");
        for (int i = 4; i <= 12; i++) {
            print(" " + Integer.toString(i) + ":");
            for (int j = 0; j < test_vectors.length; j += 4) {
                String plain = test_vectors[j][0];
                String salt = BCrypt.gensalt(i);
                String hashed1 = BCrypt.hashpw(plain, salt);
                String hashed2 = BCrypt.hashpw(plain, hashed1);
                assertEquals(hashed1, hashed2);
                print(".");
            }
        }
        println("");
    }

    /**
     * Test method for 'BCrypt.gensalt()'
     */
    @Test
    public void testGensalt() {
        print("BCrypt.gensalt(): ");
        for (int i = 0; i < test_vectors.length; i += 4) {
            String plain = test_vectors[i][0];
            String salt = BCrypt.gensalt();
            String hashed1 = BCrypt.hashpw(plain, salt);
            String hashed2 = BCrypt.hashpw(plain, hashed1);
            assertEquals(hashed1, hashed2);
            print(".");
        }
        println("");
    }

    /**
     * Test method for 'BCrypt.checkpw(String, String)' expecting success
     */
    @Test
    public void testCheckpw_success() {
        print("BCrypt.checkpw w/ good passwords: ");
        for (int i = 0; i < test_vectors.length; i++) {
            String plain = test_vectors[i][0];
            String expected = test_vectors[i][2];
            assertTrue(BCrypt.checkpw(plain, expected));
            print(".");
        }
        println("");
    }

    /**
     * Test method for 'BCrypt.checkpw(String, String)' expecting failure
     */
    @Test
    public void testCheckpw_failure() {
        print("BCrypt.checkpw w/ bad passwords: ");
        for (int i = 0; i < test_vectors.length; i++) {
            int broken_index = (i + 4) % test_vectors.length;
            String plain = test_vectors[i][0];
            String expected = test_vectors[broken_index][2];
            assertFalse(BCrypt.checkpw(plain, expected));
            print(".");
        }
        println("");
    }

    /**
     * Test for correct hashing of non-US-ASCII passwords
     */
    @Test
    public void testInternationalChars() {
        print("BCrypt.hashpw w/ international chars: ");
        String pw1 = "ππππππππ";
        String pw2 = "????????";

        String h1 = BCrypt.hashpw(pw1, BCrypt.gensalt());
        assertFalse(BCrypt.checkpw(pw2, h1));
        print(".");

        String h2 = BCrypt.hashpw(pw2, BCrypt.gensalt());
        assertFalse(BCrypt.checkpw(pw1, h2));
        print(".");
        println("");
    }

    @Test
    public void roundsForDoesNotOverflow() {
        assertEquals(1024, BCrypt.roundsForLogRounds(10));
        assertEquals(0x80000000L, BCrypt.roundsForLogRounds(31));
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyByteArrayCannotBeEncoded() {
        BCrypt.encode_base64(new byte[0], 0, new StringBuilder());
    }

    @Test(expected = IllegalArgumentException.class)
    public void moreBytesThanInTheArrayCannotBeEncoded() {
        BCrypt.encode_base64(new byte[1], 2, new StringBuilder());
    }

    @Test(expected = IllegalArgumentException.class)
    public void decodingMustRequestMoreThanZeroBytes() {
        BCrypt.decode_base64("", 0);
    }

    private static String encode_base64(byte d[], int len) throws IllegalArgumentException {
        StringBuilder rs = new StringBuilder();
        BCrypt.encode_base64(d, len, rs);
        return rs.toString();
    }

    @Test
    public void testBase64EncodeSimpleByteArrays() {
        assertEquals("..", encode_base64(new byte[] { 0 }, 1));
        assertEquals("...", encode_base64(new byte[] { 0, 0 }, 2));
        assertEquals("....", encode_base64(new byte[] { 0, 0, 0 }, 3));
    }

    @Test
    public void decodingCharsOutsideAsciiGivesNoResults() {
        byte[] ba = BCrypt.decode_base64("ππππππππ", 1);
        assertEquals(0, ba.length);
    }

    @Test
    public void decodingStopsWithFirstInvalidCharacter() {
        assertEquals(1, BCrypt.decode_base64("....", 1).length);
        assertEquals(0, BCrypt.decode_base64(" ....", 1).length);
    }

    @Test
    public void decodingOnlyProvidesAvailableBytes() {
        assertEquals(0, BCrypt.decode_base64("", 1).length);
        assertEquals(3, BCrypt.decode_base64("......", 3).length);
        assertEquals(4, BCrypt.decode_base64("......", 4).length);
        assertEquals(4, BCrypt.decode_base64("......", 5).length);
    }

    /**
     * Encode and decode each byte value in each position.
     */
    @Test
    public void testBase64EncodeDecode() {
        byte[] ba = new byte[3];

        for (int b = 0; b <= 0xFF; b++) {
            for (int i = 0; i < ba.length; i++) {
                Arrays.fill(ba, (byte) 0);
                ba[i] = (byte) b;

                String s = encode_base64(ba, 3);
                assertEquals(4, s.length());

                byte[] decoded = BCrypt.decode_base64(s, 3);
                assertArrayEquals(ba, decoded);
            }
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void genSaltFailsWithTooFewRounds() {
        BCrypt.gensalt(3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void genSaltFailsWithTooManyRounds() {
        BCrypt.gensalt(32);
    }

    @Test
    public void genSaltGeneratesCorrectSaltPrefix() {
        assertTrue(BCrypt.gensalt(4).startsWith("$2a$04$"));
        assertTrue(BCrypt.gensalt(31).startsWith("$2a$31$"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void hashpwFailsWhenSaltSpecifiesTooFewRounds() {
        BCrypt.hashpw("password", "$2a$03$......................");
    }

    @Test(expected = IllegalArgumentException.class)
    public void hashpwFailsWhenSaltSpecifiesTooManyRounds() {
        BCrypt.hashpw("password", "$2a$32$......................");
    }

    @Test(expected = IllegalArgumentException.class)
    public void saltLengthIsChecked() {
        BCrypt.hashpw("", "");
    }

    @Test
    public void hashpwWorksWithOldRevision() {
        assertEquals("$2$05$......................bvpG2UfzdyW/S0ny/4YyEZrmczoJfVm",
                BCrypt.hashpw("password", "$2$05$......................"));
    }

    @Test
    public void equalsOnStringsIsCorrect() {
        assertTrue(BCrypt.equalsNoEarlyReturn("", ""));
        assertTrue(BCrypt.equalsNoEarlyReturn("test", "test"));

        assertFalse(BCrypt.equalsNoEarlyReturn("test", ""));
        assertFalse(BCrypt.equalsNoEarlyReturn("", "test"));

        assertFalse(BCrypt.equalsNoEarlyReturn("test", "pass"));
    }
}
