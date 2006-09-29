package org.acegisecurity.util;

import junit.framework.TestCase;

import org.acegisecurity.util.EncryptionUtils.EncryptionException;

/**
 * JUnit tests for EncryptionUtils.
 * 
 * @author Alan Stewart
 * @author Ben Alex
 */
public class EncryptionUtilsTests extends TestCase {
	private final static String STRING_TO_ENCRYPT = "Alan K Stewart";
	private final static String ENCRYPTION_KEY = "123456789012345678901234567890";

	public void testEncryptsUsingDESEde() throws EncryptionException {
		final String encryptedString = EncryptionUtils.encrypt(ENCRYPTION_KEY, STRING_TO_ENCRYPT);
		assertEquals("3YIE8sIbaEoqGZZrHamFGQ==", encryptedString);
	}

	public void testEncryptionKeyCanContainLetters() throws EncryptionException {
		final String encryptedString = EncryptionUtils.encrypt("ASDF asdf 1234 8983 jklasdf J2Jaf8", STRING_TO_ENCRYPT);
		assertEquals("v4+DQoClx6qm5tJwBcRrkw==", encryptedString);
	}

	public void testDecryptsUsingDESEde() throws EncryptionException {
		final String encryptedString = "3YIE8sIbaEoqGZZrHamFGQ==";
		final String decryptedString = EncryptionUtils.decrypt(ENCRYPTION_KEY, encryptedString);
		assertEquals(STRING_TO_ENCRYPT, decryptedString);
	}

	public void testCantEncryptWithNullEncryptionKey() throws EncryptionException {
		try {
			EncryptionUtils.encrypt(null, "");
			fail("Should have thrown IAE");
		} catch (final IllegalArgumentException e) {
			assertTrue(true);
		}
	}

	public void testCantEncryptWithEmptyEncryptionKey() throws EncryptionException {
		try {
			EncryptionUtils.encrypt("", "");
			fail("Should have thrown IAE");
		} catch (final IllegalArgumentException e) {
			assertTrue(true);
		}
	}

	public void testCantEncryptWithShortEncryptionKey() throws EncryptionException {
		try {
			EncryptionUtils.encrypt("01234567890123456789012", "");
			fail("Should have thrown IAE");
		} catch (final IllegalArgumentException e) {
			assertTrue(true);
		}
	}

	public void testCantDecryptWithEmptyString() throws EncryptionException {
		try {
			EncryptionUtils.decrypt(ENCRYPTION_KEY, "");
			fail("Should have thrown IAE");
		} catch (final IllegalArgumentException e) {
			assertTrue(true);
		}
	}

	public void testCantEncryptWithEmptyString() throws EncryptionException {
		try {
			EncryptionUtils.encrypt(ENCRYPTION_KEY, "");
			fail("Should have thrown IAE");
		} catch (final IllegalArgumentException e) {
			assertTrue(true);
		}
	}

	public void testCantEncryptWithNullString() throws EncryptionException {
		try {
			EncryptionUtils.encrypt(ENCRYPTION_KEY, null);
			fail("Should have thrown IAE");
		} catch (final IllegalArgumentException e) {
			assertTrue(true);
		}
	}

	public void testEncryptAndDecrypt() throws EncryptionException {
		final String stringToEncrypt = "Alan Stewart";
		final String encryptedString = EncryptionUtils.encrypt(ENCRYPTION_KEY, stringToEncrypt);
		final String decryptedString = EncryptionUtils.decrypt(ENCRYPTION_KEY, encryptedString);
		assertEquals(stringToEncrypt, decryptedString);
	}
}
