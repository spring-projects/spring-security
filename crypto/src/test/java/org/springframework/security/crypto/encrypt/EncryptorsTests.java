package org.springframework.security.crypto.encrypt;

import static org.assertj.core.api.Assertions.assertThat;
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
		assertThat(result).isNotNull();
		assertThat(new String(result).equals("text")).isFalse();
		assertThat(new String(encryptor.decrypt(result))).isEqualTo("text");
		assertThat(new String(result)).isNotEqualTo(new String(encryptor.encrypt("text"
				.getBytes())));
	}

	@Test
	public void standard() throws Exception {
		BytesEncryptor encryptor = Encryptors.standard("password", "5c0744940b5c369b");
		byte[] result = encryptor.encrypt("text".getBytes("UTF-8"));
		assertThat(result).isNotNull();
		assertThat(new String(result).equals("text")).isFalse();
		assertThat(new String(encryptor.decrypt(result))).isEqualTo("text");
		assertThat(new String(result)).isNotEqualTo(new String(encryptor.encrypt("text"
				.getBytes())));
	}

	@Test
	public void preferred() {
		Assume.assumeTrue("GCM must be available for this test", isAesGcmAvailable());

		TextEncryptor encryptor = Encryptors.delux("password", "5c0744940b5c369b");
		String result = encryptor.encrypt("text");
		assertThat(result).isNotNull();
		assertThat(result.equals("text")).isFalse();
		assertThat(encryptor.decrypt(result)).isEqualTo("text");
		assertThat(result.equals(encryptor.encrypt("text"))).isFalse();
	}

	@Test
	public void text() {
		TextEncryptor encryptor = Encryptors.text("password", "5c0744940b5c369b");
		String result = encryptor.encrypt("text");
		assertThat(result).isNotNull();
		assertThat(result.equals("text")).isFalse();
		assertThat(encryptor.decrypt(result)).isEqualTo("text");
		assertThat(result.equals(encryptor.encrypt("text"))).isFalse();
	}

	@Test
	public void queryableText() {
		TextEncryptor encryptor = Encryptors
				.queryableText("password", "5c0744940b5c369b");
		String result = encryptor.encrypt("text");
		assertThat(result).isNotNull();
		assertThat(result.equals("text")).isFalse();
		assertThat(encryptor.decrypt(result)).isEqualTo("text");
		assertThat(result.equals(encryptor.encrypt("text"))).isTrue();
	}

	@Test
	public void noOpText() {
		TextEncryptor encryptor = Encryptors.noOpText();
		assertThat(encryptor.encrypt("text")).isEqualTo("text");
		assertThat(encryptor.decrypt("text")).isEqualTo("text");
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
