package org.springframework.security.crypto.keygen;

import static org.assertj.core.api.Assertions.*;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.security.crypto.codec.Hex;

public class KeyGeneratorsTests {

	@Test
	public void secureRandom() {
		BytesKeyGenerator keyGenerator = KeyGenerators.secureRandom();
		assertThat(keyGenerator.getKeyLength()).isEqualTo(8);
		byte[] key = keyGenerator.generateKey();
		assertThat(key.length).isEqualTo(8);
		byte[] key2 = keyGenerator.generateKey();
		assertThat(Arrays.equals(key, key2)).isFalse();
	}

	@Test
	public void secureRandomCustomLength() {
		BytesKeyGenerator keyGenerator = KeyGenerators.secureRandom(21);
		assertThat(keyGenerator.getKeyLength()).isEqualTo(21);
		byte[] key = keyGenerator.generateKey();
		assertThat(key.length).isEqualTo(21);
		byte[] key2 = keyGenerator.generateKey();
		assertThat(Arrays.equals(key, key2)).isFalse();
	}

	@Test
	public void shared() throws Exception {
		BytesKeyGenerator keyGenerator = KeyGenerators.shared(21);
		assertThat(keyGenerator.getKeyLength()).isEqualTo(21);
		byte[] key = keyGenerator.generateKey();
		assertThat(key.length).isEqualTo(21);
		byte[] key2 = keyGenerator.generateKey();
		assertThat(Arrays.equals(key, key2)).isTrue();
	}

	@Test
	public void string() {
		StringKeyGenerator keyGenerator = KeyGenerators.string();
		String hexStringKey = keyGenerator.generateKey();
		assertThat(hexStringKey.length()).isEqualTo(16);
		assertThat(Hex.decode(hexStringKey).length).isEqualTo(8);
		String hexStringKey2 = keyGenerator.generateKey();
		assertThat(hexStringKey.equals(hexStringKey2)).isFalse();
	}

}
