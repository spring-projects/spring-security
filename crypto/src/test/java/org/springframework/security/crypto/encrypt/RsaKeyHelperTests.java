/*
 * Copyright 2013-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.crypto.encrypt;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;

import static org.assertj.core.api.Assertions.assertThat;

@DisabledOnOs(OS.WINDOWS)
public class RsaKeyHelperTests {

	@Test
	public void parsePrivateKey() throws Exception {
		// ssh-keygen -m pem -b 1024 -f src/test/resources/fake.pem
		String pem = StreamUtils.copyToString(new ClassPathResource("/fake.pem", getClass()).getInputStream(),
				StandardCharsets.UTF_8);
		KeyPair result = RsaKeyHelper.parseKeyPair(pem);
		assertThat(result.getPrivate().getEncoded().length > 0).isTrue();
		assertThat(result.getPrivate().getAlgorithm()).isEqualTo("RSA");
	}

	@Test
	public void parseSpaceyKey() throws Exception {
		String pem = StreamUtils.copyToString(new ClassPathResource("/spacey.pem", getClass()).getInputStream(),
				StandardCharsets.UTF_8);
		KeyPair result = RsaKeyHelper.parseKeyPair(pem);
		assertThat(result.getPrivate().getEncoded().length > 0).isTrue();
		assertThat(result.getPrivate().getAlgorithm()).isEqualTo("RSA");
	}

	@Test
	public void parseBadKey() throws Exception {
		// ssh-keygen -m pem -b 1024 -f src/test/resources/fake.pem
		String pem = StreamUtils.copyToString(new ClassPathResource("/bad.pem", getClass()).getInputStream(),
				StandardCharsets.UTF_8);
		try {
			RsaKeyHelper.parseKeyPair(pem);
			throw new IllegalStateException("Expected IllegalArgumentException");
		}
		catch (IllegalArgumentException ex) {
			assertThat(ex.getMessage().contains("PEM")).isTrue();
		}
	}

}
