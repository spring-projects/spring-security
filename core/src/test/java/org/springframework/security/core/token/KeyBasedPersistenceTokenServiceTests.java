/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.core.token;

import static org.assertj.core.api.Assertions.*;

import java.security.SecureRandom;
import java.util.Date;

import org.junit.Test;
import org.springframework.security.core.token.DefaultToken;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.SecureRandomFactoryBean;
import org.springframework.security.core.token.Token;

/**
 * Tests {@link KeyBasedPersistenceTokenService}.
 *
 * @author Ben Alex
 *
 */
public class KeyBasedPersistenceTokenServiceTests {

	private KeyBasedPersistenceTokenService getService() {
		SecureRandomFactoryBean fb = new SecureRandomFactoryBean();
		KeyBasedPersistenceTokenService service = new KeyBasedPersistenceTokenService();
		service.setServerSecret("MY:SECRET$$$#");
		service.setServerInteger(454545);
		try {
			SecureRandom rnd = fb.getObject();
			service.setSecureRandom(rnd);
			service.afterPropertiesSet();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		return service;
	}

	@Test
	public void testOperationWithSimpleExtendedInformation() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = service.allocateToken("Hello world");
		Token result = service.verifyToken(token.getKey());
		assertThat(result).isEqualTo(token);
	}

	@Test
	public void testOperationWithComplexExtendedInformation() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = service.allocateToken("Hello:world:::");
		Token result = service.verifyToken(token.getKey());
		assertThat(result).isEqualTo(token);
	}

	@Test
	public void testOperationWithEmptyRandomNumber() {
		KeyBasedPersistenceTokenService service = getService();
		service.setPseudoRandomNumberBytes(0);
		Token token = service.allocateToken("Hello:world:::");
		Token result = service.verifyToken(token.getKey());
		assertThat(result).isEqualTo(token);
	}

	@Test
	public void testOperationWithNoExtendedInformation() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = service.allocateToken("");
		Token result = service.verifyToken(token.getKey());
		assertThat(result).isEqualTo(token);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testOperationWithMissingKey() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = new DefaultToken("", new Date().getTime(), "");
		service.verifyToken(token.getKey());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testOperationWithTamperedKey() {
		KeyBasedPersistenceTokenService service = getService();
		Token goodToken = service.allocateToken("");
		String fake = goodToken.getKey().toUpperCase();
		Token token = new DefaultToken(fake, new Date().getTime(), "");
		service.verifyToken(token.getKey());
	}

}
