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

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.core.token.SecureRandomFactoryBean;

/**
 * Tests {@link SecureRandomFactoryBean}.
 *
 * @author Ben Alex
 *
 */
public class SecureRandomFactoryBeanTests {
	@Test
	public void testObjectType() {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		assertThat(factory.getObjectType()).isEqualTo(SecureRandom.class);
	}

	@Test
	public void testIsSingleton() {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		assertThat(factory.isSingleton()).isFalse();
	}

	@Test
	public void testCreatesUsingDefaults() throws Exception {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Object result = factory.getObject();
		assertThat(result).isInstanceOf(SecureRandom.class);
		int rnd = ((SecureRandom) result).nextInt();
		assertThat(rnd).isNotEqualTo(0);
	}

	@Test
	public void testCreatesUsingSeed() throws Exception {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Resource resource = new ClassPathResource(
				"org/springframework/security/core/token/SecureRandomFactoryBeanTests.class");
		assertThat(resource).isNotNull();
		factory.setSeed(resource);
		Object result = factory.getObject();
		assertThat(result).isInstanceOf(SecureRandom.class);
		int rnd = ((SecureRandom) result).nextInt();
		assertThat(rnd).isNotEqualTo(0);
	}

}
