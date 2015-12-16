package org.springframework.security.core.token;

import java.security.SecureRandom;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.core.token.SecureRandomFactoryBean;

import junit.framework.Assert;

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
		Assert.assertThat(factory.getObjectType()).isEqualTo(SecureRandom.class);
	}

	@Test
	public void testIsSingleton() {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Assert.assertThat(factory.isSingleton()).isFalse();
	}

	@Test
	public void testCreatesUsingDefaults() throws Exception {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Object result = factory.getObject();
		Assert.assertThat(result instanceof SecureRandom).isTrue();
		int rnd = ((SecureRandom) result).nextInt();
		Assert.assertThat(rnd != 0).isTrue();
	}

	@Test
	public void testCreatesUsingSeed() throws Exception {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Resource resource = new ClassPathResource(
				"org/springframework/security/core/token/SecureRandomFactoryBeanTests.class");
		Assert.assertThat(resource).isNotNull();
		factory.setSeed(resource);
		Object result = factory.getObject();
		Assert.assertThat(result instanceof SecureRandom).isTrue();
		int rnd = ((SecureRandom) result).nextInt();
		Assert.assertThat(rnd != 0).isTrue();
	}

}
