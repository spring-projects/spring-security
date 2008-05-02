package org.springframework.security.token;

import java.security.SecureRandom;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

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
		Assert.assertEquals(SecureRandom.class, factory.getObjectType());
	}
	
	@Test
	public void testIsSingleton() {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Assert.assertFalse(factory.isSingleton());
	}

	@Test
	public void testCreatesUsingDefaults() throws Exception {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Object result = factory.getObject();
		Assert.assertTrue(result instanceof SecureRandom);
		int rnd = ((SecureRandom)result).nextInt();
		Assert.assertTrue(rnd != 0);
	}
	
	@Test
	public void testCreatesUsingSeed() throws Exception {
		SecureRandomFactoryBean factory = new SecureRandomFactoryBean();
		Resource resource = new ClassPathResource("org/springframework/security/token/SecureRandomFactoryBeanTests.class");
		Assert.assertNotNull(resource);
		factory.setSeed(resource);
		Object result = factory.getObject();
		Assert.assertTrue(result instanceof SecureRandom);
		int rnd = ((SecureRandom)result).nextInt();
		Assert.assertTrue(rnd != 0);
	}
	
}
