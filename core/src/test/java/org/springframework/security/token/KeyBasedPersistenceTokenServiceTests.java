

package org.springframework.security.token;

import java.security.SecureRandom;
import java.util.Date;

import junit.framework.Assert;

import org.junit.Test;

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
		service.setServerInteger(new Integer(454545));
		try {
			SecureRandom rnd = (SecureRandom) fb.getObject();
			service.setSecureRandom(rnd);
			service.afterPropertiesSet();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return service;
	}
	
	@Test
	public void testOperationWithSimpleExtendedInformation() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = service.allocateToken("Hello world");
		Token result = service.verifyToken(token.getKey());
		Assert.assertEquals(token, result);
	}


	@Test
	public void testOperationWithComplexExtendedInformation() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = service.allocateToken("Hello:world:::");
		Token result = service.verifyToken(token.getKey());
		Assert.assertEquals(token, result);
	}

	@Test
	public void testOperationWithEmptyRandomNumber() {
		KeyBasedPersistenceTokenService service = getService();
		service.setPseudoRandomNumberBits(0);
		Token token = service.allocateToken("Hello:world:::");
		Token result = service.verifyToken(token.getKey());
		Assert.assertEquals(token, result);
	}
	
	@Test
	public void testOperationWithNoExtendedInformation() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = service.allocateToken("");
		Token result = service.verifyToken(token.getKey());
		Assert.assertEquals(token, result);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testOperationWithMissingKey() {
		KeyBasedPersistenceTokenService service = getService();
		Token token = new DefaultToken("", new Date().getTime(), "");
		service.verifyToken(token.getKey());
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testOperationWithTamperedKey() {
		KeyBasedPersistenceTokenService service = getService();
		Token goodToken = service.allocateToken("");
		String fake = goodToken.getKey().toUpperCase();
		Token token = new DefaultToken(fake, new Date().getTime(), "");
		service.verifyToken(token.getKey());
	}
}
