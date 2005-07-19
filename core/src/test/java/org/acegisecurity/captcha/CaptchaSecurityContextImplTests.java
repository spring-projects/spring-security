package net.sf.acegisecurity.captcha;

import net.sf.acegisecurity.context.SecurityContextImplTests;

public class CaptchaSecurityContextImplTests extends SecurityContextImplTests {

	public void testDefaultValues() {
		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		assertEquals("should not be human", false, context.isHuman());
		assertEquals("should be 0", 0, context
				.getLastPassedCaptchaDateInMillis());
		assertEquals("should be 0", 0, context
				.getHumanRestrictedResourcesRequestsCount());
	}

	public void testSetHuman() {
		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		long now = System.currentTimeMillis();
		context.setHuman();
		assertEquals("should be human", true, context.isHuman());
		assertTrue("should be more than 0", context
				.getLastPassedCaptchaDateInMillis()
				- now >= 0);
		assertTrue("should be less than 0,1 seconde", context
				.getLastPassedCaptchaDateInMillis()
				- now < 100);
		assertEquals("should be 0", 0, context
				.getHumanRestrictedResourcesRequestsCount());
	}

	public void testIncrementRequests() {
		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		context.setHuman();
		assertEquals("should be human", true, context.isHuman());
		assertEquals("should be 0", 0, context
				.getHumanRestrictedResourcesRequestsCount());
		context.incrementHumanRestrictedRessoucesRequestsCount();
		assertEquals("should be 1", 1, context
				.getHumanRestrictedResourcesRequestsCount());
	}

	public void testResetHuman() {
		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		context.setHuman();
		assertEquals("should be human", true, context.isHuman());
		assertEquals("should be 0", 0, context
				.getHumanRestrictedResourcesRequestsCount());
		context.incrementHumanRestrictedRessoucesRequestsCount();
		assertEquals("should be 1", 1, context
				.getHumanRestrictedResourcesRequestsCount());
		long now = System.currentTimeMillis();
		context.setHuman();
		assertEquals("should be 0", 0, context
				.getHumanRestrictedResourcesRequestsCount());
		assertTrue("should be more than 0", context
				.getLastPassedCaptchaDateInMillis()
				- now >= 0);
		assertTrue("should be less than 0,1 seconde", context
				.getLastPassedCaptchaDateInMillis()
				- now < 100);

	}

}
