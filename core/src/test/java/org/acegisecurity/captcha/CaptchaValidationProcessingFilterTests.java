package net.sf.acegisecurity.captcha;

import junit.framework.TestCase;
import net.sf.acegisecurity.context.SecurityContextHolder;
import net.sf.acegisecurity.util.MockFilterChain;

import org.springframework.mock.web.MockHttpServletRequest;

public class CaptchaValidationProcessingFilterTests extends TestCase {

	/*
	 */
	public void testAfterPropertiesSet() throws Exception {
		CaptchaValidationProcessingFilter filter = new CaptchaValidationProcessingFilter();

		try {
			filter.afterPropertiesSet();
			fail("should have thrown an invalid argument exception");
		} catch (Exception e) {
			assertTrue("should be an InvalidArgumentException",
					IllegalArgumentException.class.isAssignableFrom(e
							.getClass()));
		}
		filter.setCaptchaService(new MockCaptchaServiceProxy());
		filter.afterPropertiesSet();

	}

	/*
	 * Test method for
	 * 'net.sf.acegisecurity.captcha.CaptchaValidationProcessingFilter.doFilter(ServletRequest,
	 * ServletResponse, FilterChain)'
	 */
	public void testDoFilterWithoutRequestParameter() throws Exception {
		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		SecurityContextHolder.setContext(context);
		MockHttpServletRequest request = new MockHttpServletRequest();
		CaptchaValidationProcessingFilter filter = new CaptchaValidationProcessingFilter();
		MockCaptchaServiceProxy service = new MockCaptchaServiceProxy();
		MockFilterChain chain = new MockFilterChain(true);
		filter.setCaptchaService(service);
		filter.doFilter(request, null, chain);
		assertFalse("proxy should not have been called", service.hasBeenCalled);
		assertFalse("context should not have been updated", context.isHuman());
		// test with valid
		service.valid = true;
		filter.doFilter(request, null, chain);
		assertFalse("proxy should not have been called", service.hasBeenCalled);
		assertFalse("context should not have been updated", context.isHuman());

	}

	/*
	 * Test method for
	 * 'net.sf.acegisecurity.captcha.CaptchaValidationProcessingFilter.doFilter(ServletRequest,
	 * ServletResponse, FilterChain)'
	 */
	public void testDoFilterWithRequestParameter() throws Exception {
		CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
		SecurityContextHolder.setContext(context);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request
				.addParameter(
						CaptchaValidationProcessingFilter.CAPTCHA_VALIDATION_SECURITY_PARAMETER_KEY,
						"");

		CaptchaValidationProcessingFilter filter = new CaptchaValidationProcessingFilter();
		MockCaptchaServiceProxy service = new MockCaptchaServiceProxy();
		MockFilterChain chain = new MockFilterChain(true);
		filter.setCaptchaService(service);
		filter.doFilter(request, null, chain);
		assertTrue("should have been called", service.hasBeenCalled);
		assertFalse("context should not have been updated", context.isHuman());
		// test with valid
		service.valid = true;
		filter.doFilter(request, null, chain);
		assertTrue("should have been called", service.hasBeenCalled);
		assertTrue("context should have been updated", context.isHuman());

	}

}
