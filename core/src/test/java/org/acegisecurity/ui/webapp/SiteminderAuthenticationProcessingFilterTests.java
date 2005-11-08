package net.sf.acegisecurity.ui.webapp;

import junit.framework.TestCase;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.MockAuthenticationManager;
import net.sf.acegisecurity.ui.WebAuthenticationDetails;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Tests SiteminderAuthenticationProcessingFilter.
 * 
 * @author Ben Alex
 * @author <a href="mailto:scott@mccrory.us">Scott McCrory</a>
 * @version CVS $Id: SiteminderAuthenticationProcessingFilterTests.java,v 1.1
 *          2005/09/25 22:48:33 smccrory Exp $
 */
public class SiteminderAuthenticationProcessingFilterTests extends TestCase {

	/**
	 * Basic constructor.
	 */
	public SiteminderAuthenticationProcessingFilterTests() {
		super();
	}

	/**
	 * Argument constructor.
	 * 
	 * @param arg0
	 */
	public SiteminderAuthenticationProcessingFilterTests(String arg0) {
		super(arg0);
	}

	/**
	 * @see junit.framework.TestCase#setUp()
	 */
	public final void setUp() throws Exception {
		super.setUp();
	}

	/**
	 * Runs the tests as a command-line program.
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		junit.textui.TestRunner
				.run(SiteminderAuthenticationProcessingFilterTests.class);
	}

	/**
	 * Tests the class' getters.
	 */
	public void testAccessors() {

		SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
		
		filter.setAlwaysUseDefaultTargetUrl(true);
		assertTrue(filter.isAlwaysUseDefaultTargetUrl());
		
		filter.setAuthenticationFailureUrl("foo");
		assertEquals("foo", filter.getAuthenticationFailureUrl());
		
		filter.setContinueChainBeforeSuccessfulAuthentication(true);
		assertTrue(filter.isContinueChainBeforeSuccessfulAuthentication());
		
		filter.setDefaultTargetUrl("bar");
		assertEquals("bar", filter.getDefaultTargetUrl());
		
		filter.setFilterProcessesUrl("foobar");
		assertEquals("foobar", filter.getFilterProcessesUrl());
		
		filter.setFormPasswordParameterKey("passwordParamKey");
		assertEquals("passwordParamKey", filter.getFormPasswordParameterKey());
		
		filter.setFormUsernameParameterKey("usernameParamKey");
		assertEquals("usernameParamKey", filter.getFormUsernameParameterKey());
		
		filter.setSiteminderPasswordHeaderKey("passwordHeaderKey");
		assertEquals("passwordHeaderKey", filter.getSiteminderPasswordHeaderKey());
		
		filter.setSiteminderUsernameHeaderKey("usernameHeaderKey");
		assertEquals("usernameHeaderKey", filter.getSiteminderUsernameHeaderKey());

	}

	/**
	 * Tests normal form processing.
	 * 
	 * @throws Exception
	 */
	public void testFormNormalOperation() throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request
				.addParameter(
						SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
						"marissa");
		request
				.addParameter(
						SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
						"koala");

		MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

		SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authMgr);
		filter.init(null);

		Authentication result = filter.attemptAuthentication(request);
		assertTrue(result != null);
		assertEquals("127.0.0.1", ((WebAuthenticationDetails) result
				.getDetails()).getRemoteAddress());

	}

	/**
	 * Tests form null password handling.
	 * 
	 * @throws Exception
	 */
	public void testFormNullPasswordHandledGracefully() throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request
				.addParameter(
						SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
						"marissa");

		MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

		SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authMgr);
		filter.init(null);

		Authentication result = filter.attemptAuthentication(request);
		assertTrue(result != null);

	}

	/**
	 * Tests form null username handling.
	 * 
	 * @throws Exception
	 */
	public void testFormNullUsernameHandledGracefully() throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request
				.addParameter(
						SiteminderAuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
						"koala");

		MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

		SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authMgr);
		filter.init(null);

		Authentication result = filter.attemptAuthentication(request);
		assertTrue(result != null);

	}

	/**
	 * Tests normal Siteminder header processing.
	 * 
	 * @throws Exception
	 */
	public void testSiteminderNormalOperation() throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("SM_USER", "E099544");

		MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

		SiteminderAuthenticationProcessingFilter filter = new SiteminderAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authMgr);
		filter.setSiteminderUsernameHeaderKey("SM_USER");
		filter.setSiteminderPasswordHeaderKey("SM_USER");
		filter.init(null);

		Authentication result = filter.attemptAuthentication(request);
		assertTrue(result != null);
		assertEquals("127.0.0.1", ((WebAuthenticationDetails) result
				.getDetails()).getRemoteAddress());

	}

}
