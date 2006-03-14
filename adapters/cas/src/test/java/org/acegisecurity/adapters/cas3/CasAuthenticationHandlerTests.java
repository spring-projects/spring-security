package org.acegisecurity.adapters.cas3;

import org.acegisecurity.AuthenticationManager;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.springframework.test.AbstractDependencyInjectionSpringContextTests;

/**
 * Tests {@link CasAuthenticationHandler}
 * @author Scott Battaglia
 * @version $Id$
 *
 */
public class CasAuthenticationHandlerTests extends AbstractDependencyInjectionSpringContextTests {

	private AuthenticationManager authenticationManager;
	
	private CasAuthenticationHandler casAuthenticationHandler;
	
	public void setAuthenticationManager(final AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	protected String[] getConfigLocations() {
		return new String[] {"/org/acegisecurity/adapters/cas/applicationContext-valid.xml"};
	}

	protected void onSetUp() throws Exception {
		this.casAuthenticationHandler = new CasAuthenticationHandler();
		this.casAuthenticationHandler.setAuthenticationManager(authenticationManager);
		this.casAuthenticationHandler.afterPropertiesSet();
	}
	
	public void testAfterPropertiesSet() throws Exception {
		this.casAuthenticationHandler.setAuthenticationManager(null);
		try {
			this.casAuthenticationHandler.afterPropertiesSet();
			fail("IllegalArgumenException expected when no AuthenticationManager is set.");
		} catch (final IllegalArgumentException e) {
			// this is okay
		}
	}
	
	public void testValidUsernamePasswordCombination() {
		try {
			assertTrue(this.casAuthenticationHandler.authenticate(getCredentialsFor("scott", "wombat")));
		} catch (final AuthenticationException  e) {
			fail("AuthenticationException not expected.");
		}
	}
	
	public void testInvalidUsernamePasswordCombination() {
		try {
			assertFalse(this.casAuthenticationHandler.authenticate(getCredentialsFor("scott", "scott")));
		} catch (final AuthenticationException  e) {
			fail("AuthenticationException not expected.");
		}
	}
	
	public void testGracefullyHandlesInvalidInput() {

		try {
			assertFalse(this.casAuthenticationHandler.authenticate(getCredentialsFor("", "")));
			assertFalse(this.casAuthenticationHandler.authenticate(getCredentialsFor(null, null)));
		} catch (final AuthenticationException  e) {
			fail("AuthenticationException not expected.");
		}
	}
	
	private UsernamePasswordCredentials getCredentialsFor(final String username, final String password) {
		final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials();
		credentials.setUsername(username);
		credentials.setPassword(password);
		
		return credentials;
	}
}
