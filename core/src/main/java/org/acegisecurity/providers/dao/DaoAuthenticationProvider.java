/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.providers.dao;

import java.util.Map;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.encoding.PasswordEncoder;
import org.acegisecurity.providers.encoding.PlaintextPasswordEncoder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.springframework.context.ApplicationContext;
import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that retrieves user details
 * from an {@link UserDetailsService}.
 * 
 * @author Ben Alex
 * @version $Id: DaoAuthenticationProvider.java 1857 2007-05-24 00:47:12Z
 * benalex $
 */
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

	// ~ Instance fields
	// ================================================================================================

	private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();

	private SaltSource saltSource;

	private UserDetailsService userDetailsService;

	private boolean includeDetailsObject = true;

	// ~ Methods
	// ========================================================================================================

	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		Object salt = null;

		if (this.saltSource != null) {
			salt = this.saltSource.getSalt(userDetails);
		}

		if (authentication.getCredentials() == null) {
			throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"),
					includeDetailsObject ? userDetails : null);
		}

		String presentedPassword = authentication.getCredentials() == null ? "" : authentication.getCredentials()
				.toString();

		if (!passwordEncoder.isPasswordValid(userDetails.getPassword(), presentedPassword, salt)) {
			throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"),
					includeDetailsObject ? userDetails : null);
		}
	}

	protected void doAfterPropertiesSet() throws Exception {
		Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
	}

	/**
	 * Introspects the <code>Applicationcontext</code> for the single instance
	 * of {@link AccessDeniedHandler}. If found invoke
	 * setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) method by
	 * providing the found instance of accessDeniedHandler as a method
	 * parameter. If more than one instance of <code>AccessDeniedHandler</code>
	 * is found, the method throws <code>IllegalStateException</code>.
	 * 
	 * @param applicationContext to locate the instance
	 */
	private void autoDetectAnyUserDetailsServiceAndUseIt(ApplicationContext applicationContext) {
		if (applicationContext != null) {
			Map map = applicationContext.getBeansOfType(UserDetailsService.class);

			if (map.size() > 1) {
				throw new IllegalArgumentException(
						"More than one UserDetailsService beans detected please refer to the one using "
								+ " [ principalRepositoryBeanRef  ] " + "attribute");
			}
			else if (map.size() == 1) {
				setUserDetailsService((UserDetailsService) map.values().iterator().next());
			}
		}
	}

	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	public SaltSource getSaltSource() {
		return saltSource;
	}

	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		UserDetails loadedUser;

		try {
			loadedUser = this.getUserDetailsService().loadUserByUsername(username);
		}
		catch (DataAccessException repositoryProblem) {
			throw new AuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
		}

		if (loadedUser == null) {
			throw new AuthenticationServiceException(
					"UserDetailsService returned null, which is an interface contract violation");
		}
		return loadedUser;
	}

	/**
	 * Sets the PasswordEncoder instance to be used to encode and validate
	 * passwords. If not set, {@link PlaintextPasswordEncoder} will be used by
	 * default.
	 * 
	 * @param passwordEncoder The passwordEncoder to use
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * The source of salts to use when decoding passwords. <code>null</code>
	 * is a valid value, meaning the <code>DaoAuthenticationProvider</code>
	 * will present <code>null</code> to the relevant
	 * <code>PasswordEncoder</code>.
	 * 
	 * @param saltSource to use when attempting to decode passwords via the
	 * <code>PasswordEncoder</code>
	 */
	public void setSaltSource(SaltSource saltSource) {
		this.saltSource = saltSource;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public boolean isIncludeDetailsObject() {
		return includeDetailsObject;
	}

	public void setIncludeDetailsObject(boolean includeDetailsObject) {
		this.includeDetailsObject = includeDetailsObject;
	}

}
