/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.cas.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apereo.cas.client.validation.Assertion;
import org.apereo.cas.client.validation.TicketValidationException;
import org.apereo.cas.client.validation.TicketValidator;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that integrates with JA-SIG Central
 * Authentication Service (CAS).
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating
 * {@link CasServiceTicketAuthenticationToken} requests which contain a
 * <code>principal</code> name equal to either
 * {@link CasServiceTicketAuthenticationToken#CAS_STATEFUL_IDENTIFIER} or
 * {@link CasServiceTicketAuthenticationToken#CAS_STATELESS_IDENTIFIER}. It can also
 * validate a previously created {@link CasAuthenticationToken}.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 * @author Kim Youngwoong
 */
public class CasAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {

	private static final Log logger = LogFactory.getLog(CasAuthenticationProvider.class);

	private AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService;

	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private StatelessTicketCache statelessTicketCache = new NullStatelessTicketCache();

	private String key;

	private TicketValidator ticketValidator;

	private ServiceProperties serviceProperties;

	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.authenticationUserDetailsService, "An authenticationUserDetailsService must be set");
		Assert.notNull(this.ticketValidator, "A ticketValidator must be set");
		Assert.notNull(this.statelessTicketCache, "A statelessTicketCache must be set");
		Assert.hasText(this.key,
				"A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated");
		Assert.notNull(this.messages, "A message source must be set");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		// If an existing CasAuthenticationToken, just check we created it
		if (authentication instanceof CasAuthenticationToken) {
			if (this.key.hashCode() != ((CasAuthenticationToken) authentication).getKeyHash()) {
				throw new BadCredentialsException(this.messages.getMessage("CasAuthenticationProvider.incorrectKey",
						"The presented CasAuthenticationToken does not contain the expected key"));
			}
			return authentication;
		}

		// Ensure credentials are presented
		if ((authentication.getCredentials() == null) || "".equals(authentication.getCredentials())) {
			throw new BadCredentialsException(this.messages.getMessage("CasAuthenticationProvider.noServiceTicket",
					"Failed to provide a CAS service ticket to validate"));
		}

		boolean stateless = (authentication instanceof CasServiceTicketAuthenticationToken token
				&& token.isStateless());
		CasAuthenticationToken result = null;

		if (stateless) {
			// Try to obtain from cache
			result = this.statelessTicketCache.getByTicketId(authentication.getCredentials().toString());
		}
		if (result == null) {
			result = this.authenticateNow(authentication);
			result.setDetails(authentication.getDetails());
		}
		if (stateless) {
			// Add to cache
			this.statelessTicketCache.putTicketInCache(result);
		}
		return result;
	}

	private CasAuthenticationToken authenticateNow(final Authentication authentication) throws AuthenticationException {
		try {
			Assertion assertion = this.ticketValidator.validate(authentication.getCredentials().toString(),
					getServiceUrl(authentication));
			UserDetails userDetails = loadUserByAssertion(assertion);
			this.userDetailsChecker.check(userDetails);
			return new CasAuthenticationToken(this.key, userDetails, authentication.getCredentials(),
					this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities()), userDetails, assertion);
		}
		catch (TicketValidationException ex) {
			throw new BadCredentialsException(ex.getMessage(), ex);
		}
	}

	/**
	 * Gets the serviceUrl. If the {@link Authentication#getDetails()} is an instance of
	 * {@link ServiceAuthenticationDetails}, then
	 * {@link ServiceAuthenticationDetails#getServiceUrl()} is used. Otherwise, the
	 * {@link ServiceProperties#getService()} is used.
	 * @param authentication
	 * @return
	 */
	private String getServiceUrl(Authentication authentication) {
		String serviceUrl;
		if (authentication.getDetails() instanceof ServiceAuthenticationDetails) {
			return ((ServiceAuthenticationDetails) authentication.getDetails()).getServiceUrl();
		}
		Assert.state(this.serviceProperties != null,
				"serviceProperties cannot be null unless Authentication.getDetails() implements ServiceAuthenticationDetails.");
		Assert.state(this.serviceProperties.getService() != null,
				"serviceProperties.getService() cannot be null unless Authentication.getDetails() implements ServiceAuthenticationDetails.");
		serviceUrl = this.serviceProperties.getService();
		logger.debug(LogMessage.format("serviceUrl = %s", serviceUrl));
		return serviceUrl;
	}

	/**
	 * Template method for retrieving the UserDetails based on the assertion. Default is
	 * to call configured userDetailsService and pass the username. Deployers can override
	 * this method and retrieve the user based on any criteria they desire.
	 * @param assertion The CAS Assertion.
	 * @return the UserDetails.
	 */
	protected UserDetails loadUserByAssertion(final Assertion assertion) {
		final CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(assertion, "");
		return this.authenticationUserDetailsService.loadUserDetails(token);
	}

	@SuppressWarnings("unchecked")
	/**
	 * Sets the UserDetailsService to use. This is a convenience method to invoke
	 */
	public void setUserDetailsService(final UserDetailsService userDetailsService) {
		this.authenticationUserDetailsService = new UserDetailsByNameServiceWrapper(userDetailsService);
	}

	public void setAuthenticationUserDetailsService(
			final AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService) {
		this.authenticationUserDetailsService = authenticationUserDetailsService;
	}

	/**
	 * Sets the UserDetailsChecker to be used for checking the status of retrieved user
	 * details. This allows customization of the UserDetailsChecker implementation.
	 * @param userDetailsChecker the UserDetailsChecker to be set
	 * @since 6.4
	 */
	public void setUserDetailsChecker(final UserDetailsChecker userDetailsChecker) {
		Assert.notNull(userDetailsChecker, "userDetailsChecker cannot be null");
		this.userDetailsChecker = userDetailsChecker;
	}

	public void setServiceProperties(final ServiceProperties serviceProperties) {
		this.serviceProperties = serviceProperties;
	}

	protected String getKey() {
		return this.key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public StatelessTicketCache getStatelessTicketCache() {
		return this.statelessTicketCache;
	}

	protected TicketValidator getTicketValidator() {
		return this.ticketValidator;
	}

	@Override
	public void setMessageSource(final MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setStatelessTicketCache(final StatelessTicketCache statelessTicketCache) {
		this.statelessTicketCache = statelessTicketCache;
	}

	public void setTicketValidator(final TicketValidator ticketValidator) {
		this.ticketValidator = ticketValidator;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	@Override
	public boolean supports(final Class<?> authentication) {
		return (CasServiceTicketAuthenticationToken.class.isAssignableFrom(authentication))
				|| (CasAuthenticationToken.class.isAssignableFrom(authentication))
				|| (CasAssertionAuthenticationToken.class.isAssignableFrom(authentication));
	}

}
