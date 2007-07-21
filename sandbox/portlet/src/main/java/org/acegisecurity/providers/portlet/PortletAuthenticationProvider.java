/*
 * Copyright 2005-2007 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.providers.portlet;

import java.security.Principal;
import java.util.Map;

import javax.portlet.PortletRequest;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.portlet.cache.NullUserCache;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * <p>Processes a JSR-168 Portlet authentication request.  The request will typically
 * originate from {@link org.acegisecurity.ui.portlet.PortletProcessingInterceptor}.</p>
 *
 * <p>Be aware that this provider is trusting the portal and portlet container to handle
 * actual authentication. If a valid {@link PortletAuthenticationToken} is presented with
 * non-null principal and credentials, then the {@link #authenticate} method will succeed.</p>
 *
 * <p>If the <code>details</code> property of the requesting <code>Authentication</code>
 * object happens to be the <code>PortletRequest</code>, then this provider will place
 * the contents of the <code>USER_INFO</code> map from of the request attributes into
 * the <code>details</code> property of the authentication result.</p>
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletAuthenticationProvider
		implements AuthenticationProvider, InitializingBean {

	//~ Static fields/initializers =====================================================================================

	private static final Log logger = LogFactory.getLog(PortletAuthenticationProvider.class);

	//~ Instance fields ================================================================================================

	private PortletAuthoritiesPopulator portletAuthoritiesPopulator;
	private UserCache userCache = new NullUserCache();

	//~ Methods ========================================================================================================

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.portletAuthoritiesPopulator, "An authorities populator must be set");
		Assert.notNull(this.userCache, "A user cache must be set");
	}

	public boolean supports(Class authentication) {
		return PortletAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public Authentication authenticate(Authentication authentication)
		throws AuthenticationException {

		// make sure we support the authentication
		if (!supports(authentication.getClass())) {
			return null;
		}

		if (logger.isDebugEnabled())
			logger.debug("portlet authentication request: " + authentication);

		// make sure there is a valid principal in the authentication attempt
		Object principal = authentication.getPrincipal();
		if (principal == null) {
			throw new BadCredentialsException("No principal presented - user is not authenticated");
		}

		// make sure there are valid credentials in the authentication attempt
		Object credentials = authentication.getCredentials();
		if (credentials == null) {
			throw new BadCredentialsException("No credentials presented - user is not authenticated");
		}

		// determine the username string from the principal
		String username = getUsernameFromPrincipal(principal);
		if (username == null) {
			throw new BadCredentialsException("No username available - user is not authenticated");
		}

		// try to retrieve the user from the cache
		UserDetails user = this.userCache.getUserFromCache(username);

		// if the user is null then it wasn't in the cache so go get it
		if (user == null) {

			if (logger.isDebugEnabled())
				logger.debug("user not found in the cache");

			// get the user from the authorities populator
			user = this.portletAuthoritiesPopulator.getUserDetails(authentication);

			if (user == null) {
				throw new AuthenticationServiceException(
					"portletAuthoritiesPopulator returned null, which is an interface contract violation");
			}

			// store the result back in the cache
			this.userCache.putUserInCache(user);

		} else {

			if (logger.isDebugEnabled())
				logger.debug("got user from the cache");
		}

		// build the resulting successful authentication token
		PortletAuthenticationToken result = new PortletAuthenticationToken(
				user, authentication.getCredentials(), user.getAuthorities());
		result.setAuthenticated(true);

		// see if the detail property on the request is the PortletRequest
		if (authentication.getDetails() instanceof PortletRequest) {
			// if available, place the USER_INFO map into the details property of the result
			PortletRequest request = (PortletRequest)authentication.getDetails();
			Map userInfo = null;
			try {
				userInfo = (Map)request.getAttribute(PortletRequest.USER_INFO);
			} catch (Exception e) {
				logger.warn("unable to retrieve USER_INFO map from portlet request", e);
			}
			result.setDetails(userInfo);
		} else {
			// copy any other details information forward
			result.setDetails(authentication.getDetails());
		}

		if (logger.isDebugEnabled())
			logger.debug("portlet authentication succeeded: " + result);

		return result;
	}

	/**
	 * This method attempt to determine the username string from the principal object.
	 * If the principal object is a {@link UserDetails} object then it will use the
	 * {@link UserDetails#getUsername() method.  If the principal object is a
	 * {@link Principal} object then it will use the {@link Principal#getName()}
	 * method.  Otherwise it will simply call the <code>toString()<code> method
	 * on the principal object and return that.
	 * @param principal the principal object to inspect for a username
	 * @return the determined username, or null if no principal is passed
	 */
	public static final String getUsernameFromPrincipal(Object principal) {
		if (principal == null) {
			return null;
		}
		if (principal instanceof UserDetails) {
			return ((UserDetails)principal).getUsername();
		}
		if (principal instanceof Principal) {
			return ((Principal)principal).getName();
		}
		return principal.toString();
	}


	public PortletAuthoritiesPopulator getPortletAuthoritiesPopulator() {
		return this.portletAuthoritiesPopulator;
	}

	public void setPortletAuthoritiesPopulator(PortletAuthoritiesPopulator portletAuthoritiesPopulator) {
		this.portletAuthoritiesPopulator = portletAuthoritiesPopulator;
	}

	public UserCache getUserCache() {
		return userCache;
	}

	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}

}
