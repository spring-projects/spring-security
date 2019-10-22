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

package org.springframework.security.openid;

import org.openid4java.consumer.ConsumerException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;

/**
 * Filter which processes OpenID authentication requests.
 * <p>
 * The OpenID authentication involves two stages.
 *
 * <h2>Submission of OpenID identity</h2>
 *
 * The user's OpenID identity is submitted via a login form, just as it would be for a
 * normal form login. At this stage the filter will extract the identity from the
 * submitted request (by default, the parameter is called <tt>openid_identifier</tt>, as
 * recommended by the OpenID 2.0 Specification). It then passes the identity to the
 * configured <tt>OpenIDConsumer</tt>, which returns the URL to which the request should
 * be redirected for authentication. A "return_to" URL is also supplied, which matches the
 * URL processed by this filter, to allow the filter to handle the request once the user
 * has been successfully authenticated. The OpenID server will then authenticate the user
 * and redirect back to the application.
 *
 * <h2>Processing the Redirect from the OpenID Server</h2>
 *
 * Once the user has been authenticated externally, the redirected request will be passed
 * to the <tt>OpenIDConsumer</tt> again for validation. The returned
 * <tt>OpenIDAuthentication</tt> will be passed to the <tt>AuthenticationManager</tt>
 * where it should (normally) be processed by an <tt>OpenIDAuthenticationProvider</tt> in
 * order to load the authorities for the user.
 *
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 * to <a href="https://openid.net/connect/">OpenID Connect</a>.
 * @author Robin Bramley
 * @author Ray Krueger
 * @author Luke Taylor
 * @since 2.0
 * @see OpenIDAuthenticationProvider
 */
public class OpenIDAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	// ~ Static fields/initializers
	// =====================================================================================

	public static final String DEFAULT_CLAIMED_IDENTITY_FIELD = "openid_identifier";

	// ~ Instance fields
	// ================================================================================================

	private OpenIDConsumer consumer;
	private String claimedIdentityFieldName = DEFAULT_CLAIMED_IDENTITY_FIELD;
	private Map<String, String> realmMapping = Collections.emptyMap();
	private Set<String> returnToUrlParameters = Collections.emptySet();

	// ~ Constructors
	// ===================================================================================================

	public OpenIDAuthenticationFilter() {
		super("/login/openid");
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();

		if (consumer == null) {
			try {
				consumer = new OpenID4JavaConsumer();
			}
			catch (ConsumerException e) {
				throw new IllegalArgumentException("Failed to initialize OpenID", e);
			}
		}

		if (returnToUrlParameters.isEmpty()
				&& getRememberMeServices() instanceof AbstractRememberMeServices) {
			returnToUrlParameters = new HashSet<>();
			returnToUrlParameters
					.add(((AbstractRememberMeServices) getRememberMeServices())
							.getParameter());
		}
	}

	/**
	 * Authentication has two phases.
	 * <ol>
	 * <li>The initial submission of the claimed OpenID. A redirect to the URL returned
	 * from the consumer will be performed and null will be returned.</li>
	 * <li>The redirection from the OpenID server to the return_to URL, once it has
	 * authenticated the user</li>
	 * </ol>
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException, IOException {
		OpenIDAuthenticationToken token;

		String identity = request.getParameter("openid.identity");

		if (!StringUtils.hasText(identity)) {
			String claimedIdentity = obtainUsername(request);

			try {
				String returnToUrl = buildReturnToUrl(request);
				String realm = lookupRealm(returnToUrl);
				String openIdUrl = consumer.beginConsumption(request, claimedIdentity,
						returnToUrl, realm);
				if (logger.isDebugEnabled()) {
					logger.debug("return_to is '" + returnToUrl + "', realm is '" + realm
							+ "'");
					logger.debug("Redirecting to " + openIdUrl);
				}
				response.sendRedirect(openIdUrl);

				// Indicate to parent class that authentication is continuing.
				return null;
			}
			catch (OpenIDConsumerException e) {
				logger.debug("Failed to consume claimedIdentity: " + claimedIdentity, e);
				throw new AuthenticationServiceException(
						"Unable to process claimed identity '" + claimedIdentity + "'");
			}
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Supplied OpenID identity is " + identity);
		}

		try {
			token = consumer.endConsumption(request);
		}
		catch (OpenIDConsumerException oice) {
			throw new AuthenticationServiceException("Consumer error", oice);
		}

		token.setDetails(authenticationDetailsSource.buildDetails(request));

		// delegate to the authentication provider
		Authentication authentication = this.getAuthenticationManager().authenticate(
				token);

		return authentication;
	}

	protected String lookupRealm(String returnToUrl) {
		String mapping = realmMapping.get(returnToUrl);

		if (mapping == null) {
			try {
				URL url = new URL(returnToUrl);
				int port = url.getPort();

				StringBuilder realmBuffer = new StringBuilder(returnToUrl.length())
						.append(url.getProtocol()).append("://").append(url.getHost());
				if (port > 0) {
					realmBuffer.append(":").append(port);
				}
				realmBuffer.append("/");
				mapping = realmBuffer.toString();
			}
			catch (MalformedURLException e) {
				logger.warn("returnToUrl was not a valid URL: [" + returnToUrl + "]", e);
			}
		}

		return mapping;
	}

	/**
	 * Builds the <tt>return_to</tt> URL that will be sent to the OpenID service provider.
	 * By default returns the URL of the current request.
	 *
	 * @param request the current request which is being processed by this filter
	 * @return The <tt>return_to</tt> URL.
	 */
	protected String buildReturnToUrl(HttpServletRequest request) {
		StringBuffer sb = request.getRequestURL();

		Iterator<String> iterator = returnToUrlParameters.iterator();
		boolean isFirst = true;

		while (iterator.hasNext()) {
			String name = iterator.next();
			// Assume for simplicity that there is only one value
			String value = request.getParameter(name);

			if (value == null) {
				continue;
			}

			if (isFirst) {
				sb.append("?");
				isFirst = false;
			}
			sb.append(utf8UrlEncode(name)).append("=").append(utf8UrlEncode(value));

			if (iterator.hasNext()) {
				sb.append("&");
			}
		}
		return sb.toString();
	}

	/**
	 * Reads the <tt>claimedIdentityFieldName</tt> from the submitted request.
	 */
	protected String obtainUsername(HttpServletRequest req) {
		String claimedIdentity = req.getParameter(claimedIdentityFieldName);

		if (!StringUtils.hasText(claimedIdentity)) {
			logger.error("No claimed identity supplied in authentication request");
			return "";
		}

		return claimedIdentity.trim();
	}

	/**
	 * Maps the <tt>return_to url</tt> to a realm, for example:
	 *
	 * <pre>
	 * https://www.example.com/login/openid -&gt; https://www.example.com/realm
	 * </pre>
	 *
	 * If no mapping is provided then the returnToUrl will be parsed to extract the
	 * protocol, hostname and port followed by a trailing slash. This means that
	 * <tt>https://foo.example.com/login/openid</tt> will automatically become
	 * <tt>http://foo.example.com:80/</tt>
	 *
	 * @param realmMapping containing returnToUrl -&gt; realm mappings
	 */
	public void setRealmMapping(Map<String, String> realmMapping) {
		this.realmMapping = realmMapping;
	}

	/**
	 * The name of the request parameter containing the OpenID identity, as submitted from
	 * the initial login form.
	 *
	 * @param claimedIdentityFieldName defaults to "openid_identifier"
	 */
	public void setClaimedIdentityFieldName(String claimedIdentityFieldName) {
		this.claimedIdentityFieldName = claimedIdentityFieldName;
	}

	public void setConsumer(OpenIDConsumer consumer) {
		this.consumer = consumer;
	}

	/**
	 * Specifies any extra parameters submitted along with the identity field which should
	 * be appended to the {@code return_to} URL which is assembled by
	 * {@link #buildReturnToUrl}.
	 *
	 * @param returnToUrlParameters the set of parameter names. If not set, it will
	 * default to the parameter name used by the {@code RememberMeServices} obtained from
	 * the parent class (if one is set).
	 */
	public void setReturnToUrlParameters(Set<String> returnToUrlParameters) {
		Assert.notNull(returnToUrlParameters, "returnToUrlParameters cannot be null");
		this.returnToUrlParameters = returnToUrlParameters;
	}

	/**
	 * Performs URL encoding with UTF-8
	 *
	 * @param value the value to URL encode
	 * @return the encoded value
	 */
	private String utf8UrlEncode(String value) {
		try {
			return URLEncoder.encode(value, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			Error err = new AssertionError(
					"The Java platform guarantees UTF-8 support, but it seemingly is not present.");
			err.initCause(e);
			throw err;
		}
	}
}
