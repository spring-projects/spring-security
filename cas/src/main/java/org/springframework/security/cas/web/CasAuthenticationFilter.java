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

package org.springframework.security.cas.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Processes a CAS service ticket, obtains proxy granting tickets, and processes proxy
 * tickets.
 * <h2>Service Tickets</h2>
 * <p>
 * A service ticket consists of an opaque ticket string. It arrives at this filter by the
 * user's browser successfully authenticating using CAS, and then receiving a HTTP
 * redirect to a <code>service</code>. The opaque ticket string is presented in the
 * <code>ticket</code> request parameter.
 * <p>
 * This filter monitors the <code>service</code> URL so it can receive the service ticket
 * and process it. By default this filter processes the URL <tt>/login/cas</tt>. When
 * processing this URL, the value of {@link ServiceProperties#getService()} is used as the
 * <tt>service</tt> when validating the <code>ticket</code>. This means that it is
 * important that {@link ServiceProperties#getService()} specifies the same value as the
 * <tt>filterProcessesUrl</tt>.
 * <p>
 * Processing the service ticket involves creating a
 * <code>UsernamePasswordAuthenticationToken</code> which uses
 * {@link #CAS_STATEFUL_IDENTIFIER} for the <code>principal</code> and the opaque ticket
 * string as the <code>credentials</code>.
 * <h2>Obtaining Proxy Granting Tickets</h2>
 * <p>
 * If specified, the filter can also monitor the <code>proxyReceptorUrl</code>. The filter
 * will respond to requests matching this url so that the CAS Server can provide a PGT to
 * the filter. Note that in addition to the <code>proxyReceptorUrl</code> a non-null
 * <code>proxyGrantingTicketStorage</code> must be provided in order for the filter to
 * respond to proxy receptor requests. By configuring a shared
 * {@link ProxyGrantingTicketStorage} between the {@link TicketValidator} and the
 * CasAuthenticationFilter one can have the CasAuthenticationFilter handle the proxying
 * requirements for CAS.
 * <h2>Proxy Tickets</h2>
 * <p>
 * The filter can process tickets present on any url. This is useful when wanting to
 * process proxy tickets. In order for proxy tickets to get processed
 * {@link ServiceProperties#isAuthenticateAllArtifacts()} must return <code>true</code>.
 * Additionally, if the request is already authenticated, authentication will <b>not</b>
 * occur. Last, {@link AuthenticationDetailsSource#buildDetails(Object)} must return a
 * {@link ServiceAuthenticationDetails}. This can be accomplished using the
 * {@link ServiceAuthenticationDetailsSource}. In this case
 * {@link ServiceAuthenticationDetails#getServiceUrl()} will be used for the service url.
 * <p>
 * Processing the proxy ticket involves creating a
 * <code>UsernamePasswordAuthenticationToken</code> which uses
 * {@link #CAS_STATELESS_IDENTIFIER} for the <code>principal</code> and the opaque ticket
 * string as the <code>credentials</code>. When a proxy ticket is successfully
 * authenticated, the FilterChain continues and the
 * <code>authenticationSuccessHandler</code> is not used.
 * <h2>Notes about the <code>AuthenticationManager</code></h2>
 * <p>
 * The configured <code>AuthenticationManager</code> is expected to provide a provider
 * that can recognise <code>UsernamePasswordAuthenticationToken</code>s containing this
 * special <code>principal</code> name, and process them accordingly by validation with
 * the CAS server. Additionally, it should be capable of using the result of
 * {@link ServiceAuthenticationDetails#getServiceUrl()} as the service when validating the
 * ticket.
 * <h2>Example Configuration</h2>
 * <p>
 * An example configuration that supports service tickets, obtaining proxy granting
 * tickets, and proxy tickets is illustrated below:
 *
 * <pre>
 * &lt;b:bean id=&quot;serviceProperties&quot;
 *     class=&quot;org.springframework.security.cas.ServiceProperties&quot;
 *     p:service=&quot;https://service.example.com/cas-sample/login/cas&quot;
 *     p:authenticateAllArtifacts=&quot;true&quot;/&gt;
 * &lt;b:bean id=&quot;casEntryPoint&quot;
 *     class=&quot;org.springframework.security.cas.web.CasAuthenticationEntryPoint&quot;
 *     p:serviceProperties-ref=&quot;serviceProperties&quot; p:loginUrl=&quot;https://login.example.org/cas/login&quot; /&gt;
 * &lt;b:bean id=&quot;casFilter&quot;
 *     class=&quot;org.springframework.security.cas.web.CasAuthenticationFilter&quot;
 *     p:authenticationManager-ref=&quot;authManager&quot;
 *     p:serviceProperties-ref=&quot;serviceProperties&quot;
 *     p:proxyGrantingTicketStorage-ref=&quot;pgtStorage&quot;
 *     p:proxyReceptorUrl=&quot;/login/cas/proxyreceptor&quot;&gt;
 *     &lt;b:property name=&quot;authenticationDetailsSource&quot;&gt;
 *         &lt;b:bean class=&quot;org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource&quot;/&gt;
 *     &lt;/b:property&gt;
 *     &lt;b:property name=&quot;authenticationFailureHandler&quot;&gt;
 *         &lt;b:bean class=&quot;org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler&quot;
 *             p:defaultFailureUrl=&quot;/casfailed.jsp&quot;/&gt;
 *     &lt;/b:property&gt;
 * &lt;/b:bean&gt;
 * &lt;!--
 *     NOTE: In a real application you should not use an in memory implementation. You will also want
 *           to ensure to clean up expired tickets by calling ProxyGrantingTicketStorage.cleanup()
 *  --&gt;
 * &lt;b:bean id=&quot;pgtStorage&quot; class=&quot;org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl&quot;/&gt;
 * &lt;b:bean id=&quot;casAuthProvider&quot; class=&quot;org.springframework.security.cas.authentication.CasAuthenticationProvider&quot;
 *     p:serviceProperties-ref=&quot;serviceProperties&quot;
 *     p:key=&quot;casAuthProviderKey&quot;&gt;
 *     &lt;b:property name=&quot;authenticationUserDetailsService&quot;&gt;
 *         &lt;b:bean
 *             class=&quot;org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper&quot;&gt;
 *             &lt;b:constructor-arg ref=&quot;userService&quot; /&gt;
 *         &lt;/b:bean&gt;
 *     &lt;/b:property&gt;
 *     &lt;b:property name=&quot;ticketValidator&quot;&gt;
 *         &lt;b:bean
 *             class=&quot;org.jasig.cas.client.validation.Cas20ProxyTicketValidator&quot;
 *             p:acceptAnyProxy=&quot;true&quot;
 *             p:proxyCallbackUrl=&quot;https://service.example.com/cas-sample/login/cas/proxyreceptor&quot;
 *             p:proxyGrantingTicketStorage-ref=&quot;pgtStorage&quot;&gt;
 *             &lt;b:constructor-arg value=&quot;https://login.example.org/cas&quot; /&gt;
 *         &lt;/b:bean&gt;
 *     &lt;/b:property&gt;
 *     &lt;b:property name=&quot;statelessTicketCache&quot;&gt;
 *         &lt;b:bean class=&quot;org.springframework.security.cas.authentication.EhCacheBasedTicketCache&quot;&gt;
 *             &lt;b:property name=&quot;cache&quot;&gt;
 *                 &lt;b:bean class=&quot;net.sf.ehcache.Cache&quot;
 *                   init-method=&quot;initialise&quot;
 *                   destroy-method=&quot;dispose&quot;&gt;
 *                     &lt;b:constructor-arg value=&quot;casTickets&quot;/&gt;
 *                     &lt;b:constructor-arg value=&quot;50&quot;/&gt;
 *                     &lt;b:constructor-arg value=&quot;true&quot;/&gt;
 *                     &lt;b:constructor-arg value=&quot;false&quot;/&gt;
 *                     &lt;b:constructor-arg value=&quot;3600&quot;/&gt;
 *                     &lt;b:constructor-arg value=&quot;900&quot;/&gt;
 *                 &lt;/b:bean&gt;
 *             &lt;/b:property&gt;
 *         &lt;/b:bean&gt;
 *     &lt;/b:property&gt;
 * &lt;/b:bean&gt;
 * </pre>
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class CasAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	// ~ Static fields/initializers
	// =====================================================================================

	/**
	 * Used to identify a CAS request for a stateful user agent, such as a web browser.
	 */
	public static final String CAS_STATEFUL_IDENTIFIER = "_cas_stateful_";

	/**
	 * Used to identify a CAS request for a stateless user agent, such as a remoting
	 * protocol client (e.g. Hessian, Burlap, SOAP etc). Results in a more aggressive
	 * caching strategy being used, as the absence of a <code>HttpSession</code> will
	 * result in a new authentication attempt on every request.
	 */
	public static final String CAS_STATELESS_IDENTIFIER = "_cas_stateless_";

	/**
	 * The last portion of the receptor url, i.e. /proxy/receptor
	 */
	private RequestMatcher proxyReceptorMatcher;

	/**
	 * The backing storage to store ProxyGrantingTicket requests.
	 */
	private ProxyGrantingTicketStorage proxyGrantingTicketStorage;

	private String artifactParameter = ServiceProperties.DEFAULT_CAS_ARTIFACT_PARAMETER;

	private boolean authenticateAllArtifacts;

	private AuthenticationFailureHandler proxyFailureHandler = new SimpleUrlAuthenticationFailureHandler();

	// ~ Constructors
	// ===================================================================================================

	public CasAuthenticationFilter() {
		super("/login/cas");
		setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	protected final void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, Authentication authResult) throws IOException, ServletException {
		boolean continueFilterChain = proxyTicketRequest(serviceTicketRequest(request, response), request);
		if (!continueFilterChain) {
			super.successfulAuthentication(request, response, chain, authResult);
			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authResult);
		}

		SecurityContextHolder.getContext().setAuthentication(authResult);

		// Fire event
		if (this.eventPublisher != null) {
			eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
		}

		chain.doFilter(request, response);
	}

	@Override
	public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
			throws AuthenticationException, IOException {
		// if the request is a proxy request process it and return null to indicate the
		// request has been processed
		if (proxyReceptorRequest(request)) {
			logger.debug("Responding to proxy receptor request");
			CommonUtils.readAndRespondToProxyReceptorRequest(request, response, this.proxyGrantingTicketStorage);
			return null;
		}

		final boolean serviceTicketRequest = serviceTicketRequest(request, response);
		final String username = serviceTicketRequest ? CAS_STATEFUL_IDENTIFIER : CAS_STATELESS_IDENTIFIER;
		String password = obtainArtifact(request);

		if (password == null) {
			logger.debug("Failed to obtain an artifact (cas ticket)");
			password = "";
		}

		final UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
				password);

		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

		return this.getAuthenticationManager().authenticate(authRequest);
	}

	/**
	 * If present, gets the artifact (CAS ticket) from the {@link HttpServletRequest}.
	 * @param request
	 * @return if present the artifact from the {@link HttpServletRequest}, else null
	 */
	protected String obtainArtifact(HttpServletRequest request) {
		return request.getParameter(artifactParameter);
	}

	/**
	 * Overridden to provide proxying capabilities.
	 */
	protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
		final boolean serviceTicketRequest = serviceTicketRequest(request, response);
		final boolean result = serviceTicketRequest || proxyReceptorRequest(request)
				|| (proxyTicketRequest(serviceTicketRequest, request));
		if (logger.isDebugEnabled()) {
			logger.debug("requiresAuthentication = " + result);
		}
		return result;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} for proxy requests.
	 * @param proxyFailureHandler
	 */
	public final void setProxyAuthenticationFailureHandler(AuthenticationFailureHandler proxyFailureHandler) {
		Assert.notNull(proxyFailureHandler, "proxyFailureHandler cannot be null");
		this.proxyFailureHandler = proxyFailureHandler;
	}

	/**
	 * Wraps the {@link AuthenticationFailureHandler} to distinguish between handling
	 * proxy ticket authentication failures and service ticket failures.
	 */
	@Override
	public final void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
		super.setAuthenticationFailureHandler(new CasAuthenticationFailureHandler(failureHandler));
	}

	public final void setProxyReceptorUrl(final String proxyReceptorUrl) {
		this.proxyReceptorMatcher = new AntPathRequestMatcher("/**" + proxyReceptorUrl);
	}

	public final void setProxyGrantingTicketStorage(final ProxyGrantingTicketStorage proxyGrantingTicketStorage) {
		this.proxyGrantingTicketStorage = proxyGrantingTicketStorage;
	}

	public final void setServiceProperties(final ServiceProperties serviceProperties) {
		this.artifactParameter = serviceProperties.getArtifactParameter();
		this.authenticateAllArtifacts = serviceProperties.isAuthenticateAllArtifacts();
	}

	/**
	 * Indicates if the request is elgible to process a service ticket. This method exists
	 * for readability.
	 * @param request
	 * @param response
	 * @return
	 */
	private boolean serviceTicketRequest(final HttpServletRequest request, final HttpServletResponse response) {
		boolean result = super.requiresAuthentication(request, response);
		if (logger.isDebugEnabled()) {
			logger.debug("serviceTicketRequest = " + result);
		}
		return result;
	}

	/**
	 * Indicates if the request is elgible to process a proxy ticket.
	 * @param request
	 * @return
	 */
	private boolean proxyTicketRequest(final boolean serviceTicketRequest, final HttpServletRequest request) {
		if (serviceTicketRequest) {
			return false;
		}
		final boolean result = authenticateAllArtifacts && obtainArtifact(request) != null && !authenticated();
		if (logger.isDebugEnabled()) {
			logger.debug("proxyTicketRequest = " + result);
		}
		return result;
	}

	/**
	 * Determines if a user is already authenticated.
	 * @return
	 */
	private boolean authenticated() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authentication != null && authentication.isAuthenticated()
				&& !(authentication instanceof AnonymousAuthenticationToken);
	}

	/**
	 * Indicates if the request is elgible to be processed as the proxy receptor.
	 * @param request
	 * @return
	 */
	private boolean proxyReceptorRequest(final HttpServletRequest request) {
		final boolean result = proxyReceptorConfigured() && proxyReceptorMatcher.matches(request);
		if (logger.isDebugEnabled()) {
			logger.debug("proxyReceptorRequest = " + result);
		}
		return result;
	}

	/**
	 * Determines if the {@link CasAuthenticationFilter} is configured to handle the proxy
	 * receptor requests.
	 * @return
	 */
	private boolean proxyReceptorConfigured() {
		final boolean result = this.proxyGrantingTicketStorage != null && proxyReceptorMatcher != null;
		if (logger.isDebugEnabled()) {
			logger.debug("proxyReceptorConfigured = " + result);
		}
		return result;
	}

	/**
	 * A wrapper for the AuthenticationFailureHandler that will flex the
	 * {@link AuthenticationFailureHandler} that is used. The value
	 * {@link CasAuthenticationFilter#setProxyAuthenticationFailureHandler(AuthenticationFailureHandler)
	 * will be used for proxy requests that fail. The value
	 * {@link CasAuthenticationFilter#setAuthenticationFailureHandler(AuthenticationFailureHandler)}
	 * will be used for service tickets that fail.
	 *
	 * @author Rob Winch
	 */
	private class CasAuthenticationFailureHandler implements AuthenticationFailureHandler {

		private final AuthenticationFailureHandler serviceTicketFailureHandler;

		CasAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
			Assert.notNull(failureHandler, "failureHandler");
			this.serviceTicketFailureHandler = failureHandler;
		}

		public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException exception) throws IOException, ServletException {
			if (serviceTicketRequest(request, response)) {
				serviceTicketFailureHandler.onAuthenticationFailure(request, response, exception);
			}
			else {
				proxyFailureHandler.onAuthenticationFailure(request, response, exception);
			}
		}

	}

}
