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

package org.springframework.security.web;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.HttpStatusRequestRejectedHandler;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Delegates {@code Filter} requests to a list of Spring-managed filter beans. As of
 * version 2.0, you shouldn't need to explicitly configure a {@code FilterChainProxy} bean
 * in your application context unless you need very fine control over the filter chain
 * contents. Most cases should be adequately covered by the default
 * {@code <security:http />} namespace configuration options.
 * <p>
 * The {@code FilterChainProxy} is linked into the servlet container filter chain by
 * adding a standard Spring {@link DelegatingFilterProxy} declaration in the application
 * {@code web.xml} file.
 *
 * <h2>Configuration</h2>
 * <p>
 * As of version 3.1, {@code FilterChainProxy} is configured using a list of
 * {@link SecurityFilterChain} instances, each of which contains a {@link RequestMatcher}
 * and a list of filters which should be applied to matching requests. Most applications
 * will only contain a single filter chain, and if you are using the namespace, you don't
 * have to set the chains explicitly. If you require finer-grained control, you can make
 * use of the {@code <filter-chain>} namespace element. This defines a URI pattern and the
 * list of filters (as comma-separated bean names) which should be applied to requests
 * which match the pattern. An example configuration might look like this:
 *
 * <pre>
 *  &lt;bean id="myfilterChainProxy" class="org.springframework.security.web.FilterChainProxy"&gt;
 *      &lt;constructor-arg&gt;
 *          &lt;util:list&gt;
 *              &lt;security:filter-chain pattern="/do/not/filter*" filters="none"/&gt;
 *              &lt;security:filter-chain pattern="/**" filters="filter1,filter2,filter3"/&gt;
 *          &lt;/util:list&gt;
 *      &lt;/constructor-arg&gt;
 *  &lt;/bean&gt;
 * </pre>
 *
 * The names "filter1", "filter2", "filter3" should be the bean names of {@code Filter}
 * instances defined in the application context. The order of the names defines the order
 * in which the filters will be applied. As shown above, use of the value "none" for the
 * "filters" can be used to exclude a request pattern from the security filter chain
 * entirely. Please consult the security namespace schema file for a full list of
 * available configuration options.
 *
 * <h2>Request Handling</h2>
 * <p>
 * Each possible pattern that the {@code FilterChainProxy} should service must be entered.
 * The first match for a given request will be used to define all of the {@code Filter}s
 * that apply to that request. This means you must put most specific matches at the top of
 * the list, and ensure all {@code Filter}s that should apply for a given matcher are
 * entered against the respective entry. The {@code FilterChainProxy} will not iterate
 * through the remainder of the map entries to locate additional {@code Filter}s.
 * <p>
 * {@code FilterChainProxy} respects normal handling of {@code Filter}s that elect not to
 * call
 * {@link jakarta.servlet.Filter#doFilter(jakarta.servlet.ServletRequest, jakarta.servlet.ServletResponse, jakarta.servlet.FilterChain)}
 * , in that the remainder of the original or {@code FilterChainProxy}-declared filter
 * chain will not be called.
 *
 * <h3>Request Firewalling</h3>
 *
 * An {@link HttpFirewall} instance is used to validate incoming requests and create a
 * wrapped request which provides consistent path values for matching against. See
 * {@link StrictHttpFirewall}, for more information on the type of attacks which the
 * default implementation protects against. A custom implementation can be injected to
 * provide stricter control over the request contents or if an application needs to
 * support certain types of request which are rejected by default.
 * <p>
 * Note that this means that you must use the Spring Security filters in combination with
 * a {@code FilterChainProxy} if you want this protection. Don't define them explicitly in
 * your {@code web.xml} file.
 * <p>
 * {@code FilterChainProxy} will use the firewall instance to obtain both request and
 * response objects which will be fed down the filter chain, so it is also possible to use
 * this functionality to control the functionality of the response. When the request has
 * passed through the security filter chain, the {@code reset} method will be called. With
 * the default implementation this means that the original values of {@code servletPath}
 * and {@code pathInfo} will be returned thereafter, instead of the modified ones used for
 * security pattern matching.
 * <p>
 * Since this additional wrapping functionality is performed by the
 * {@code FilterChainProxy}, we don't recommend that you use multiple instances in the
 * same filter chain. It shouldn't be considered purely as a utility for wrapping filter
 * beans in a single {@code Filter} instance.
 *
 * <h2>Filter Lifecycle</h2>
 * <p>
 * Note the {@code Filter} lifecycle mismatch between the servlet container and IoC
 * container. As described in the {@link DelegatingFilterProxy} Javadocs, we recommend you
 * allow the IoC container to manage the lifecycle instead of the servlet container.
 * {@code FilterChainProxy} does not invoke the standard filter lifecycle methods on any
 * filter beans that you add to the application context.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 */
public class FilterChainProxy extends GenericFilterBean {

	private static final Log logger = LogFactory.getLog(FilterChainProxy.class);

	private static final String FILTER_APPLIED = FilterChainProxy.class.getName().concat(".APPLIED");

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private List<SecurityFilterChain> filterChains;

	private FilterChainValidator filterChainValidator = new NullFilterChainValidator();

	private HttpFirewall firewall = new StrictHttpFirewall();

	private RequestRejectedHandler requestRejectedHandler = new HttpStatusRequestRejectedHandler();

	private ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

	private FilterChainDecorator filterChainDecorator = new VirtualFilterChainDecorator();

	public FilterChainProxy() {
	}

	public FilterChainProxy(SecurityFilterChain chain) {
		this(Arrays.asList(chain));
	}

	public FilterChainProxy(List<SecurityFilterChain> filterChains) {
		this.filterChains = filterChains;
	}

	@Override
	public void afterPropertiesSet() {
		this.filterChainValidator.validate(this);
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
		if (!clearContext) {
			doFilterInternal(request, response, chain);
			return;
		}
		try {
			request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
			doFilterInternal(request, response, chain);
		}
		catch (Exception ex) {
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
			Throwable requestRejectedException = this.throwableAnalyzer
					.getFirstThrowableOfType(RequestRejectedException.class, causeChain);
			if (!(requestRejectedException instanceof RequestRejectedException)) {
				throw ex;
			}
			this.requestRejectedHandler.handle((HttpServletRequest) request, (HttpServletResponse) response,
					(RequestRejectedException) requestRejectedException);
		}
		finally {
			this.securityContextHolderStrategy.clearContext();
			request.removeAttribute(FILTER_APPLIED);
		}
	}

	private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest) request);
		HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse) response);
		List<Filter> filters = getFilters(firewallRequest);
		if (filters == null || filters.size() == 0) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.of(() -> "No security for " + requestLine(firewallRequest)));
			}
			firewallRequest.reset();
			this.filterChainDecorator.decorate(chain).doFilter(firewallRequest, firewallResponse);
			return;
		}
		if (logger.isDebugEnabled()) {
			logger.debug(LogMessage.of(() -> "Securing " + requestLine(firewallRequest)));
		}
		FilterChain reset = (req, res) -> {
			if (logger.isDebugEnabled()) {
				logger.debug(LogMessage.of(() -> "Secured " + requestLine(firewallRequest)));
			}
			// Deactivate path stripping as we exit the security filter chain
			firewallRequest.reset();
			chain.doFilter(req, res);
		};
		this.filterChainDecorator.decorate(reset, filters).doFilter(firewallRequest, firewallResponse);
	}

	/**
	 * Returns the first filter chain matching the supplied URL.
	 * @param request the request to match
	 * @return an ordered array of Filters defining the filter chain
	 */
	private List<Filter> getFilters(HttpServletRequest request) {
		int count = 0;
		for (SecurityFilterChain chain : this.filterChains) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, ++count,
						this.filterChains.size()));
			}
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}
		return null;
	}

	/**
	 * Convenience method, mainly for testing.
	 * @param url the URL
	 * @return matching filter list
	 */
	public List<Filter> getFilters(String url) {
		return getFilters(this.firewall.getFirewalledRequest(new FilterInvocation(url, "GET").getRequest()));
	}

	/**
	 * @return the list of {@code SecurityFilterChain}s which will be matched against and
	 * applied to incoming requests.
	 */
	public List<SecurityFilterChain> getFilterChains() {
		return Collections.unmodifiableList(this.filterChains);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Used (internally) to specify a validation strategy for the filters in each
	 * configured chain.
	 * @param filterChainValidator the validator instance which will be invoked on during
	 * initialization to check the {@code FilterChainProxy} instance.
	 */
	public void setFilterChainValidator(FilterChainValidator filterChainValidator) {
		this.filterChainValidator = filterChainValidator;
	}

	/**
	 * Used to decorate the original {@link FilterChain} for each request
	 *
	 * <p>
	 * By default, this decorates the filter chain with a {@link VirtualFilterChain} that
	 * iterates through security filters and then delegates to the original chain
	 * @param filterChainDecorator the strategy for constructing the filter chain
	 * @since 6.0
	 */
	public void setFilterChainDecorator(FilterChainDecorator filterChainDecorator) {
		Assert.notNull(filterChainDecorator, "filterChainDecorator cannot be null");
		this.filterChainDecorator = filterChainDecorator;
	}

	/**
	 * Sets the "firewall" implementation which will be used to validate and wrap (or
	 * potentially reject) the incoming requests. The default implementation should be
	 * satisfactory for most requirements.
	 * @param firewall
	 */
	public void setFirewall(HttpFirewall firewall) {
		this.firewall = firewall;
	}

	/**
	 * Sets the {@link RequestRejectedHandler} to be used for requests rejected by the
	 * firewall.
	 * @param requestRejectedHandler the {@link RequestRejectedHandler}
	 * @since 5.2
	 */
	public void setRequestRejectedHandler(RequestRejectedHandler requestRejectedHandler) {
		Assert.notNull(requestRejectedHandler, "requestRejectedHandler may not be null");
		this.requestRejectedHandler = requestRejectedHandler;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("FilterChainProxy[");
		sb.append("Filter Chains: ");
		sb.append(this.filterChains);
		sb.append("]");
		return sb.toString();
	}

	private static String requestLine(HttpServletRequest request) {
		return request.getMethod() + " " + UrlUtils.buildRequestUrl(request);
	}

	/**
	 * Internal {@code FilterChain} implementation that is used to pass a request through
	 * the additional internal list of filters which match the request.
	 */
	private static final class VirtualFilterChain implements FilterChain {

		private final FilterChain originalChain;

		private final List<Filter> additionalFilters;

		private final int size;

		private int currentPosition = 0;

		private VirtualFilterChain(FilterChain chain, List<Filter> additionalFilters) {
			this.originalChain = chain;
			this.additionalFilters = additionalFilters;
			this.size = additionalFilters.size();
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
			if (this.currentPosition == this.size) {
				this.originalChain.doFilter(request, response);
				return;
			}
			this.currentPosition++;
			Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
			if (logger.isTraceEnabled()) {
				String name = nextFilter.getClass().getSimpleName();
				logger.trace(LogMessage.format("Invoking %s (%d/%d)", name, this.currentPosition, this.size));
			}
			nextFilter.doFilter(request, response, this);
		}

	}

	public interface FilterChainValidator {

		void validate(FilterChainProxy filterChainProxy);

	}

	private static class NullFilterChainValidator implements FilterChainValidator {

		@Override
		public void validate(FilterChainProxy filterChainProxy) {
		}

	}

	/**
	 * A strategy for decorating the provided filter chain with one that accounts for the
	 * {@link SecurityFilterChain} for a given request.
	 *
	 * @author Josh Cummings
	 * @since 6.0
	 */
	public interface FilterChainDecorator {

		/**
		 * Provide a new {@link FilterChain} that accounts for needed security
		 * considerations when there are no security filters.
		 * @param original the original {@link FilterChain}
		 * @return a security-enabled {@link FilterChain}
		 */
		default FilterChain decorate(FilterChain original) {
			return decorate(original, Collections.emptyList());
		}

		/**
		 * Provide a new {@link FilterChain} that accounts for the provided filters as
		 * well as teh original filter chain.
		 * @param original the original {@link FilterChain}
		 * @param filters the security filters
		 * @return a security-enabled {@link FilterChain} that includes the provided
		 * filters
		 */
		FilterChain decorate(FilterChain original, List<Filter> filters);

	}

	/**
	 * A {@link FilterChainDecorator} that uses the {@link VirtualFilterChain}
	 *
	 * @author Josh Cummings
	 * @since 6.0
	 */
	public static final class VirtualFilterChainDecorator implements FilterChainDecorator {

		/**
		 * {@inheritDoc}
		 */
		@Override
		public FilterChain decorate(FilterChain original) {
			return original;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public FilterChain decorate(FilterChain original, List<Filter> filters) {
			return new VirtualFilterChain(original, filters);
		}

	}

}
