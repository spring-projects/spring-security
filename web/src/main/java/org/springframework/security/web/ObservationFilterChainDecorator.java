/*
 * Copyright 2002-2023 the original author or authors.
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.DisableEncodeUrlFilter;
import org.springframework.security.web.session.ForceEagerSessionCreationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.CorsFilter;

/**
 * A {@link org.springframework.security.web.FilterChainProxy.FilterChainDecorator} that
 * wraps the chain in before and after observations
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationFilterChainDecorator implements FilterChainProxy.FilterChainDecorator {

	private static final Log logger = LogFactory.getLog(FilterChainProxy.class);

	private static final int OPENTELEMETRY_MAX_NAME_LENGTH = 63;

	private static final int MAX_OBSERVATION_NAME_LENGTH = OPENTELEMETRY_MAX_NAME_LENGTH - ".before".length();

	private static final Map<String, String> OBSERVATION_NAMES = new HashMap<>();

	private static final String ATTRIBUTE = ObservationFilterChainDecorator.class + ".observation";

	static final String UNSECURED_OBSERVATION_NAME = "spring.security.http.unsecured.requests";

	static final String SECURED_OBSERVATION_NAME = "spring.security.http.secured.requests";

	private final ObservationRegistry registry;

	public ObservationFilterChainDecorator(ObservationRegistry registry) {
		this.registry = registry;
	}

	@Override
	public FilterChain decorate(FilterChain original) {
		return wrapUnsecured(original);
	}

	@Override
	public FilterChain decorate(FilterChain original, List<Filter> filters) {
		return new VirtualFilterChain(wrapSecured(original), wrap(filters));
	}

	private FilterChain wrapSecured(FilterChain original) {
		return (req, res) -> {
			AroundFilterObservation parent = observation((HttpServletRequest) req);
			Observation observation = Observation.createNotStarted(SECURED_OBSERVATION_NAME, this.registry)
					.contextualName("secured request");
			parent.wrap(FilterObservation.create(observation).wrap(original)).doFilter(req, res);
		};
	}

	private FilterChain wrapUnsecured(FilterChain original) {
		return (req, res) -> {
			Observation observation = Observation.createNotStarted(UNSECURED_OBSERVATION_NAME, this.registry)
					.contextualName("unsecured request");
			FilterObservation.create(observation).wrap(original).doFilter(req, res);
		};
	}

	private List<ObservationFilter> wrap(List<Filter> filters) {
		int size = filters.size();
		List<ObservationFilter> observableFilters = new ArrayList<>();
		int position = 1;
		for (Filter filter : filters) {
			observableFilters.add(new ObservationFilter(this.registry, filter, position, size));
			position++;
		}
		return observableFilters;
	}

	static {
		registerName(DisableEncodeUrlFilter.class, "session.encode-url.disable");
		registerName(ForceEagerSessionCreationFilter.class, "session.create");
		registerName(ChannelProcessingFilter.class, "web.request.delivery.ensure");
		registerName(WebAsyncManagerIntegrationFilter.class, "web-async-manager.join.security-context");
		registerName(SecurityContextHolderFilter.class, "security-context.hold");
		registerName(SecurityContextPersistenceFilter.class, "security-context.persist");
		registerName(HeaderWriterFilter.class, "web.response.header.set");
		registerName(CorsFilter.class, "cors.process");
		registerName(CsrfFilter.class, "csrf.protect");
		registerName(LogoutFilter.class, "principal.logout");
		registerName("org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter",
				"web.request.oauth2.redirect");
		registerName(
				"org.springframework.security.saml2.provider.service.web." + "Saml2WebSsoAuthenticationRequestFilter",
				"web.request.saml2.redirect");
		registerName(X509AuthenticationFilter.class, "web.request.x509.auth");
		registerName(AbstractPreAuthenticatedProcessingFilter.class, "web.request.pre-auth.base.process");
		registerName("org.springframework.security.cas.web.CasAuthenticationFilter", "web.request.sas.auth");
		registerName("org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter",
				"web.response.oauth2.process");
		registerName("org.springframework.security.saml2.provider.service.web.authentication"
				+ ".Saml2WebSsoAuthenticationFilter", "web.request.saml2.auth");
		registerName(UsernamePasswordAuthenticationFilter.class, "web.request.username-password.auth");
		registerName(DefaultLoginPageGeneratingFilter.class, "web.login-page.default.generate");
		registerName(DefaultLogoutPageGeneratingFilter.class, "web.logout-page.default.generate");
		registerName(ConcurrentSessionFilter.class, "session.refresh");
		registerName(DigestAuthenticationFilter.class, "web.request.digest.auth");
		registerName("org.springframework.security.oauth2.server.resource.web.authentication."
				+ "BearerTokenAuthenticationFilter", "web.request.bearer.auth");
		registerName(BasicAuthenticationFilter.class, "web.request.basic.auth");
		registerName(RequestCacheAwareFilter.class, "web.request.cache.extract");
		registerName(SecurityContextHolderAwareRequestFilter.class, "web.request.security.wrap");
		registerName(JaasApiIntegrationFilter.class, "web.request.jass.auth");
		registerName(RememberMeAuthenticationFilter.class, "web.request.remember-me.auth");
		registerName(AnonymousAuthenticationFilter.class, "web.request.anonymous.auth");
		registerName("org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter",
				"web.response.oauth2.code-grant.process");
		registerName(SessionManagementFilter.class, "session.manage");
		registerName(ExceptionTranslationFilter.class, "exception.translate");
		registerName(FilterSecurityInterceptor.class, "web.response.security.intercept");
		registerName(AuthorizationFilter.class, "web.access.auth.restrict");
		registerName(SwitchUserFilter.class, "session.switch");
	}

	public static void registerName(Class clazz, String name) {
		String keyName = clazz.getName();
		checkAlreadyRegistered(keyName);
		OBSERVATION_NAMES.put(keyName, limitLength(name));
	}

	public static void registerName(String className, String name) {
		checkAlreadyRegistered(className);
		OBSERVATION_NAMES.put(className, name);
	}

	static AroundFilterObservation observation(HttpServletRequest request) {
		return (AroundFilterObservation) request.getAttribute(ATTRIBUTE);
	}

	private static String getObservationName(String className) {
		if (OBSERVATION_NAMES.containsKey(className)) {
			return OBSERVATION_NAMES.get(className);
		}
		throw new IllegalArgumentException("Class not registered for observation: " + className);
	}

	private static String limitLength(String s) {
		Assert.isTrue(s.length() <= MAX_OBSERVATION_NAME_LENGTH,
				"The name must be less than MAX_OBSERVATION_NAME_LENGTH=" + MAX_OBSERVATION_NAME_LENGTH);
		return s;
	}

	private static void checkAlreadyRegistered(String keyName) {
		Assert.isTrue(!OBSERVATION_NAMES.containsKey(keyName), "Observation name is registered already: " + keyName);
	}

	private static final class VirtualFilterChain implements FilterChain {

		private final FilterChain originalChain;

		private final List<ObservationFilter> additionalFilters;

		private final int size;

		private int currentPosition = 0;

		private VirtualFilterChain(FilterChain chain, List<ObservationFilter> additionalFilters) {
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
			ObservationFilter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
			if (logger.isTraceEnabled()) {
				String name = nextFilter.getName();
				logger.trace(LogMessage.format("Invoking %s (%d/%d)", name, this.currentPosition, this.size));
			}
			nextFilter.doFilter(request, response, this);
		}

	}

	static final class ObservationFilter implements Filter {

		private final ObservationRegistry registry;

		private final FilterChainObservationConvention convention = new FilterChainObservationConvention();

		private final Filter filter;

		private final String name;

		private final String observationName;

		private final int position;

		private final int size;

		ObservationFilter(ObservationRegistry registry, Filter filter, int position, int size) {
			this.registry = registry;
			this.filter = filter;
			this.name = filter.getClass().getSimpleName();
			this.position = position;
			this.size = size;
			String tempObservationName;
			try {
				tempObservationName = ObservationFilterChainDecorator.getObservationName(filter.getClass().getName());
			}
			catch (IllegalArgumentException ex) {
				tempObservationName = compressName(this.name);
				logger.warn(
						"Class " + filter.getClass().getName()
								+ " is not registered for observation and will have name " + tempObservationName
								+ ". Please consider of registering this class with "
								+ ObservationFilterChainDecorator.class.getSimpleName() + ".registerName(class, name).",
						ex);
			}
			this.observationName = tempObservationName;
		}

		String getName() {
			return this.name;
		}

		String getObservationName() {
			return this.observationName;
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
				throws IOException, ServletException {
			if (this.position == 1) {
				AroundFilterObservation parent = parent((HttpServletRequest) request);
				parent.wrap(this::wrapFilter).doFilter(request, response, chain);
			}
			else {
				wrapFilter(request, response, chain);
			}
		}

		private void wrapFilter(ServletRequest request, ServletResponse response, FilterChain chain)
				throws IOException, ServletException {
			AroundFilterObservation parent = observation((HttpServletRequest) request);
			if (parent.before().getContext() instanceof FilterChainObservationContext parentBefore) {
				parentBefore.setChainSize(this.size);
				parentBefore.setFilterName(this.name);
				parentBefore.setChainPosition(this.position);
			}
			parent.before().event(Observation.Event.of(this.observationName + ".before",
					"before " + this.name));
			this.filter.doFilter(request, response, chain);
			parent.start();
			if (parent.after().getContext() instanceof FilterChainObservationContext parentAfter) {
				parentAfter.setChainSize(this.size);
				parentAfter.setFilterName(this.name);
				parentAfter.setChainPosition(this.size - this.position + 1);
			}
			parent.after().event(Observation.Event.of(this.observationName + ".after",
					"after " + this.name));
		}

		private AroundFilterObservation parent(HttpServletRequest request) {
			FilterChainObservationContext beforeContext = FilterChainObservationContext.before();
			FilterChainObservationContext afterContext = FilterChainObservationContext.after();
			Observation before = Observation.createNotStarted(this.convention, () -> beforeContext, this.registry);
			Observation after = Observation.createNotStarted(this.convention, () -> afterContext, this.registry);
			AroundFilterObservation parent = AroundFilterObservation.create(before, after);
			request.setAttribute(ATTRIBUTE, parent);
			return parent;
		}

		private String compressName(String className) {
			if (className.length() >= MAX_OBSERVATION_NAME_LENGTH) {
				return maximalCompressClassName(className, MAX_OBSERVATION_NAME_LENGTH);
			}
			return className;
		}

		private String maximalCompressClassName(String className, int maxLength) {
			String[] names = className.split("(?=\\p{Lu})");
			for (int j = 0; j < names.length; j++) {
				final int maxPortionLength = maxLength / names.length;
				if (names[j].length() > maxPortionLength) {
					names[j] = names[j].substring(0, maxPortionLength);
				}
			}
			return StringUtils.arrayToDelimitedString(names, "");
		}

	}

	interface AroundFilterObservation extends FilterObservation {

		AroundFilterObservation NOOP = new AroundFilterObservation() {
		};

		static AroundFilterObservation create(Observation before, Observation after) {
			if (before.isNoop() || after.isNoop()) {
				return NOOP;
			}
			return new SimpleAroundFilterObservation(before, after);
		}

		default Observation before() {
			return Observation.NOOP;
		}

		default Observation after() {
			return Observation.NOOP;
		}

		class SimpleAroundFilterObservation implements AroundFilterObservation {

			private final ObservationReference before;

			private final ObservationReference after;

			private final AtomicReference<ObservationReference> reference = new AtomicReference<>(
					ObservationReference.NOOP);

			SimpleAroundFilterObservation(Observation before, Observation after) {
				this.before = new ObservationReference(before);
				this.after = new ObservationReference(after);
			}

			@Override
			public void start() {
				if (this.reference.compareAndSet(ObservationReference.NOOP, this.before)) {
					this.before.start();
					return;
				}
				if (this.reference.compareAndSet(this.before, this.after)) {
					this.before.stop();
					this.after.start();
				}
			}

			@Override
			public void error(Throwable ex) {
				this.reference.get().error(ex);
			}

			@Override
			public void stop() {
				this.reference.get().stop();
			}

			@Override
			public Filter wrap(Filter filter) {
				return (request, response, chain) -> {
					start();
					try {
						filter.doFilter(request, response, chain);
					}
					catch (Throwable ex) {
						error(ex);
						throw ex;
					}
					finally {
						stop();
					}
				};
			}

			@Override
			public FilterChain wrap(FilterChain chain) {
				return (request, response) -> {
					stop();
					try {
						chain.doFilter(request, response);
					}
					finally {
						start();
					}
				};
			}

			@Override
			public Observation before() {
				return this.before.observation;
			}

			@Override
			public Observation after() {
				return this.after.observation;
			}

			private static final class ObservationReference {

				private static final ObservationReference NOOP = new ObservationReference(Observation.NOOP);

				private final AtomicInteger state = new AtomicInteger(0);

				private final Observation observation;

				private volatile Observation.Scope scope;

				private ObservationReference(Observation observation) {
					this.observation = observation;
					this.scope = Observation.Scope.NOOP;
				}

				private void start() {
					if (this.state.compareAndSet(0, 1)) {
						this.observation.start();
						this.scope = this.observation.openScope();
					}
				}

				private void error(Throwable error) {
					if (this.state.get() == 1) {
						this.scope.close();
						this.scope.getCurrentObservation().error(error);
					}
				}

				private void stop() {
					if (this.state.compareAndSet(1, 2)) {
						this.scope.close();
						this.scope.getCurrentObservation().stop();
					}
				}

			}

		}

	}

	interface FilterObservation {

		FilterObservation NOOP = new FilterObservation() {
		};

		static FilterObservation create(Observation observation) {
			if (observation.isNoop()) {
				return NOOP;
			}
			return new SimpleFilterObservation(observation);
		}

		default void start() {
		}

		default void error(Throwable ex) {
		}

		default void stop() {
		}

		default Filter wrap(Filter filter) {
			return filter;
		}

		default FilterChain wrap(FilterChain chain) {
			return chain;
		}

		class SimpleFilterObservation implements FilterObservation {

			private final Observation observation;

			SimpleFilterObservation(Observation observation) {
				this.observation = observation;
			}

			@Override
			public void start() {
				this.observation.start();
			}

			@Override
			public void error(Throwable ex) {
				this.observation.error(ex);
			}

			@Override
			public void stop() {
				this.observation.stop();
			}

			@Override
			public Filter wrap(Filter filter) {
				if (this.observation.isNoop()) {
					return filter;
				}
				return (request, response, chain) -> {
					this.observation.start();
					try (Observation.Scope scope = this.observation.openScope()) {
						filter.doFilter(request, response, chain);
					}
					catch (Throwable ex) {
						this.observation.error(ex);
						throw ex;
					}
					finally {
						this.observation.stop();
					}
				};
			}

			@Override
			public FilterChain wrap(FilterChain chain) {
				if (this.observation.isNoop()) {
					return chain;
				}
				return (request, response) -> {
					this.observation.start();
					try (Observation.Scope scope = this.observation.openScope()) {
						chain.doFilter(request, response);
					}
					catch (Throwable ex) {
						this.observation.error(ex);
						throw ex;
					}
					finally {
						this.observation.stop();
					}
				};
			}

		}

	}

	static final class FilterChainObservationContext extends Observation.Context {

		private final String filterSection;

		private String filterName;

		private int chainPosition;

		private int chainSize;

		private FilterChainObservationContext(String filterSection) {
			this.filterSection = filterSection;
			setContextualName("security filterchain " + filterSection);
		}

		static FilterChainObservationContext before() {
			return new FilterChainObservationContext("before");
		}

		static FilterChainObservationContext after() {
			return new FilterChainObservationContext("after");
		}

		String getFilterSection() {
			return this.filterSection;
		}

		String getFilterName() {
			return this.filterName;
		}

		void setFilterName(String filterName) {
			this.filterName = filterName;
		}

		int getChainPosition() {
			return this.chainPosition;
		}

		void setChainPosition(int chainPosition) {
			this.chainPosition = chainPosition;
		}

		int getChainSize() {
			return this.chainSize;
		}

		void setChainSize(int chainSize) {
			this.chainSize = chainSize;
		}

	}

	static final class FilterChainObservationConvention
			implements ObservationConvention<FilterChainObservationContext> {

		static final String CHAIN_OBSERVATION_NAME = "spring.security.filterchains";

		private static final String CHAIN_POSITION_NAME = "spring.security.filterchain.position";

		private static final String CHAIN_SIZE_NAME = "spring.security.filterchain.size";

		private static final String FILTER_SECTION_NAME = "security.security.reached.filter.section";

		private static final String FILTER_NAME = "spring.security.reached.filter.name";

		@Override
		public String getName() {
			return CHAIN_OBSERVATION_NAME;
		}

		@Override
		public String getContextualName(FilterChainObservationContext context) {
			return "security filterchain " + context.getFilterSection();
		}

		@Override
		public KeyValues getLowCardinalityKeyValues(FilterChainObservationContext context) {
			KeyValues kv = KeyValues.of(CHAIN_SIZE_NAME, String.valueOf(context.getChainSize()))
					.and(CHAIN_POSITION_NAME, String.valueOf(context.getChainPosition()))
					.and(FILTER_SECTION_NAME, context.getFilterSection());
			if (context.getFilterName() != null) {
				kv = kv.and(FILTER_NAME, context.getFilterName());
			}
			return kv;
		}

		@Override
		public boolean supportsContext(Observation.Context context) {
			return context instanceof FilterChainObservationContext;
		}

	}

}
