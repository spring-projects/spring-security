/*
 * Copyright 2002-2025 the original author or authors.
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

import io.micrometer.common.KeyValue;
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
import org.springframework.util.StringUtils;

/**
 * A {@link org.springframework.security.web.FilterChainProxy.FilterChainDecorator} that
 * wraps the chain in before and after observations
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationFilterChainDecorator implements FilterChainProxy.FilterChainDecorator {

	private static final Log logger = LogFactory.getLog(FilterChainProxy.class);

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

	static AroundFilterObservation observation(HttpServletRequest request) {
		return (AroundFilterObservation) request.getAttribute(ATTRIBUTE);
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

		static final Map<String, String> OBSERVATION_NAMES = new HashMap<>();

		static {
			OBSERVATION_NAMES.put("DisableEncodeUrlFilter", "session.urlencoding");
			OBSERVATION_NAMES.put("ForceEagerSessionCreationFilter", "session.eagercreate");
			OBSERVATION_NAMES.put("ChannelProcessingFilter", "access.channel");
			OBSERVATION_NAMES.put("WebAsyncManagerIntegrationFilter", "context.async");
			OBSERVATION_NAMES.put("SecurityContextHolderFilter", "context.holder");
			OBSERVATION_NAMES.put("SecurityContextPersistenceFilter", "context.management");
			OBSERVATION_NAMES.put("HeaderWriterFilter", "header");
			OBSERVATION_NAMES.put("CorsFilter", "cors");
			OBSERVATION_NAMES.put("CsrfFilter", "csrf");
			OBSERVATION_NAMES.put("LogoutFilter", "logout");
			OBSERVATION_NAMES.put("OAuth2AuthorizationRequestRedirectFilter", "oauth2.authnrequest");
			OBSERVATION_NAMES.put("Saml2WebSsoAuthenticationRequestFilter", "saml2.authnrequest");
			OBSERVATION_NAMES.put("X509AuthenticationFilter", "authentication.x509");
			OBSERVATION_NAMES.put("J2eePreAuthenticatedProcessingFilter", "preauthentication.j2ee");
			OBSERVATION_NAMES.put("RequestHeaderAuthenticationFilter", "preauthentication.header");
			OBSERVATION_NAMES.put("RequestAttributeAuthenticationFilter", "preauthentication.attribute");
			OBSERVATION_NAMES.put("WebSpherePreAuthenticatedProcessingFilter", "preauthentication.websphere");
			OBSERVATION_NAMES.put("CasAuthenticationFilter", "cas.authentication");
			OBSERVATION_NAMES.put("OAuth2LoginAuthenticationFilter", "oauth2.authentication");
			OBSERVATION_NAMES.put("Saml2WebSsoAuthenticationFilter", "saml2.authentication");
			OBSERVATION_NAMES.put("UsernamePasswordAuthenticationFilter", "authentication.form");
			OBSERVATION_NAMES.put("DefaultLoginPageGeneratingFilter", "page.login");
			OBSERVATION_NAMES.put("DefaultLogoutPageGeneratingFilter", "page.logout");
			OBSERVATION_NAMES.put("ConcurrentSessionFilter", "session.concurrent");
			OBSERVATION_NAMES.put("DigestAuthenticationFilter", "authentication.digest");
			OBSERVATION_NAMES.put("BearerTokenAuthenticationFilter", "authentication.bearer");
			OBSERVATION_NAMES.put("BasicAuthenticationFilter", "authentication.basic");
			OBSERVATION_NAMES.put("RequestCacheAwareFilter", "requestcache");
			OBSERVATION_NAMES.put("SecurityContextHolderAwareRequestFilter", "context.servlet");
			OBSERVATION_NAMES.put("JaasApiIntegrationFilter", "jaas");
			OBSERVATION_NAMES.put("RememberMeAuthenticationFilter", "authentication.rememberme");
			OBSERVATION_NAMES.put("AnonymousAuthenticationFilter", "authentication.anonymous");
			OBSERVATION_NAMES.put("OAuth2AuthorizationCodeGrantFilter", "oauth2.client.code");
			OBSERVATION_NAMES.put("SessionManagementFilter", "session.management");
			OBSERVATION_NAMES.put("ExceptionTranslationFilter", "access.exceptions");
			OBSERVATION_NAMES.put("FilterSecurityInterceptor", "access.request");
			OBSERVATION_NAMES.put("AuthorizationFilter", "authorization");
			OBSERVATION_NAMES.put("SwitchUserFilter", "authentication.switch");
		}

		private final ObservationRegistry registry;

		private final FilterChainObservationConvention convention = new FilterChainObservationConvention();

		private final Filter filter;

		private final String name;

		private final String eventName;

		private final int position;

		private final int size;

		ObservationFilter(ObservationRegistry registry, Filter filter, int position, int size) {
			this.registry = registry;
			this.filter = filter;
			this.name = filter.getClass().getSimpleName();
			this.position = position;
			this.size = size;
			this.eventName = eventName(this.name);
		}

		private String eventName(String className) {
			String eventName = OBSERVATION_NAMES.get(className);
			return (eventName != null) ? eventName : className;
		}

		String getName() {
			return this.name;
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
			parent.before().event(Observation.Event.of(this.eventName + ".before", "before " + this.name));
			this.filter.doFilter(request, response, chain);
			parent.start();
			if (parent.after().getContext() instanceof FilterChainObservationContext parentAfter) {
				parentAfter.setChainSize(this.size);
				parentAfter.setFilterName(this.name);
				parentAfter.setChainPosition(this.size - this.position + 1);
			}
			parent.after().event(Observation.Event.of(this.eventName + ".after", "after " + this.name));
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

		private static final String FILTER_SECTION_NAME = "spring.security.reached.filter.section";

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
			return KeyValues.of(CHAIN_SIZE_NAME, String.valueOf(context.getChainSize()))
				.and(CHAIN_POSITION_NAME, String.valueOf(context.getChainPosition()))
				.and(FILTER_SECTION_NAME, context.getFilterSection())
				.and(FILTER_NAME,
						(StringUtils.hasText(context.getFilterName())) ? context.getFilterName() : KeyValue.NONE_VALUE);
		}

		@Override
		public boolean supportsContext(Observation.Context context) {
			return context instanceof FilterChainObservationContext;
		}

	}

}
