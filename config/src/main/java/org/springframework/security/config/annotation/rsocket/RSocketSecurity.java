/*
 * Copyright 2019-2024 the original author or authors.
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

package org.springframework.security.config.annotation.rsocket;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import reactor.core.publisher.Mono;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.rsocket.api.PayloadInterceptor;
import org.springframework.security.rsocket.authentication.AnonymousPayloadInterceptor;
import org.springframework.security.rsocket.authentication.AuthenticationPayloadExchangeConverter;
import org.springframework.security.rsocket.authentication.AuthenticationPayloadInterceptor;
import org.springframework.security.rsocket.authentication.BearerPayloadExchangeConverter;
import org.springframework.security.rsocket.authorization.AuthorizationPayloadInterceptor;
import org.springframework.security.rsocket.authorization.PayloadExchangeMatcherReactiveAuthorizationManager;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeAuthorizationContext;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatcher;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatcherEntry;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatchers;
import org.springframework.security.rsocket.util.matcher.RoutePayloadExchangeMatcher;

/**
 * Allows configuring RSocket based security.
 *
 * A minimal example can be found below:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableRSocketSecurity
 * public class SecurityConfig {
 *     &#064;Bean
 *     PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
 *         rsocket
 *             .authorizePayload((authorize) -&gt;
 *                 authorize
 *                     .anyRequest().authenticated()
 *             );
 *         return rsocket.build();
 *     }
 *
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *          UserDetails user = User.withDefaultPasswordEncoder()
 *               .username("user")
 *               .password("password")
 *               .roles("USER")
 *               .build();
 *          return new MapReactiveUserDetailsService(user);
 *     }
 * }
 * </pre>
 *
 * A more advanced configuration can be seen below:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableRSocketSecurity
 * public class SecurityConfig {
 *     &#064;Bean
 *     PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
 *         rsocket
 *             .authorizePayload((authorize) -&gt;
 *                 authorize
 *                     // must have ROLE_SETUP to make connection
 *                     .setup().hasRole("SETUP")
 *                      // must have ROLE_ADMIN for routes starting with "admin."
 *                     .route("admin.*").hasRole("ADMIN")
 *                     // any other request must be authenticated for
 *                     .anyRequest().authenticated()
 *             );
 *         return rsocket.build();
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @author Jesús Ascama Arias
 * @author Luis Felipe Vega
 * @author Manuel Tejeda
 * @author Ebert Toribio
 * @author Ngoc Nhan
 * @since 5.2
 */
public class RSocketSecurity {

	private List<PayloadInterceptor> payloadInterceptors = new ArrayList<>();

	private BasicAuthenticationSpec basicAuthSpec;

	private SimpleAuthenticationSpec simpleAuthSpec;

	private JwtSpec jwtSpec;

	private AuthorizePayloadsSpec authorizePayload;

	private ApplicationContext context;

	private ReactiveAuthenticationManager authenticationManager;

	/**
	 * Adds a {@link PayloadInterceptor} to be used. This is typically only used when
	 * using the DSL does not meet a users needs. In order to ensure the
	 * {@link PayloadInterceptor} is done in the proper order the
	 * {@link PayloadInterceptor} should either implement
	 * {@link org.springframework.core.Ordered} or be annotated with
	 * {@link org.springframework.core.annotation.Order}.
	 * @param interceptor
	 * @return the builder for additional customizations
	 * @see PayloadInterceptorOrder
	 */
	public RSocketSecurity addPayloadInterceptor(PayloadInterceptor interceptor) {
		this.payloadInterceptors.add(interceptor);
		return this;
	}

	public RSocketSecurity authenticationManager(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	/**
	 * Adds support for validating a username and password using <a href=
	 * "https://github.com/rsocket/rsocket/blob/5920ed374d008abb712cb1fd7c9d91778b2f4a68/Extensions/Security/Simple.md">Simple
	 * Authentication</a>
	 * @param simple a customizer
	 * @return RSocketSecurity for additional configuration
	 * @since 5.3
	 */
	public RSocketSecurity simpleAuthentication(Customizer<SimpleAuthenticationSpec> simple) {
		if (this.simpleAuthSpec == null) {
			this.simpleAuthSpec = new SimpleAuthenticationSpec();
		}
		simple.customize(this.simpleAuthSpec);
		return this;
	}

	/**
	 * Adds authentication with BasicAuthenticationPayloadExchangeConverter.
	 * @param basic
	 * @return this instance
	 * @deprecated Use {@link #simpleAuthentication(Customizer)}
	 */
	@Deprecated
	public RSocketSecurity basicAuthentication(Customizer<BasicAuthenticationSpec> basic) {
		if (this.basicAuthSpec == null) {
			this.basicAuthSpec = new BasicAuthenticationSpec();
		}
		basic.customize(this.basicAuthSpec);
		return this;
	}

	public RSocketSecurity jwt(Customizer<JwtSpec> jwt) {
		if (this.jwtSpec == null) {
			this.jwtSpec = new JwtSpec();
		}
		jwt.customize(this.jwtSpec);
		return this;
	}

	public RSocketSecurity authorizePayload(Customizer<AuthorizePayloadsSpec> authorize) {
		if (this.authorizePayload == null) {
			this.authorizePayload = new AuthorizePayloadsSpec();
		}
		authorize.customize(this.authorizePayload);
		return this;
	}

	public PayloadSocketAcceptorInterceptor build() {
		PayloadSocketAcceptorInterceptor interceptor = new PayloadSocketAcceptorInterceptor(payloadInterceptors());
		RSocketMessageHandler handler = getBean(RSocketMessageHandler.class);
		interceptor.setDefaultDataMimeType(handler.getDefaultDataMimeType());
		interceptor.setDefaultMetadataMimeType(handler.getDefaultMetadataMimeType());
		return interceptor;
	}

	private List<PayloadInterceptor> payloadInterceptors() {
		List<PayloadInterceptor> result = new ArrayList<>(this.payloadInterceptors);
		if (this.basicAuthSpec != null) {
			result.add(this.basicAuthSpec.build());
		}
		if (this.simpleAuthSpec != null) {
			result.add(this.simpleAuthSpec.build());
		}
		if (this.jwtSpec != null) {
			result.addAll(this.jwtSpec.build());
		}
		result.add(anonymous());
		if (this.authorizePayload != null) {
			result.add(this.authorizePayload.build());
		}
		AnnotationAwareOrderComparator.sort(result);
		return result;
	}

	private AnonymousPayloadInterceptor anonymous() {
		AnonymousPayloadInterceptor result = new AnonymousPayloadInterceptor("anonymousUser");
		result.setOrder(PayloadInterceptorOrder.ANONYMOUS.getOrder());
		return result;
	}

	private <T> T getBean(Class<T> beanClass) {
		if (this.context == null) {
			return null;
		}
		return this.context.getBean(beanClass);
	}

	private <T> T getBeanOrNull(Class<T> beanClass) {
		return getBeanOrNull(ResolvableType.forClass(beanClass));
	}

	@SuppressWarnings("unchecked")
	private <T> T getBeanOrNull(ResolvableType type) {
		if (this.context == null) {
			return null;
		}
		return (T) this.context.getBeanProvider(type).getIfUnique();
	}

	protected void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.context = applicationContext;
	}

	/**
	 * @since 5.3
	 */
	public final class SimpleAuthenticationSpec {

		private ReactiveAuthenticationManager authenticationManager;

		private SimpleAuthenticationSpec() {
		}

		public SimpleAuthenticationSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager == null) {
				return RSocketSecurity.this.authenticationManager;
			}
			return this.authenticationManager;
		}

		protected AuthenticationPayloadInterceptor build() {
			ReactiveAuthenticationManager manager = getAuthenticationManager();
			AuthenticationPayloadInterceptor result = new AuthenticationPayloadInterceptor(manager);
			result.setAuthenticationConverter(new AuthenticationPayloadExchangeConverter());
			result.setOrder(PayloadInterceptorOrder.AUTHENTICATION.getOrder());
			return result;
		}

	}

	public final class BasicAuthenticationSpec {

		private ReactiveAuthenticationManager authenticationManager;

		private BasicAuthenticationSpec() {
		}

		public BasicAuthenticationSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager == null) {
				return RSocketSecurity.this.authenticationManager;
			}
			return this.authenticationManager;
		}

		protected AuthenticationPayloadInterceptor build() {
			ReactiveAuthenticationManager manager = getAuthenticationManager();
			AuthenticationPayloadInterceptor result = new AuthenticationPayloadInterceptor(manager);
			result.setOrder(PayloadInterceptorOrder.AUTHENTICATION.getOrder());
			return result;
		}

	}

	public final class JwtSpec {

		private ReactiveAuthenticationManager authenticationManager;

		private JwtSpec() {
		}

		public JwtSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		private ReactiveAuthenticationManager getAuthenticationManager() {
			if (this.authenticationManager != null) {
				return this.authenticationManager;
			}
			ReactiveJwtDecoder jwtDecoder = getBeanOrNull(ReactiveJwtDecoder.class);
			if (jwtDecoder != null) {
				this.authenticationManager = new JwtReactiveAuthenticationManager(jwtDecoder);
				return this.authenticationManager;
			}
			return RSocketSecurity.this.authenticationManager;
		}

		protected List<AuthenticationPayloadInterceptor> build() {
			ReactiveAuthenticationManager manager = getAuthenticationManager();
			AuthenticationPayloadInterceptor legacy = new AuthenticationPayloadInterceptor(manager);
			legacy.setAuthenticationConverter(new BearerPayloadExchangeConverter());
			legacy.setOrder(PayloadInterceptorOrder.AUTHENTICATION.getOrder());
			AuthenticationPayloadInterceptor standard = new AuthenticationPayloadInterceptor(manager);
			standard.setAuthenticationConverter(new AuthenticationPayloadExchangeConverter());
			standard.setOrder(PayloadInterceptorOrder.AUTHENTICATION.getOrder());
			return Arrays.asList(standard, legacy);
		}

	}

	public class AuthorizePayloadsSpec {

		private PayloadExchangeMatcherReactiveAuthorizationManager.Builder authzBuilder = PayloadExchangeMatcherReactiveAuthorizationManager
			.builder();

		public Access setup() {
			return matcher(PayloadExchangeMatchers.setup());
		}

		/**
		 * Matches if
		 * {@link org.springframework.security.rsocket.api.PayloadExchangeType#isRequest()}
		 * is true, else not a match
		 * @return the Access to set up the authorization rule.
		 */
		public Access anyRequest() {
			return matcher(PayloadExchangeMatchers.anyRequest());
		}

		/**
		 * Always matches
		 * @return the Access to set up the authorization rule.
		 */
		public Access anyExchange() {
			return matcher(PayloadExchangeMatchers.anyExchange());
		}

		protected AuthorizationPayloadInterceptor build() {
			AuthorizationPayloadInterceptor result = new AuthorizationPayloadInterceptor(this.authzBuilder.build());
			result.setOrder(PayloadInterceptorOrder.AUTHORIZATION.getOrder());
			return result;
		}

		public Access route(String pattern) {
			RSocketMessageHandler handler = getBean(RSocketMessageHandler.class);
			PayloadExchangeMatcher matcher = new RoutePayloadExchangeMatcher(handler.getMetadataExtractor(),
					handler.getRouteMatcher(), pattern);
			return matcher(matcher);
		}

		public Access matcher(PayloadExchangeMatcher matcher) {
			return new Access(matcher);
		}

		public final class Access {

			private final PayloadExchangeMatcher matcher;

			private Access(PayloadExchangeMatcher matcher) {
				this.matcher = matcher;
			}

			public AuthorizePayloadsSpec authenticated() {
				return access(AuthenticatedReactiveAuthorizationManager.authenticated());
			}

			public AuthorizePayloadsSpec hasAuthority(String authority) {
				return access(AuthorityReactiveAuthorizationManager.hasAuthority(authority));
			}

			public AuthorizePayloadsSpec hasRole(String role) {
				return access(AuthorityReactiveAuthorizationManager.hasRole(role));
			}

			public AuthorizePayloadsSpec hasAnyRole(String... roles) {
				return access(AuthorityReactiveAuthorizationManager.hasAnyRole(roles));
			}

			public AuthorizePayloadsSpec permitAll() {
				return access((a, ctx) -> Mono.just(new AuthorizationDecision(true)));
			}

			public AuthorizePayloadsSpec hasAnyAuthority(String... authorities) {
				return access(AuthorityReactiveAuthorizationManager.hasAnyAuthority(authorities));
			}

			public AuthorizePayloadsSpec access(
					ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext> authorization) {
				AuthorizePayloadsSpec.this.authzBuilder
					.add(new PayloadExchangeMatcherEntry<>(this.matcher, authorization));
				return AuthorizePayloadsSpec.this;
			}

			public AuthorizePayloadsSpec denyAll() {
				return access((a, ctx) -> Mono.just(new AuthorizationDecision(false)));
			}

		}

	}

}
