/*
 * Copyright 2019 the original author or authors.
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

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.rsocket.interceptor.PayloadInterceptor;
import org.springframework.security.rsocket.interceptor.PayloadSocketAcceptorInterceptor;
import org.springframework.security.rsocket.interceptor.authentication.AnonymousPayloadInterceptor;
import org.springframework.security.rsocket.interceptor.authentication.AuthenticationPayloadInterceptor;
import org.springframework.security.rsocket.interceptor.authentication.BearerPayloadExchangeConverter;
import org.springframework.security.rsocket.interceptor.authorization.AuthorizationPayloadInterceptor;
import org.springframework.security.rsocket.interceptor.authorization.PayloadExchangeMatcherReactiveAuthorizationManager;
import org.springframework.security.rsocket.util.PayloadExchangeAuthorizationContext;
import org.springframework.security.rsocket.util.PayloadExchangeMatcher;
import org.springframework.security.rsocket.util.PayloadExchangeMatcherEntry;
import org.springframework.security.rsocket.util.PayloadExchangeMatchers;
import org.springframework.security.rsocket.util.RoutePayloadExchangeMatcher;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

/**
 * Allows configuring RSocket based security.
 *
 * A minimal example can be found below:
 *
 * <pre class="code">
 * &#064;EnableRSocketSecurity
 * public class SecurityConfig {
 *     // @formatter:off
 *     &#064;Bean
 *     PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
 *         rsocket
 *             .authorizePayload(authorize ->
 *                 authorize
 *                     .anyRequest().authenticated()
 *             );
 *         return rsocket.build();
 *     }
 *     // @formatter:on
 *
 *     // @formatter:off
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *          UserDetails user = User.withDefaultPasswordEncoder()
 *               .username("user")
 *               .password("password")
 *               .roles("USER")
 *               .build();
 *          return new MapReactiveUserDetailsService(user);
 *     }
 *     // @formatter:on
 * }
 * </pre>
 *
 * A more advanced configuration can be seen below:
 *
 * <pre class="code">
 * &#064;EnableRSocketSecurity
 * public class SecurityConfig {
 *     // @formatter:off
 *     &#064;Bean
 *     PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
 *         rsocket
 *             .authorizePayload(authorize ->
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
 *     // @formatter:on
 * }
 * </pre>
 * @author Rob Winch
 * @since 5.2
 */
public class RSocketSecurity {

	private BasicAuthenticationSpec basicAuthSpec;

	private JwtSpec jwtSpec;

	private AuthorizePayloadsSpec authorizePayload;

	private ApplicationContext context;

	private ReactiveAuthenticationManager authenticationManager;

	public RSocketSecurity authenticationManager(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	public RSocketSecurity basicAuthentication(Customizer<BasicAuthenticationSpec> basic) {
		if (this.basicAuthSpec == null) {
			this.basicAuthSpec = new BasicAuthenticationSpec();
		}
		basic.customize(this.basicAuthSpec);
		return this;
	}

	public class BasicAuthenticationSpec {
		private ReactiveAuthenticationManager authenticationManager;

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
			return new AuthenticationPayloadInterceptor(manager);
		}

		private BasicAuthenticationSpec() {}
	}

	public RSocketSecurity jwt(Customizer<JwtSpec> jwt) {
		if (this.jwtSpec == null) {
			this.jwtSpec = new JwtSpec();
		}
		jwt.customize(this.jwtSpec);
		return this;
	}

	public class JwtSpec {
		private ReactiveAuthenticationManager authenticationManager;

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

		protected AuthenticationPayloadInterceptor build() {
			ReactiveAuthenticationManager manager = getAuthenticationManager();
			AuthenticationPayloadInterceptor result = new AuthenticationPayloadInterceptor(manager);
			result.setAuthenticationConverter(new BearerPayloadExchangeConverter());
			return result;
		}

		private JwtSpec() {}
	}

	public RSocketSecurity authorizePayload(Customizer<AuthorizePayloadsSpec> authorize) {
		if (this.authorizePayload == null) {
			this.authorizePayload = new AuthorizePayloadsSpec();
		}
		authorize.customize(this.authorizePayload);
		return this;
	}

	public PayloadSocketAcceptorInterceptor build() {
		PayloadSocketAcceptorInterceptor interceptor = new PayloadSocketAcceptorInterceptor(
				payloadInterceptors());
		RSocketMessageHandler handler = getBean(RSocketMessageHandler.class);
		interceptor.setDefaultDataMimeType(handler.getDefaultDataMimeType());
		interceptor.setDefaultMetadataMimeType(handler.getDefaultMetadataMimeType());
		return interceptor;
	}

	private List<PayloadInterceptor> payloadInterceptors() {
		List<PayloadInterceptor> payloadInterceptors = new ArrayList<>();

		if (this.basicAuthSpec != null) {
			payloadInterceptors.add(this.basicAuthSpec.build());
		}
		if (this.jwtSpec != null) {
			payloadInterceptors.add(this.jwtSpec.build());
		}
		payloadInterceptors.add(new AnonymousPayloadInterceptor("anonymousUser"));

		if (this.authorizePayload != null) {
			payloadInterceptors.add(this.authorizePayload.build());
		}
		return payloadInterceptors;
	}

	public class AuthorizePayloadsSpec {

		private PayloadExchangeMatcherReactiveAuthorizationManager.Builder authzBuilder =
				PayloadExchangeMatcherReactiveAuthorizationManager.builder();

		public Access setup() {
			return matcher(PayloadExchangeMatchers.setup());
		}

		public Access anyRequest() {
			return matcher(PayloadExchangeMatchers.anyExchange());
		}

		protected AuthorizationPayloadInterceptor build() {
			return new AuthorizationPayloadInterceptor(this.authzBuilder.build());
		}

		public Access route(String pattern) {
			RSocketMessageHandler handler = getBean(RSocketMessageHandler.class);
			PayloadExchangeMatcher matcher = new RoutePayloadExchangeMatcher(
					handler.getMetadataExtractor(),
					handler.getRouteMatcher(),
					pattern);
			return matcher(matcher);
		}

		public Access matcher(PayloadExchangeMatcher matcher) {
			return new Access(matcher);
		}

		public class Access {

			private final PayloadExchangeMatcher matcher;

			private Access(PayloadExchangeMatcher matcher) {
				this.matcher = matcher;
			}

			public AuthorizePayloadsSpec authenticated() {
				return access(AuthenticatedReactiveAuthorizationManager.authenticated());
			}

			public AuthorizePayloadsSpec hasRole(String role) {
				return access(AuthorityReactiveAuthorizationManager.hasRole(role));
			}

			public AuthorizePayloadsSpec permitAll() {
				return access((a, ctx) -> Mono
						.just(new AuthorizationDecision(true)));
			}

			public AuthorizePayloadsSpec access(
					ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext> authorization) {
				AuthorizePayloadsSpec.this.authzBuilder.add(new PayloadExchangeMatcherEntry<>(this.matcher, authorization));
				return AuthorizePayloadsSpec.this;
			}
		}
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

	private <T> T getBeanOrNull(ResolvableType type) {
		if (this.context == null) {
			return null;
		}
		String[] names =  this.context.getBeanNamesForType(type);
		if (names.length == 1) {
			return (T) this.context.getBean(names[0]);
		}
		return null;
	}

	protected void setApplicationContext(ApplicationContext applicationContext)
			throws BeansException {
		this.context = applicationContext;
	}
}
