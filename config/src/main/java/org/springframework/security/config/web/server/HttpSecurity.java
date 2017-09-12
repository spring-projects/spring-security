/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config.web.server;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.security.web.server.HttpBasicAuthenticationConverter;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.www.HttpBasicAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.context.AuthenticationReactorContextFilter;
import org.springframework.security.web.server.context.SecurityContextRepositoryWebFilter;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.context.ServerWebExchangeAttributeSecurityContextRepository;
import org.springframework.security.web.server.header.CacheControlHttpHeadersWriter;
import org.springframework.security.web.server.header.CompositeHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.HttpHeaderWriterWebFilter;
import org.springframework.security.web.server.header.HttpHeadersWriter;
import org.springframework.security.web.server.header.StrictTransportSecurityHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class HttpSecurity {
	private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

	private AuthorizeExchangeBuilder authorizeExchangeBuilder;

	private HeaderBuilder headers = new HeaderBuilder();
	private HttpBasicBuilder httpBasic;
	private ReactiveAuthenticationManager authenticationManager;

	private SecurityContextRepository securityContextRepository;

	/**
	 * The ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *
	 * @param matcher the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *                Default is all requests.
	 */
	public HttpSecurity securityMatcher(ServerWebExchangeMatcher matcher) {
		Assert.notNull(matcher, "matcher cannot be null");
		this.securityMatcher = matcher;
		return this;
	}

	/**
	 * Gets the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 * @return the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 */
	private ServerWebExchangeMatcher getSecurityMatcher() {
		return this.securityMatcher;
	}

	public HttpSecurity securityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
		return this;
	}

	public HttpBasicBuilder httpBasic() {
		if(this.httpBasic == null) {
			this.httpBasic = new HttpBasicBuilder();
		}
		return this.httpBasic;
	}

	public HeaderBuilder headers() {
		return this.headers;
	}

	public AuthorizeExchangeBuilder authorizeExchange() {
		if(this.authorizeExchangeBuilder == null) {
			this.authorizeExchangeBuilder = new AuthorizeExchangeBuilder();
		}
		return this.authorizeExchangeBuilder;
	}

	public HttpSecurity authenticationManager(ReactiveAuthenticationManager manager) {
		this.authenticationManager = manager;
		return this;
	}

	public SecurityWebFilterChain build() {
		List<WebFilter> filters = new ArrayList<>();
		if(this.headers != null) {
			filters.add(this.headers.build());
		}
		SecurityContextRepositoryWebFilter securityContextRepositoryWebFilter = securityContextRepositoryWebFilter();
		if(securityContextRepositoryWebFilter != null) {
			filters.add(securityContextRepositoryWebFilter);
		}
		if(this.httpBasic != null) {
			this.httpBasic.authenticationManager(this.authenticationManager);
			if(this.securityContextRepository != null) {
				this.httpBasic.securityContextRepository(this.securityContextRepository);
			}
			filters.add(this.httpBasic.build());
		}
		filters.add(new AuthenticationReactorContextFilter());
		if(this.authorizeExchangeBuilder != null) {
			filters.add(new ExceptionTranslationWebFilter());
			filters.add(this.authorizeExchangeBuilder.build());
		}
		return new MatcherSecurityWebFilterChain(getSecurityMatcher(), filters);
	}

	public static HttpSecurity http() {
		return new HttpSecurity();
	}

	private SecurityContextRepositoryWebFilter securityContextRepositoryWebFilter() {
		return this.securityContextRepository == null ? null :
			new SecurityContextRepositoryWebFilter(this.securityContextRepository);
	}

	private HttpSecurity() {}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class AuthorizeExchangeBuilder extends AbstractServerWebExchangeMatcherRegistry<AuthorizeExchangeBuilder.Access> {
		private DelegatingReactiveAuthorizationManager.Builder managerBldr = DelegatingReactiveAuthorizationManager.builder();
		private ServerWebExchangeMatcher matcher;
		private boolean anyExchangeRegistered;

		public HttpSecurity and() {
			return HttpSecurity.this;
		}

		@Override
		public Access anyExchange() {
			Access result = super.anyExchange();
			this.anyExchangeRegistered = true;
			return result;
		}

		@Override
		protected Access registerMatcher(ServerWebExchangeMatcher matcher) {
			if(this.anyExchangeRegistered) {
				throw new IllegalStateException("Cannot register " + matcher + " which would be unreachable because anyExchange() has already been registered.");
			}
			if(this.matcher != null) {
				throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
			}
			this.matcher = matcher;
			return new Access();
		}

		protected WebFilter build() {
			if(this.matcher != null) {
				throw new IllegalStateException("The matcher " + this.matcher + " does not have an access rule defined");
			}
			return new AuthorizationWebFilter(this.managerBldr.build());
		}

		public final class Access {

			public AuthorizeExchangeBuilder permitAll() {
				return access( (a,e) -> Mono.just(new AuthorizationDecision(true)));
			}

			public AuthorizeExchangeBuilder denyAll() {
				return access( (a,e) -> Mono.just(new AuthorizationDecision(false)));
			}

			public AuthorizeExchangeBuilder hasRole(String role) {
				return access(AuthorityAuthorizationManager.hasRole(role));
			}

			public AuthorizeExchangeBuilder hasAuthority(String authority) {
				return access(AuthorityAuthorizationManager.hasAuthority(authority));
			}

			public AuthorizeExchangeBuilder authenticated() {
				return access(AuthenticatedAuthorizationManager.authenticated());
			}

			public AuthorizeExchangeBuilder access(ReactiveAuthorizationManager<AuthorizationContext> manager) {
				AuthorizeExchangeBuilder.this.managerBldr
					.add(new ServerWebExchangeMatcherEntry<>(
						AuthorizeExchangeBuilder.this.matcher, manager));
				AuthorizeExchangeBuilder.this.matcher = null;
				return AuthorizeExchangeBuilder.this;
			}
		}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class HttpBasicBuilder {
		private ReactiveAuthenticationManager authenticationManager;

		private SecurityContextRepository securityContextRepository = new ServerWebExchangeAttributeSecurityContextRepository();

		private AuthenticationEntryPoint entryPoint = new HttpBasicAuthenticationEntryPoint();

		public HttpBasicBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		public HttpBasicBuilder securityContextRepository(SecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
			return this;
		}

		public HttpSecurity and() {
			return HttpSecurity.this;
		}

		public HttpSecurity disable() {
			HttpSecurity.this.httpBasic = null;
			return HttpSecurity.this;
		}

		protected AuthenticationWebFilter build() {
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setEntryPoint(this.entryPoint);
			authenticationFilter.setAuthenticationConverter(new HttpBasicAuthenticationConverter());
			if(this.securityContextRepository != null) {
				authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
			}
			return authenticationFilter;
		}

		private HttpBasicBuilder() {}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class HeaderBuilder {
		private final List<HttpHeadersWriter> writers;

		private CacheControlHttpHeadersWriter cacheControl = new CacheControlHttpHeadersWriter();

		private ContentTypeOptionsHttpHeadersWriter contentTypeOptions = new ContentTypeOptionsHttpHeadersWriter();

		private StrictTransportSecurityHttpHeadersWriter hsts = new StrictTransportSecurityHttpHeadersWriter();

		private XFrameOptionsHttpHeadersWriter frameOptions = new XFrameOptionsHttpHeadersWriter();

		private XXssProtectionHttpHeadersWriter xss = new XXssProtectionHttpHeadersWriter();

		public HttpSecurity and() {
			return HttpSecurity.this;
		}

		public CacheSpec cache() {
			return new CacheSpec();
		}

		public ContentTypeOptionsSpec contentTypeOptions() {
			return new ContentTypeOptionsSpec();
		}

		public FrameOptionsSpec frameOptions() {
			return new FrameOptionsSpec();
		}

		public HstsSpec hsts() {
			return new HstsSpec();
		}

		public HttpHeaderWriterWebFilter build() {
			HttpHeadersWriter writer = new CompositeHttpHeadersWriter(this.writers);
			return new HttpHeaderWriterWebFilter(writer);
		}

		public XssProtectionSpec xssProtection() {
			return new XssProtectionSpec();
		}

		public class CacheSpec {
			public void disable() {
				HeaderBuilder.this.writers.remove(HeaderBuilder.this.cacheControl);
			}

			private CacheSpec() {}
		}

		public class ContentTypeOptionsSpec {
			public void disable() {
				HeaderBuilder.this.writers.remove(HeaderBuilder.this.contentTypeOptions);
			}

			private ContentTypeOptionsSpec() {}
		}

		public class FrameOptionsSpec {
			public void mode(XFrameOptionsHttpHeadersWriter.Mode mode) {
				HeaderBuilder.this.frameOptions.setMode(mode);
			}
			public void disable() {
				HeaderBuilder.this.writers.remove(HeaderBuilder.this.frameOptions);
			}

			private FrameOptionsSpec() {}
		}

		public class HstsSpec {
			public void maxAge(Duration maxAge) {
				HeaderBuilder.this.hsts.setMaxAge(maxAge);
			}

			public void includeSubdomains(boolean includeSubDomains) {
				HeaderBuilder.this.hsts.setIncludeSubDomains(includeSubDomains);
			}

			public void disable() {
				HeaderBuilder.this.writers.remove(HeaderBuilder.this.hsts);
			}

			private HstsSpec() {}
		}

		public class XssProtectionSpec {
			public void disable() {
				HeaderBuilder.this.writers.remove(HeaderBuilder.this.xss);
			}

			private XssProtectionSpec() {}
		}

		private HeaderBuilder() {
			this.writers = new ArrayList<>(
				Arrays.asList(this.cacheControl, this.contentTypeOptions, this.hsts,
					this.frameOptions, this.xss));
		}
	}
}
