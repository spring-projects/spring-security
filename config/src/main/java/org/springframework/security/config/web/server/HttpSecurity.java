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

import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerFormLoginAuthenticationConverter;
import org.springframework.security.web.server.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.LogoutHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.SecurityContextRepositoryLogoutHandler;
import org.springframework.security.web.server.authentication.www.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.context.AuthenticationReactorContextWebFilter;
import org.springframework.security.web.server.context.SecurityContextServerRepository;
import org.springframework.security.web.server.context.SecurityContextRepositoryWebFilter;
import org.springframework.security.web.server.context.ServerWebExchangeAttributeSecurityContextServerRepository;
import org.springframework.security.web.server.context.WebSessionSecurityContextServerRepository;
import org.springframework.security.web.server.header.CacheControlHttpHeadersWriter;
import org.springframework.security.web.server.header.CompositeHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.HttpHeaderWriterWebFilter;
import org.springframework.security.web.server.header.HttpHeadersWriter;
import org.springframework.security.web.server.header.StrictTransportSecurityHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionHttpHeadersWriter;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.DelegateEntry;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class HttpSecurity {
	private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

	private AuthorizeExchangeBuilder authorizeExchangeBuilder;

	private HeaderBuilder headers;

	private HttpBasicBuilder httpBasic;

	private FormLoginBuilder formLogin;

	private LogoutBuilder logout;

	private ReactiveAuthenticationManager authenticationManager;

	private SecurityContextServerRepository securityContextServerRepository;

	private ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;

	private List<DelegateEntry> defaultEntryPoints = new ArrayList<>();

	private List<WebFilter> webFilters = new ArrayList<>();

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

	public HttpSecurity addFilterAt(WebFilter webFilter, SecurityWebFiltersOrder order) {
		this.webFilters.add(new OrderedWebFilter(webFilter, order.getOrder()));
		return this;
	}

	/**
	 * Gets the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 * @return the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 */
	private ServerWebExchangeMatcher getSecurityMatcher() {
		return this.securityMatcher;
	}

	public HttpSecurity securityContextRepository(SecurityContextServerRepository securityContextServerRepository) {
		Assert.notNull(securityContextServerRepository, "securityContextRepository cannot be null");
		this.securityContextServerRepository = securityContextServerRepository;
		return this;
	}

	public HttpBasicBuilder httpBasic() {
		if(this.httpBasic == null) {
			this.httpBasic = new HttpBasicBuilder();
		}
		return this.httpBasic;
	}

	public FormLoginBuilder formLogin() {
		if(this.formLogin == null) {
			this.formLogin = new FormLoginBuilder();
		}
		return this.formLogin;
	}

	public HeaderBuilder headers() {
		if(this.headers == null) {
			this.headers = new HeaderBuilder();
		}
		return this.headers;
	}

	public AuthorizeExchangeBuilder authorizeExchange() {
		if(this.authorizeExchangeBuilder == null) {
			this.authorizeExchangeBuilder = new AuthorizeExchangeBuilder();
		}
		return this.authorizeExchangeBuilder;
	}

	public LogoutBuilder logout() {
		if (this.logout == null) {
			this.logout = new LogoutBuilder();
		}
		return this.logout;
	}

	public HttpSecurity authenticationManager(ReactiveAuthenticationManager manager) {
		this.authenticationManager = manager;
		return this;
	}

	public SecurityWebFilterChain build() {
		if(this.headers != null) {
			this.headers.configure(this);
		}
		WebFilter securityContextRepositoryWebFilter = securityContextRepositoryWebFilter();
		if(securityContextRepositoryWebFilter != null) {
			this.webFilters.add(securityContextRepositoryWebFilter);
		}
		if(this.httpBasic != null) {
			this.httpBasic.authenticationManager(this.authenticationManager);
			if(this.securityContextServerRepository != null) {
				this.httpBasic.securityContextRepository(this.securityContextServerRepository);
			}
			this.httpBasic.configure(this);
		}
		if(this.formLogin != null) {
			this.formLogin.authenticationManager(this.authenticationManager);
			if(this.securityContextServerRepository != null) {
				this.formLogin.securityContextRepository(this.securityContextServerRepository);
			}
			if(this.formLogin.serverAuthenticationEntryPoint == null) {
				this.webFilters.add(new OrderedWebFilter(new LoginPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING.getOrder()));
			}
			this.formLogin.configure(this);
		}
		if(this.logout != null) {
			this.logout.configure(this);
		}
		this.addFilterAt(new AuthenticationReactorContextWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION_CONTEXT);
		if(this.authorizeExchangeBuilder != null) {
			ServerAuthenticationEntryPoint serverAuthenticationEntryPoint = getServerAuthenticationEntryPoint();
			ExceptionTranslationWebFilter exceptionTranslationWebFilter = new ExceptionTranslationWebFilter();
			if(serverAuthenticationEntryPoint != null) {
				exceptionTranslationWebFilter.setServerAuthenticationEntryPoint(
					serverAuthenticationEntryPoint);
			}
			this.addFilterAt(exceptionTranslationWebFilter, SecurityWebFiltersOrder.EXCEPTION_TRANSLATION);
			this.authorizeExchangeBuilder.configure(this);
		}
		AnnotationAwareOrderComparator.sort(this.webFilters);
		return new MatcherSecurityWebFilterChain(getSecurityMatcher(), this.webFilters);
	}

	private ServerAuthenticationEntryPoint getServerAuthenticationEntryPoint() {
		if(this.serverAuthenticationEntryPoint != null || this.defaultEntryPoints.isEmpty()) {
			return this.serverAuthenticationEntryPoint;
		}
		if(this.defaultEntryPoints.size() == 1) {
			return this.defaultEntryPoints.get(0).getEntryPoint();
		}
		DelegatingServerAuthenticationEntryPoint result = new DelegatingServerAuthenticationEntryPoint(this.defaultEntryPoints);
		result.setDefaultEntryPoint(this.defaultEntryPoints.get(this.defaultEntryPoints.size() - 1).getEntryPoint());
		return result;
	}

	public static HttpSecurity http() {
		return new HttpSecurity();
	}

	private WebFilter securityContextRepositoryWebFilter() {
		SecurityContextServerRepository repository = this.securityContextServerRepository;
		if(repository == null) {
			return null;
		}
		WebFilter result = new SecurityContextRepositoryWebFilter(repository);
		return new OrderedWebFilter(result, SecurityWebFiltersOrder.SECURITY_CONTEXT_REPOSITORY.getOrder());
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

		protected void configure(HttpSecurity http) {
			if(this.matcher != null) {
				throw new IllegalStateException("The matcher " + this.matcher + " does not have an access rule defined");
			}
			AuthorizationWebFilter result = new AuthorizationWebFilter(this.managerBldr.build());
			http.addFilterAt(result, SecurityWebFiltersOrder.AUTHORIZATION);
		}

		public final class Access {

			public AuthorizeExchangeBuilder permitAll() {
				return access( (a,e) -> Mono.just(new AuthorizationDecision(true)));
			}

			public AuthorizeExchangeBuilder denyAll() {
				return access( (a,e) -> Mono.just(new AuthorizationDecision(false)));
			}

			public AuthorizeExchangeBuilder hasRole(String role) {
				return access(AuthorityReactiveAuthorizationManager.hasRole(role));
			}

			public AuthorizeExchangeBuilder hasAuthority(String authority) {
				return access(AuthorityReactiveAuthorizationManager.hasAuthority(authority));
			}

			public AuthorizeExchangeBuilder authenticated() {
				return access(AuthenticatedReactiveAuthorizationManager.authenticated());
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

		private SecurityContextServerRepository securityContextServerRepository = new ServerWebExchangeAttributeSecurityContextServerRepository();

		private ServerAuthenticationEntryPoint entryPoint = new HttpBasicServerAuthenticationEntryPoint();

		public HttpBasicBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		public HttpBasicBuilder securityContextRepository(SecurityContextServerRepository securityContextServerRepository) {
			this.securityContextServerRepository = securityContextServerRepository;
			return this;
		}

		public HttpSecurity and() {
			return HttpSecurity.this;
		}

		public HttpSecurity disable() {
			HttpSecurity.this.httpBasic = null;
			return HttpSecurity.this;
		}

		protected void configure(HttpSecurity http) {
			MediaTypeServerWebExchangeMatcher restMatcher = new MediaTypeServerWebExchangeMatcher(
				MediaType.APPLICATION_ATOM_XML,
				MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML,
				MediaType.MULTIPART_FORM_DATA, MediaType.TEXT_XML);
			restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			HttpSecurity.this.defaultEntryPoints.add(new DelegateEntry(restMatcher, this.entryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(this.entryPoint));
			authenticationFilter.setAuthenticationConverter(new ServerHttpBasicAuthenticationConverter());
			if(this.securityContextServerRepository != null) {
				authenticationFilter.setSecurityContextServerRepository(this.securityContextServerRepository);
			}
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);
		}

		private HttpBasicBuilder() {}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class FormLoginBuilder {
		private ReactiveAuthenticationManager authenticationManager;

		private SecurityContextServerRepository securityContextServerRepository = new WebSessionSecurityContextServerRepository();

		private ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;

		private ServerWebExchangeMatcher requiresAuthenticationMatcher;

		private AuthenticationFailureHandler authenticationFailureHandler;

		public FormLoginBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		public FormLoginBuilder loginPage(String loginPage) {
			this.serverAuthenticationEntryPoint =  new RedirectServerAuthenticationEntryPoint(loginPage);
			this.requiresAuthenticationMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, loginPage);
			this.authenticationFailureHandler = new AuthenticationEntryPointFailureHandler(new RedirectServerAuthenticationEntryPoint(loginPage + "?error"));
			return this;
		}

		public FormLoginBuilder authenticationEntryPoint(ServerAuthenticationEntryPoint serverAuthenticationEntryPoint) {
			this.serverAuthenticationEntryPoint = serverAuthenticationEntryPoint;
			return this;
		}

		public FormLoginBuilder requiresAuthenticationMatcher(ServerWebExchangeMatcher requiresAuthenticationMatcher) {
			this.requiresAuthenticationMatcher = requiresAuthenticationMatcher;
			return this;
		}

		public FormLoginBuilder authenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		public FormLoginBuilder securityContextRepository(SecurityContextServerRepository securityContextServerRepository) {
			this.securityContextServerRepository = securityContextServerRepository;
			return this;
		}

		public HttpSecurity and() {
			return HttpSecurity.this;
		}

		public HttpSecurity disable() {
			HttpSecurity.this.formLogin = null;
			return HttpSecurity.this;
		}

		protected void configure(HttpSecurity http) {
			if(this.serverAuthenticationEntryPoint == null) {
				loginPage("/login");
			}
			MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(
				MediaType.TEXT_HTML);
			htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			HttpSecurity.this.defaultEntryPoints.add(0, new DelegateEntry(htmlMatcher, this.serverAuthenticationEntryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setRequiresAuthenticationMatcher(this.requiresAuthenticationMatcher);
			authenticationFilter.setAuthenticationFailureHandler(this.authenticationFailureHandler);
			authenticationFilter.setAuthenticationConverter(new ServerFormLoginAuthenticationConverter());
			authenticationFilter.setServerAuthenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/"));
			authenticationFilter.setSecurityContextServerRepository(this.securityContextServerRepository);
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.FORM_LOGIN);
		}

		private FormLoginBuilder() {
		}
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

		protected void configure(HttpSecurity http) {
			HttpHeadersWriter writer = new CompositeHttpHeadersWriter(this.writers);
			HttpHeaderWriterWebFilter result = new HttpHeaderWriterWebFilter(writer);
			http.addFilterAt(result, SecurityWebFiltersOrder.HTTP_HEADERS_WRITER);
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

	/**
	 * @author Shazin Sadakath
	 * @since 5.0
	 */
	public final class LogoutBuilder {

		private LogoutHandler logoutHandler = new SecurityContextRepositoryLogoutHandler();

		private String logoutUrl = "/logout";

		private ServerWebExchangeMatcher requiresLogout = ServerWebExchangeMatchers
			.pathMatchers(this.logoutUrl);

		public LogoutBuilder logoutHandler(LogoutHandler logoutHandler) {
			Assert.notNull(logoutHandler, "logoutHandler must not be null");
			this.logoutHandler = logoutHandler;
			return this;
		}

		public LogoutBuilder logoutUrl(String logoutUrl) {
			Assert.notNull(this.logoutHandler, "logoutUrl must not be null");
			this.logoutUrl = logoutUrl;
			this.requiresLogout = ServerWebExchangeMatchers.pathMatchers(logoutUrl);
			return this;
		}

		public HttpSecurity disable() {
			HttpSecurity.this.logout = null;
			return and();
		}

		public HttpSecurity and() {
			return HttpSecurity.this;
		}

		public void configure(HttpSecurity http) {
			LogoutWebFilter logoutWebFilter = createLogoutWebFilter(http);
			http.addFilterAt(logoutWebFilter, SecurityWebFiltersOrder.LOGOUT);
		}

		private LogoutWebFilter createLogoutWebFilter(HttpSecurity http) {
			LogoutWebFilter logoutWebFilter = new LogoutWebFilter();
			logoutWebFilter.setLogoutHandler(this.logoutHandler);
			logoutWebFilter.setRequiresLogout(this.requiresLogout);

			return logoutWebFilter;
		}

		private LogoutBuilder() {}
	}

	private static class OrderedWebFilter implements WebFilter, Ordered {
		private final WebFilter webFilter;
		private final int order;

		public OrderedWebFilter(WebFilter webFilter, int order) {
			this.webFilter = webFilter;
			this.order = order;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange,
			WebFilterChain chain) {
			return this.webFilter.filter(exchange, chain);
		}

		@Override
		public int getOrder() {
			return this.order;
		}

		@Override
		public String toString() {
			return "OrderedWebFilter{" + "webFilter=" + this.webFilter + ", order=" + this.order
				+ '}';
		}
	}
}
