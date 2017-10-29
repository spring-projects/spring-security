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
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerFormLoginAuthenticationConverter;
import org.springframework.security.web.server.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.context.ReactorContextWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.header.CacheControlServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CompositeServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.HttpHeaderWriterWebFilter;
import org.springframework.security.web.server.header.ServerHttpHeadersWriter;
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter;
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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
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
public class ServerHttpSecurity {
	private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

	private AuthorizeExchangeBuilder authorizeExchangeBuilder;

	private HeaderBuilder headers;

	private CsrfBuilder csrf = new CsrfBuilder();

	private HttpBasicBuilder httpBasic;

	private FormLoginBuilder formLogin;

	private LogoutBuilder logout;

	private ReactiveAuthenticationManager authenticationManager;

	private ServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();

	private ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;

	private List<DelegateEntry> defaultEntryPoints = new ArrayList<>();

	private List<WebFilter> webFilters = new ArrayList<>();

	private Throwable built;

	/**
	 * The ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *
	 * @param matcher the ServerExchangeMatcher that determines which requests apply to this HttpSecurity instance.
	 *                Default is all requests.
	 */
	public ServerHttpSecurity securityMatcher(ServerWebExchangeMatcher matcher) {
		Assert.notNull(matcher, "matcher cannot be null");
		this.securityMatcher = matcher;
		return this;
	}

	public ServerHttpSecurity addFilterAt(WebFilter webFilter, SecurityWebFiltersOrder order) {
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

	public ServerHttpSecurity securityContextRepository(ServerSecurityContextRepository serverSecurityContextRepository) {
		Assert.notNull(serverSecurityContextRepository, "securityContextRepository cannot be null");
		this.serverSecurityContextRepository = serverSecurityContextRepository;
		return this;
	}

	public CsrfBuilder csrf() {
		if(this.csrf == null) {
			this.csrf = new CsrfBuilder();
		}
		return this.csrf;
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

	public ServerHttpSecurity authenticationManager(ReactiveAuthenticationManager manager) {
		this.authenticationManager = manager;
		return this;
	}

	public SecurityWebFilterChain build() {
		if(this.built != null) {
			throw new IllegalStateException("This has already been built with the following stacktrace. " + buildToString());
		}
		this.built = new RuntimeException("First Build Invocation").fillInStackTrace();
		if(this.headers != null) {
			this.headers.configure(this);
		}
		WebFilter securityContextRepositoryWebFilter = securityContextRepositoryWebFilter();
		if(securityContextRepositoryWebFilter != null) {
			this.webFilters.add(securityContextRepositoryWebFilter);
		}
		if(this.csrf != null) {
			this.csrf.configure(this);
		}
		if(this.httpBasic != null) {
			this.httpBasic.authenticationManager(this.authenticationManager);
			if(this.serverSecurityContextRepository != null) {
				this.httpBasic.securityContextRepository(this.serverSecurityContextRepository);
			}
			this.httpBasic.configure(this);
		}
		if(this.formLogin != null) {
			this.formLogin.authenticationManager(this.authenticationManager);
			if(this.serverSecurityContextRepository != null) {
				this.formLogin.securityContextRepository(this.serverSecurityContextRepository);
			}
			if(this.formLogin.serverAuthenticationEntryPoint == null) {
				this.webFilters.add(new OrderedWebFilter(new LoginPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING.getOrder()));
			}
			this.formLogin.configure(this);
		}
		if(this.logout != null) {
			this.logout.configure(this);
		}
		this.addFilterAt(new SecurityContextServerWebExchangeWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE);
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

	private String buildToString() {
		try(StringWriter writer = new StringWriter()) {
			try(PrintWriter printer = new PrintWriter(writer)) {
				printer.println();
				printer.println();
				this.built.printStackTrace(printer);
				printer.println();
				printer.println();
				return writer.toString();
			}
		} catch(IOException e) {
			throw new RuntimeException(e);
		}
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

	public static ServerHttpSecurity http() {
		return new ServerHttpSecurity();
	}

	private WebFilter securityContextRepositoryWebFilter() {
		ServerSecurityContextRepository repository = this.serverSecurityContextRepository;
		if(repository == null) {
			return null;
		}
		WebFilter result = new ReactorContextWebFilter(repository);
		return new OrderedWebFilter(result, SecurityWebFiltersOrder.REACTOR_CONTEXT.getOrder());
	}

	private ServerHttpSecurity() {}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class AuthorizeExchangeBuilder extends AbstractServerWebExchangeMatcherRegistry<AuthorizeExchangeBuilder.Access> {
		private DelegatingReactiveAuthorizationManager.Builder managerBldr = DelegatingReactiveAuthorizationManager.builder();
		private ServerWebExchangeMatcher matcher;
		private boolean anyExchangeRegistered;

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
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

		protected void configure(ServerHttpSecurity http) {
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
	public class CsrfBuilder {
		private CsrfWebFilter filter = new CsrfWebFilter();

		public CsrfBuilder serverAccessDeniedHandler(
			ServerAccessDeniedHandler serverAccessDeniedHandler) {
			this.filter.setServerAccessDeniedHandler(serverAccessDeniedHandler);
			return this;
		}

		public CsrfBuilder csrfTokenAttributeName(String csrfTokenAttributeName) {
			Assert.notNull(csrfTokenAttributeName, "csrfTokenAttributeName cannot be null");
			this.filter.setCsrfTokenAttributeName(csrfTokenAttributeName);
			return this;
		}

		public CsrfBuilder serverCsrfTokenRepository(
			ServerCsrfTokenRepository serverCsrfTokenRepository) {
			this.filter.setServerCsrfTokenRepository(serverCsrfTokenRepository);
			return this;
		}

		public CsrfBuilder requireCsrfProtectionMatcher(
			ServerWebExchangeMatcher requireCsrfProtectionMatcher) {
			this.filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
			return this;
		}

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.csrf = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			http.addFilterAt(this.filter, SecurityWebFiltersOrder.CSRF);
		}

		private CsrfBuilder() {}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class HttpBasicBuilder {
		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository serverSecurityContextRepository = NoOpServerSecurityContextRepository.getInstance();

		private ServerAuthenticationEntryPoint entryPoint = new HttpBasicServerAuthenticationEntryPoint();

		public HttpBasicBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		public HttpBasicBuilder securityContextRepository(ServerSecurityContextRepository serverSecurityContextRepository) {
			this.serverSecurityContextRepository = serverSecurityContextRepository;
			return this;
		}

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.httpBasic = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			MediaTypeServerWebExchangeMatcher restMatcher = new MediaTypeServerWebExchangeMatcher(
				MediaType.APPLICATION_ATOM_XML,
				MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML,
				MediaType.MULTIPART_FORM_DATA, MediaType.TEXT_XML);
			restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerHttpSecurity.this.defaultEntryPoints.add(new DelegateEntry(restMatcher, this.entryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setServerAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(this.entryPoint));
			authenticationFilter.setAuthenticationConverter(new ServerHttpBasicAuthenticationConverter());
			if(this.serverSecurityContextRepository != null) {
				authenticationFilter.setServerSecurityContextRepository(this.serverSecurityContextRepository);
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

		private ServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();

		private ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;

		private ServerWebExchangeMatcher requiresAuthenticationMatcher;

		private ServerAuthenticationFailureHandler serverAuthenticationFailureHandler;

		public FormLoginBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		public FormLoginBuilder loginPage(String loginPage) {
			this.serverAuthenticationEntryPoint =  new RedirectServerAuthenticationEntryPoint(loginPage);
			this.requiresAuthenticationMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, loginPage);
			this.serverAuthenticationFailureHandler = new ServerAuthenticationEntryPointFailureHandler(new RedirectServerAuthenticationEntryPoint(loginPage + "?error"));
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

		public FormLoginBuilder authenticationFailureHandler(ServerAuthenticationFailureHandler serverAuthenticationFailureHandler) {
			this.serverAuthenticationFailureHandler = serverAuthenticationFailureHandler;
			return this;
		}

		public FormLoginBuilder securityContextRepository(ServerSecurityContextRepository serverSecurityContextRepository) {
			this.serverSecurityContextRepository = serverSecurityContextRepository;
			return this;
		}

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.formLogin = null;
			return ServerHttpSecurity.this;
		}

		protected void configure(ServerHttpSecurity http) {
			if(this.serverAuthenticationEntryPoint == null) {
				loginPage("/login");
			}
			MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(
				MediaType.TEXT_HTML);
			htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerHttpSecurity.this.defaultEntryPoints.add(0, new DelegateEntry(htmlMatcher, this.serverAuthenticationEntryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setRequiresAuthenticationMatcher(this.requiresAuthenticationMatcher);
			authenticationFilter.setServerAuthenticationFailureHandler(this.serverAuthenticationFailureHandler);
			authenticationFilter.setAuthenticationConverter(new ServerFormLoginAuthenticationConverter());
			authenticationFilter.setServerAuthenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/"));
			authenticationFilter.setServerSecurityContextRepository(this.serverSecurityContextRepository);
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
		private final List<ServerHttpHeadersWriter> writers;

		private CacheControlServerHttpHeadersWriter cacheControl = new CacheControlServerHttpHeadersWriter();

		private ContentTypeOptionsServerHttpHeadersWriter contentTypeOptions = new ContentTypeOptionsServerHttpHeadersWriter();

		private StrictTransportSecurityServerHttpHeadersWriter hsts = new StrictTransportSecurityServerHttpHeadersWriter();

		private XFrameOptionsServerHttpHeadersWriter frameOptions = new XFrameOptionsServerHttpHeadersWriter();

		private XXssProtectionServerHttpHeadersWriter xss = new XXssProtectionServerHttpHeadersWriter();

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
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

		protected void configure(ServerHttpSecurity http) {
			ServerHttpHeadersWriter writer = new CompositeServerHttpHeadersWriter(this.writers);
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
			public void mode(XFrameOptionsServerHttpHeadersWriter.Mode mode) {
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
		private LogoutWebFilter logoutWebFilter = new LogoutWebFilter();

		public LogoutBuilder logoutHandler(ServerLogoutHandler serverLogoutHandler) {
			this.logoutWebFilter.setServerLogoutHandler(serverLogoutHandler);
			return this;
		}

		public LogoutBuilder logoutUrl(String logoutUrl) {
			Assert.notNull(logoutUrl, "logoutUrl must not be null");
			ServerWebExchangeMatcher requiresLogout = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, logoutUrl);
			return requiresLogout(requiresLogout);
		}

		public LogoutBuilder requiresLogout(ServerWebExchangeMatcher requiresLogout) {
			this.logoutWebFilter.setRequiresLogout(requiresLogout);
			return this;
		}

		public LogoutBuilder logoutSuccessHandler(ServerLogoutSuccessHandler handler) {
			this.logoutWebFilter.setServerLogoutSuccessHandler(handler);
			return this;
		}

		public ServerHttpSecurity disable() {
			ServerHttpSecurity.this.logout = null;
			return and();
		}

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		public void configure(ServerHttpSecurity http) {
			http.addFilterAt(this.logoutWebFilter, SecurityWebFiltersOrder.LOGOUT);
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
