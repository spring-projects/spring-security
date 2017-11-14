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
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ReactorContextWebFilter;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
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
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.ServerRequestCacheWebFilter;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.server.ui.LogoutPageGeneratingWebFilter;
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

	private AuthorizeExchangeSpec authorizeExchange;

	private HeaderSpec headers = new HeaderSpec();

	private CsrfSpec csrf = new CsrfSpec();

	private ExceptionHandlingSpec exceptionHandling = new ExceptionHandlingSpec();

	private HttpBasicSpec httpBasic;

	private final RequestCacheSpec requestCache = new RequestCacheSpec();

	private FormLoginSpec formLogin;

	private LogoutSpec logout = new LogoutSpec();

	private ReactiveAuthenticationManager authenticationManager;

	private ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();

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

	public ServerHttpSecurity securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
		return this;
	}

	public CsrfSpec csrf() {
		if(this.csrf == null) {
			this.csrf = new CsrfSpec();
		}
		return this.csrf;
	}

	public HttpBasicSpec httpBasic() {
		if(this.httpBasic == null) {
			this.httpBasic = new HttpBasicSpec();
		}
		return this.httpBasic;
	}

	public FormLoginSpec formLogin() {
		if(this.formLogin == null) {
			this.formLogin = new FormLoginSpec();
		}
		return this.formLogin;
	}

	public HeaderSpec headers() {
		if(this.headers == null) {
			this.headers = new HeaderSpec();
		}
		return this.headers;
	}

	public ExceptionHandlingSpec exceptionHandling() {
		if(this.exceptionHandling == null) {
			this.exceptionHandling = new ExceptionHandlingSpec();
		}
		return this.exceptionHandling;
	}

	public AuthorizeExchangeSpec authorizeExchange() {
		if(this.authorizeExchange == null) {
			this.authorizeExchange = new AuthorizeExchangeSpec();
		}
		return this.authorizeExchange;
	}

	public LogoutSpec logout() {
		if (this.logout == null) {
			this.logout = new LogoutSpec();
		}
		return this.logout;
	}

	public RequestCacheSpec requestCache() {
		return this.requestCache;
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
			if(this.securityContextRepository != null) {
				this.httpBasic.securityContextRepository(this.securityContextRepository);
			}
			this.httpBasic.configure(this);
		}
		if(this.formLogin != null) {
			this.formLogin.authenticationManager(this.authenticationManager);
			if(this.securityContextRepository != null) {
				this.formLogin.securityContextRepository(this.securityContextRepository);
			}
			if(this.formLogin.serverAuthenticationEntryPoint == null) {
				this.webFilters.add(new OrderedWebFilter(new LoginPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING.getOrder()));
				this.webFilters.add(new OrderedWebFilter(new LogoutPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGOUT_PAGE_GENERATING.getOrder()));
			}
			this.formLogin.configure(this);
		}
		if(this.logout != null) {
			this.logout.configure(this);
		}
		this.requestCache.configure(this);
		this.addFilterAt(new SecurityContextServerWebExchangeWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE);
		if(this.authorizeExchange != null) {
			ServerAuthenticationEntryPoint serverAuthenticationEntryPoint = getServerAuthenticationEntryPoint();
			ExceptionTranslationWebFilter exceptionTranslationWebFilter = new ExceptionTranslationWebFilter();
			if(serverAuthenticationEntryPoint != null) {
				exceptionTranslationWebFilter.setServerAuthenticationEntryPoint(
					serverAuthenticationEntryPoint);
			}
			this.addFilterAt(exceptionTranslationWebFilter, SecurityWebFiltersOrder.EXCEPTION_TRANSLATION);
			this.authorizeExchange.configure(this);
		}
		AnnotationAwareOrderComparator.sort(this.webFilters);
		List<WebFilter> sortedWebFilters = new ArrayList<>();
		this.webFilters.forEach( f -> {
			if(f instanceof OrderedWebFilter) {
				f = ((OrderedWebFilter)f).webFilter;
			}
			sortedWebFilters.add(f);
		});
		return new MatcherSecurityWebFilterChain(getSecurityMatcher(), sortedWebFilters);
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
		ServerSecurityContextRepository repository = this.securityContextRepository;
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
	public class AuthorizeExchangeSpec
		extends AbstractServerWebExchangeMatcherRegistry<AuthorizeExchangeSpec.Access> {
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

			public AuthorizeExchangeSpec permitAll() {
				return access( (a,e) -> Mono.just(new AuthorizationDecision(true)));
			}

			public AuthorizeExchangeSpec denyAll() {
				return access( (a,e) -> Mono.just(new AuthorizationDecision(false)));
			}

			public AuthorizeExchangeSpec hasRole(String role) {
				return access(AuthorityReactiveAuthorizationManager.hasRole(role));
			}

			public AuthorizeExchangeSpec hasAuthority(String authority) {
				return access(AuthorityReactiveAuthorizationManager.hasAuthority(authority));
			}

			public AuthorizeExchangeSpec authenticated() {
				return access(AuthenticatedReactiveAuthorizationManager.authenticated());
			}

			public AuthorizeExchangeSpec access(ReactiveAuthorizationManager<AuthorizationContext> manager) {
				AuthorizeExchangeSpec.this.managerBldr
					.add(new ServerWebExchangeMatcherEntry<>(
						AuthorizeExchangeSpec.this.matcher, manager));
				AuthorizeExchangeSpec.this.matcher = null;
				return AuthorizeExchangeSpec.this;
			}
		}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class CsrfSpec {
		private CsrfWebFilter filter = new CsrfWebFilter();

		public CsrfSpec serverAccessDeniedHandler(
			ServerAccessDeniedHandler serverAccessDeniedHandler) {
			this.filter.setServerAccessDeniedHandler(serverAccessDeniedHandler);
			return this;
		}

		public CsrfSpec serverCsrfTokenRepository(
			ServerCsrfTokenRepository serverCsrfTokenRepository) {
			this.filter.setServerCsrfTokenRepository(serverCsrfTokenRepository);
			return this;
		}

		public CsrfSpec requireCsrfProtectionMatcher(
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

		private CsrfSpec() {}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class ExceptionHandlingSpec {
		public ExceptionHandlingSpec serverAuthenticationEntryPoint(ServerAuthenticationEntryPoint authenticationEntryPoint) {
			ServerHttpSecurity.this.serverAuthenticationEntryPoint = authenticationEntryPoint;
			return this;
		}

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		private ExceptionHandlingSpec() {}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class RequestCacheSpec {
		private ServerRequestCache requestCache = new WebSessionServerRequestCache();

		public RequestCacheSpec requestCache(ServerRequestCache requestCache) {
			Assert.notNull(requestCache, "requestCache cannot be null");
			this.requestCache = requestCache;
			return this;
		}

		protected void configure(ServerHttpSecurity http) {
			http.addFilterAt(new ServerRequestCacheWebFilter(), SecurityWebFiltersOrder.SERVER_REQUEST_CACHE);
		}

		public ServerHttpSecurity and() {
			return ServerHttpSecurity.this;
		}

		public ServerHttpSecurity disable() {
			this.requestCache = NoOpServerRequestCache.getInstance();
			return and();
		}

		private RequestCacheSpec() {}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class HttpBasicSpec {
		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository securityContextRepository = NoOpServerSecurityContextRepository.getInstance();

		private ServerAuthenticationEntryPoint entryPoint = new HttpBasicServerAuthenticationEntryPoint();

		public HttpBasicSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		public HttpBasicSpec securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
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
			authenticationFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(this.entryPoint));
			authenticationFilter.setAuthenticationConverter(new ServerHttpBasicAuthenticationConverter());
			if(this.securityContextRepository != null) {
				authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
			}
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);
		}

		private HttpBasicSpec() {}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class FormLoginSpec {
		private final RedirectServerAuthenticationSuccessHandler defaultSuccessHandler = new RedirectServerAuthenticationSuccessHandler("/");

		private RedirectServerAuthenticationEntryPoint defaultEntryPoint;

		private ReactiveAuthenticationManager authenticationManager;

		private ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();

		private ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;

		private ServerWebExchangeMatcher requiresAuthenticationMatcher;

		private ServerAuthenticationFailureHandler authenticationFailureHandler;

		private ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler = this.defaultSuccessHandler;

		public FormLoginSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
			return this;
		}

		public FormLoginSpec serverAuthenticationSuccessHandler(
			ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler) {
			Assert.notNull(serverAuthenticationSuccessHandler, "serverAuthenticationSuccessHandler cannot be null");
			this.serverAuthenticationSuccessHandler = serverAuthenticationSuccessHandler;
			return this;
		}

		public FormLoginSpec loginPage(String loginPage) {
			this.defaultEntryPoint = new RedirectServerAuthenticationEntryPoint(loginPage);
			this.serverAuthenticationEntryPoint = this.defaultEntryPoint;
			this.requiresAuthenticationMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, loginPage);
			this.authenticationFailureHandler = new RedirectServerAuthenticationFailureHandler(loginPage + "?error");
			return this;
		}

		public FormLoginSpec authenticationEntryPoint(ServerAuthenticationEntryPoint serverAuthenticationEntryPoint) {
			this.serverAuthenticationEntryPoint = serverAuthenticationEntryPoint;
			return this;
		}

		public FormLoginSpec requiresAuthenticationMatcher(ServerWebExchangeMatcher requiresAuthenticationMatcher) {
			this.requiresAuthenticationMatcher = requiresAuthenticationMatcher;
			return this;
		}

		public FormLoginSpec authenticationFailureHandler(ServerAuthenticationFailureHandler authenticationFailureHandler) {
			this.authenticationFailureHandler = authenticationFailureHandler;
			return this;
		}

		public FormLoginSpec securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
			this.securityContextRepository = securityContextRepository;
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
			if(http.requestCache != null) {
				ServerRequestCache requestCache = http.requestCache.requestCache;
				this.defaultSuccessHandler.setRequestCache(requestCache);
				if(this.defaultEntryPoint != null) {
					this.defaultEntryPoint.setRequestCache(requestCache);
				}
			}
			MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(
				MediaType.TEXT_HTML);
			htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			ServerHttpSecurity.this.defaultEntryPoints.add(0, new DelegateEntry(htmlMatcher, this.serverAuthenticationEntryPoint));
			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
				this.authenticationManager);
			authenticationFilter.setRequiresAuthenticationMatcher(this.requiresAuthenticationMatcher);
			authenticationFilter.setAuthenticationFailureHandler(this.authenticationFailureHandler);
			authenticationFilter.setAuthenticationConverter(new ServerFormLoginAuthenticationConverter());
			authenticationFilter.setServerAuthenticationSuccessHandler(this.serverAuthenticationSuccessHandler);
			authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.FORM_LOGIN);
		}

		private FormLoginSpec() {
		}
	}

	/**
	 * @author Rob Winch
	 * @since 5.0
	 */
	public class HeaderSpec {
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
				HeaderSpec.this.writers.remove(HeaderSpec.this.cacheControl);
			}

			private CacheSpec() {}
		}

		public class ContentTypeOptionsSpec {
			public void disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.contentTypeOptions);
			}

			private ContentTypeOptionsSpec() {}
		}

		public class FrameOptionsSpec {
			public void mode(XFrameOptionsServerHttpHeadersWriter.Mode mode) {
				HeaderSpec.this.frameOptions.setMode(mode);
			}
			public void disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.frameOptions);
			}

			private FrameOptionsSpec() {}
		}

		public class HstsSpec {
			public void maxAge(Duration maxAge) {
				HeaderSpec.this.hsts.setMaxAge(maxAge);
			}

			public void includeSubdomains(boolean includeSubDomains) {
				HeaderSpec.this.hsts.setIncludeSubDomains(includeSubDomains);
			}

			public void disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.hsts);
			}

			private HstsSpec() {}
		}

		public class XssProtectionSpec {
			public void disable() {
				HeaderSpec.this.writers.remove(HeaderSpec.this.xss);
			}

			private XssProtectionSpec() {}
		}

		private HeaderSpec() {
			this.writers = new ArrayList<>(
				Arrays.asList(this.cacheControl, this.contentTypeOptions, this.hsts,
					this.frameOptions, this.xss));
		}
	}

	/**
	 * @author Shazin Sadakath
	 * @since 5.0
	 */
	public final class LogoutSpec {
		private LogoutWebFilter logoutWebFilter = new LogoutWebFilter();

		public LogoutSpec logoutHandler(ServerLogoutHandler serverLogoutHandler) {
			this.logoutWebFilter.setServerLogoutHandler(serverLogoutHandler);
			return this;
		}

		public LogoutSpec logoutUrl(String logoutUrl) {
			Assert.notNull(logoutUrl, "logoutUrl must not be null");
			ServerWebExchangeMatcher requiresLogout = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, logoutUrl);
			return requiresLogout(requiresLogout);
		}

		public LogoutSpec requiresLogout(ServerWebExchangeMatcher requiresLogout) {
			this.logoutWebFilter.setRequiresLogout(requiresLogout);
			return this;
		}

		public LogoutSpec logoutSuccessHandler(ServerLogoutSuccessHandler handler) {
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

		private LogoutSpec() {}
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
