package org.springframework.security.web.authentication.suply;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.supply.AuthenticationSupplier;
import org.springframework.security.web.authentication.supply.AuthenticationSupplierRegistry;
import org.springframework.security.web.authentication.supply.AuthenticationTokenSupplier;
import org.springframework.security.web.authentication.supply.GenericAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationSupplier;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Tests {@link GenericAuthenticationFilter}.
 *
 * @author Sergey Bespalov
 */
public class GenericAuthenticationFilterTests {

	private GenericAuthenticationFilter filter;
	private AuthenticationManager manager;
	private AuthenticationSupplier<UsernamePasswordAuthenticationToken> basicAuthenticationSupplier;

	@Before
	public void setUp() throws Exception {
		SecurityContextHolder.clearContext();

		UsernamePasswordAuthenticationToken requestedAuthentication = new UsernamePasswordAuthenticationToken(
				"vasya", "pupkin");
		requestedAuthentication.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication authenticatedAuthentication = new UsernamePasswordAuthenticationToken("vasya", "pupkin",
				AuthorityUtils.createAuthorityList("ROLE_1"));

		RequestMatcher requestMatcher = mock(RequestMatcher.class);
		when(requestMatcher.matches(any(HttpServletRequest.class))).thenReturn(true);
		filter = new GenericAuthenticationFilter(requestMatcher);

		manager = mock(AuthenticationManager.class);
		when(manager.authenticate(requestedAuthentication)).thenReturn(authenticatedAuthentication);
		when(manager.authenticate(not(eq(requestedAuthentication)))).thenThrow(
				new BadCredentialsException(""));
		filter.setAuthenticationManager(manager);

		BasicAuthenticationSupplier basicAuthenticationSupplier = new BasicAuthenticationSupplier();
		basicAuthenticationSupplier.setRealmName("springframework.com");
		AuthenticationTokenSupplier authenticationTokenSupplier = new AuthenticationTokenSupplier<>(basicAuthenticationSupplier);
		AuthenticationSupplierRegistry authenticationSupplierRegistry = mock(AuthenticationSupplierRegistry.class);
		when(authenticationSupplierRegistry.<UsernamePasswordAuthenticationToken>lookupSupplierByAuthenticationType(
				eq(BasicAuthenticationSupplier.AUTHENTICATION_TYPE_BASIC))).thenReturn(authenticationTokenSupplier);
		when(authenticationSupplierRegistry
				.lookupSupplierByAuthenticationType(not(eq(BasicAuthenticationSupplier.AUTHENTICATION_TYPE_BASIC))))
						.thenReturn(null);

		filter.setAuthenticationSupplierRegistry(authenticationSupplierRegistry);
	}

	@After
	public void clearContext() throws Exception {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testFilterIgnoresRequestsContainingNoAuthorizationHeader()
			throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/some_file.html");
		final MockHttpServletResponse response = new MockHttpServletResponse();

		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testInvalidBasicAuthorizationTokenIsIgnored() throws Exception {
		String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization",
				"Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
		request.setSession(new MockHttpSession());
		final MockHttpServletResponse response = new MockHttpServletResponse();

		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verify(chain, never()).doFilter(any(ServletRequest.class),
				any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void invalidBase64IsIgnored() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic NOT_VALID_BASE64");
		request.setServletPath("/some_file.html");
		request.setSession(new MockHttpSession());
		final MockHttpServletResponse response = new MockHttpServletResponse();

		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verify(chain, never()).doFilter(any(ServletRequest.class),
				any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testAuthenticationPassed() throws Exception {
		String token = "vasya:pupkin";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization",
				"Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, new MockHttpServletResponse(), chain);

		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
				.isEqualTo("vasya");
	}

	@Test
	public void testUnsupportedAuthenticationTypeIsIgnored() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Unsupported auth");
		request.setServletPath("/some_file.html");
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, new MockHttpServletResponse(), chain);

		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testInvalidAuthenticationReturnsUnauthorized()
			throws Exception {
		String token = "vasya:WRONG_PASSWORD";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization",
				"Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
		request.setSession(new MockHttpSession());
		MockHttpServletResponse response = new MockHttpServletResponse();

		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verify(chain, never()).doFilter(any(ServletRequest.class),
				any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		assertThat(response.getHeader("WWW-Authenticate")).isNotNull();
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Basic realm=\"springframework.com\"");
	}

}
