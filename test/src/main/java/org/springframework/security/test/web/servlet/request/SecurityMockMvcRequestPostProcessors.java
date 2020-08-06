/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.test.web.servlet.request;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.util.StringUtils;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.DigestUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

import static java.lang.Boolean.TRUE;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

/**
 * Contains {@link MockMvc} {@link RequestPostProcessor} implementations for Spring
 * Security.
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class SecurityMockMvcRequestPostProcessors {

	/**
	 * Creates a DigestRequestPostProcessor that enables easily adding digest based
	 * authentication to a request.
	 * @return the DigestRequestPostProcessor to use
	 */
	public static DigestRequestPostProcessor digest() {
		return new DigestRequestPostProcessor();
	}

	/**
	 * Creates a DigestRequestPostProcessor that enables easily adding digest based
	 * authentication to a request.
	 * @param username the username to use
	 * @return the DigestRequestPostProcessor to use
	 */
	public static DigestRequestPostProcessor digest(String username) {
		return digest().username(username);
	}

	/**
	 * Populates the provided X509Certificate instances on the request.
	 * @param certificates the X509Certificate instances to pouplate
	 * @return the
	 * {@link org.springframework.test.web.servlet.request.RequestPostProcessor} to use.
	 */
	public static RequestPostProcessor x509(X509Certificate... certificates) {
		return new X509RequestPostProcessor(certificates);
	}

	/**
	 * Finds an X509Cetificate using a resoureName and populates it on the request.
	 * @param resourceName the name of the X509Certificate resource
	 * @return the
	 * {@link org.springframework.test.web.servlet.request.RequestPostProcessor} to use.
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static RequestPostProcessor x509(String resourceName) throws IOException, CertificateException {
		ResourceLoader loader = new DefaultResourceLoader();
		Resource resource = loader.getResource(resourceName);
		InputStream inputStream = resource.getInputStream();
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
		return x509(certificate);
	}

	/**
	 * Creates a {@link RequestPostProcessor} that will automatically populate a valid
	 * {@link CsrfToken} in the request.
	 * @return the {@link CsrfRequestPostProcessor} for further customizations.
	 */
	public static CsrfRequestPostProcessor csrf() {
		return new CsrfRequestPostProcessor();
	}

	/**
	 * Creates a {@link RequestPostProcessor} that can be used to ensure that the
	 * resulting request is ran with the user in the {@link TestSecurityContextHolder}.
	 * @return the {@link RequestPostProcessor} to sue
	 */
	public static RequestPostProcessor testSecurityContext() {
		return new TestSecurityContextHolderPostProcessor();
	}

	/**
	 * Establish a {@link SecurityContext} that has a
	 * {@link UsernamePasswordAuthenticationToken} for the
	 * {@link Authentication#getPrincipal()} and a {@link User} for the
	 * {@link UsernamePasswordAuthenticationToken#getPrincipal()}. All details are
	 * declarative and do not require that the user actually exists.
	 *
	 * <p>
	 * The support works by associating the user to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 * @param username the username to populate
	 * @return the {@link UserRequestPostProcessor} for additional customization
	 */
	public static UserRequestPostProcessor user(String username) {
		return new UserRequestPostProcessor(username);
	}

	/**
	 * Establish a {@link SecurityContext} that has a
	 * {@link UsernamePasswordAuthenticationToken} for the
	 * {@link Authentication#getPrincipal()} and a custom {@link UserDetails} for the
	 * {@link UsernamePasswordAuthenticationToken#getPrincipal()}. All details are
	 * declarative and do not require that the user actually exists.
	 *
	 * <p>
	 * The support works by associating the user to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 * @param user the UserDetails to populate
	 * @return the {@link RequestPostProcessor} to use
	 */
	public static RequestPostProcessor user(UserDetails user) {
		return new UserDetailsRequestPostProcessor(user);
	}

	/**
	 * Establish a {@link SecurityContext} that has a {@link JwtAuthenticationToken} for
	 * the {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are declarative and do not
	 * require the JWT to be valid.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To
	 * associate the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 * @return the {@link JwtRequestPostProcessor} for additional customization
	 */
	public static JwtRequestPostProcessor jwt() {
		return new JwtRequestPostProcessor();
	}

	/**
	 * Establish a {@link SecurityContext} that has a {@link BearerTokenAuthentication}
	 * for the {@link Authentication} and a {@link OAuth2AuthenticatedPrincipal} for the
	 * {@link Authentication#getPrincipal()}. All details are declarative and do not
	 * require the token to be valid
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To
	 * associate the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 * @return the {@link OpaqueTokenRequestPostProcessor} for additional customization
	 * @since 5.3
	 */
	public static OpaqueTokenRequestPostProcessor opaqueToken() {
		return new OpaqueTokenRequestPostProcessor();
	}

	/**
	 * Establish a {@link SecurityContext} that uses the specified {@link Authentication}
	 * for the {@link Authentication#getPrincipal()} and a custom {@link UserDetails}. All
	 * details are declarative and do not require that the user actually exists.
	 *
	 * <p>
	 * The support works by associating the user to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 * @param authentication the Authentication to populate
	 * @return the {@link RequestPostProcessor} to use
	 */
	public static RequestPostProcessor authentication(Authentication authentication) {
		return new AuthenticationRequestPostProcessor(authentication);
	}

	/**
	 * Establish a {@link SecurityContext} that uses an
	 * {@link AnonymousAuthenticationToken}. This is useful when a user wants to run a
	 * majority of tests as a specific user and wishes to override a few methods to be
	 * anonymous. For example:
	 *
	 * <pre>
	 * <code>
	 * public class SecurityTests {
	 *     &#064;Before
	 *     public void setup() {
	 *         mockMvc = MockMvcBuilders
	 *             .webAppContextSetup(context)
	 *             .defaultRequest(get("/").with(user("user")))
	 *             .build();
	 *     }
	 *
	 *     &#064;Test
	 *     public void anonymous() {
	 *         mockMvc.perform(get("anonymous").with(anonymous()));
	 *     }
	 *     // ... lots of tests ran with a default user ...
	 * }
	 * </code> </pre>
	 * @return the {@link RequestPostProcessor} to use
	 */
	public static RequestPostProcessor anonymous() {
		return new AnonymousRequestPostProcessor();
	}

	/**
	 * Establish the specified {@link SecurityContext} to be used.
	 *
	 * <p>
	 * This works by associating the user to the {@link HttpServletRequest}. To associate
	 * the request to the {@link SecurityContextHolder} you need to ensure that the
	 * {@link SecurityContextPersistenceFilter} (i.e. Spring Security's FilterChainProxy
	 * will typically do this) is associated with the {@link MockMvc} instance.
	 * </p>
	 */
	public static RequestPostProcessor securityContext(SecurityContext securityContext) {
		return new SecurityContextRequestPostProcessor(securityContext);
	}

	/**
	 * Convenience mechanism for setting the Authorization header to use HTTP Basic with
	 * the given username and password. This method will automatically perform the
	 * necessary Base64 encoding.
	 * @param username the username to include in the Authorization header.
	 * @param password the password to include in the Authorization header.
	 * @return the {@link RequestPostProcessor} to use
	 */
	public static RequestPostProcessor httpBasic(String username, String password) {
		return new HttpBasicRequestPostProcessor(username, password);
	}

	/**
	 * Establish a {@link SecurityContext} that has a {@link OAuth2AuthenticationToken}
	 * for the {@link Authentication}, a {@link OAuth2User} as the principal, and a
	 * {@link OAuth2AuthorizedClient} in the session. All details are declarative and do
	 * not require associated tokens to be valid.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To
	 * associate the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 * @return the {@link OidcLoginRequestPostProcessor} for additional customization
	 * @since 5.3
	 */
	public static OAuth2LoginRequestPostProcessor oauth2Login() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", null,
				null, Collections.singleton("read"));
		return new OAuth2LoginRequestPostProcessor(accessToken);
	}

	/**
	 * Establish a {@link SecurityContext} that has a {@link OAuth2AuthenticationToken}
	 * for the {@link Authentication}, a {@link OidcUser} as the principal, and a
	 * {@link OAuth2AuthorizedClient} in the session. All details are declarative and do
	 * not require associated tokens to be valid.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To
	 * associate the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 * @return the {@link OidcLoginRequestPostProcessor} for additional customization
	 * @since 5.3
	 */
	public static OidcLoginRequestPostProcessor oidcLogin() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", null,
				null, Collections.singleton("read"));
		return new OidcLoginRequestPostProcessor(accessToken);
	}

	/**
	 * Establish an {@link OAuth2AuthorizedClient} in the session. All details are
	 * declarative and do not require associated tokens to be valid.
	 *
	 * <p>
	 * The support works by associating the authorized client to the HttpServletRequest
	 * via the {@link HttpSessionOAuth2AuthorizedClientRepository}
	 * </p>
	 * @return the {@link OAuth2ClientRequestPostProcessor} for additional customization
	 * @since 5.3
	 */
	public static OAuth2ClientRequestPostProcessor oauth2Client() {
		return new OAuth2ClientRequestPostProcessor();
	}

	/**
	 * Establish an {@link OAuth2AuthorizedClient} in the session. All details are
	 * declarative and do not require associated tokens to be valid.
	 *
	 * <p>
	 * The support works by associating the authorized client to the HttpServletRequest
	 * via the {@link HttpSessionOAuth2AuthorizedClientRepository}
	 * </p>
	 * @param registrationId The registration id for the {@link OAuth2AuthorizedClient}
	 * @return the {@link OAuth2ClientRequestPostProcessor} for additional customization
	 * @since 5.3
	 */
	public static OAuth2ClientRequestPostProcessor oauth2Client(String registrationId) {
		return new OAuth2ClientRequestPostProcessor(registrationId);
	}

	/**
	 * Populates the X509Certificate instances onto the request
	 */
	private static final class X509RequestPostProcessor implements RequestPostProcessor {

		private final X509Certificate[] certificates;

		private X509RequestPostProcessor(X509Certificate... certificates) {
			Assert.notNull(certificates, "X509Certificate cannot be null");
			this.certificates = certificates;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			request.setAttribute("javax.servlet.request.X509Certificate", this.certificates);
			return request;
		}

	}

	/**
	 * Populates a valid {@link CsrfToken} into the request.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	public static final class CsrfRequestPostProcessor implements RequestPostProcessor {

		private boolean asHeader;

		private boolean useInvalidToken;

		private CsrfRequestPostProcessor() {
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			CsrfTokenRepository repository = WebTestUtils.getCsrfTokenRepository(request);
			if (!(repository instanceof TestCsrfTokenRepository)) {
				repository = new TestCsrfTokenRepository(new HttpSessionCsrfTokenRepository());
				WebTestUtils.setCsrfTokenRepository(request, repository);
			}
			TestCsrfTokenRepository.enable(request);
			CsrfToken token = repository.generateToken(request);
			repository.saveToken(token, request, new MockHttpServletResponse());
			String tokenValue = this.useInvalidToken ? "invalid" + token.getToken() : token.getToken();
			if (this.asHeader) {
				request.addHeader(token.getHeaderName(), tokenValue);
			}
			else {
				request.setParameter(token.getParameterName(), tokenValue);
			}
			return request;
		}

		/**
		 * Instead of using the {@link CsrfToken} as a request parameter (default) will
		 * populate the {@link CsrfToken} as a header.
		 * @return the {@link CsrfRequestPostProcessor} for additional customizations
		 */
		public CsrfRequestPostProcessor asHeader() {
			this.asHeader = true;
			return this;
		}

		/**
		 * Populates an invalid token value on the request.
		 * @return the {@link CsrfRequestPostProcessor} for additional customizations
		 */
		public CsrfRequestPostProcessor useInvalidToken() {
			this.useInvalidToken = true;
			return this;
		}

		/**
		 * Used to wrap the CsrfTokenRepository to provide support for testing when the
		 * request is wrapped (i.e. Spring Session is in use).
		 */
		static class TestCsrfTokenRepository implements CsrfTokenRepository {

			final static String TOKEN_ATTR_NAME = TestCsrfTokenRepository.class.getName().concat(".TOKEN");

			final static String ENABLED_ATTR_NAME = TestCsrfTokenRepository.class.getName().concat(".ENABLED");

			private final CsrfTokenRepository delegate;

			TestCsrfTokenRepository(CsrfTokenRepository delegate) {
				this.delegate = delegate;
			}

			@Override
			public CsrfToken generateToken(HttpServletRequest request) {
				return this.delegate.generateToken(request);
			}

			@Override
			public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
				if (isEnabled(request)) {
					request.setAttribute(TOKEN_ATTR_NAME, token);
				}
				else {
					this.delegate.saveToken(token, request, response);
				}
			}

			@Override
			public CsrfToken loadToken(HttpServletRequest request) {
				if (isEnabled(request)) {
					return (CsrfToken) request.getAttribute(TOKEN_ATTR_NAME);
				}
				else {
					return this.delegate.loadToken(request);
				}
			}

			public static void enable(HttpServletRequest request) {
				request.setAttribute(ENABLED_ATTR_NAME, TRUE);
			}

			public boolean isEnabled(HttpServletRequest request) {
				return TRUE.equals(request.getAttribute(ENABLED_ATTR_NAME));
			}

		}

	}

	public static class DigestRequestPostProcessor implements RequestPostProcessor {

		private String username = "user";

		private String password = "password";

		private String realm = "Spring Security";

		private String nonce = generateNonce(60);

		private String qop = "auth";

		private String nc = "00000001";

		private String cnonce = "c822c727a648aba7";

		/**
		 * Configures the username to use
		 * @param username the username to use
		 * @return the DigestRequestPostProcessor for further customization
		 */
		private DigestRequestPostProcessor username(String username) {
			Assert.notNull(username, "username cannot be null");
			this.username = username;
			return this;
		}

		/**
		 * Configures the password to use
		 * @param password the password to use
		 * @return the DigestRequestPostProcessor for further customization
		 */
		public DigestRequestPostProcessor password(String password) {
			Assert.notNull(password, "password cannot be null");
			this.password = password;
			return this;
		}

		/**
		 * Configures the realm to use
		 * @param realm the realm to use
		 * @return the DigestRequestPostProcessor for further customization
		 */
		public DigestRequestPostProcessor realm(String realm) {
			Assert.notNull(realm, "realm cannot be null");
			this.realm = realm;
			return this;
		}

		private static String generateNonce(int validitySeconds) {
			long expiryTime = System.currentTimeMillis() + (validitySeconds * 1000);
			String toDigest = expiryTime + ":" + "key";
			String signatureValue = md5Hex(toDigest);
			String nonceValue = expiryTime + ":" + signatureValue;

			return new String(Base64.getEncoder().encode(nonceValue.getBytes()));
		}

		private String createAuthorizationHeader(MockHttpServletRequest request) {
			String uri = request.getRequestURI();
			String responseDigest = generateDigest(this.username, this.realm, this.password, request.getMethod(), uri,
					this.qop, this.nonce, this.nc, this.cnonce);
			return "Digest username=\"" + this.username + "\", realm=\"" + this.realm + "\", nonce=\"" + this.nonce
					+ "\", uri=\"" + uri + "\", response=\"" + responseDigest + "\", qop=" + this.qop + ", nc="
					+ this.nc + ", cnonce=\"" + this.cnonce + "\"";
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {

			request.addHeader("Authorization", createAuthorizationHeader(request));
			return request;
		}

		/**
		 * Computes the <code>response</code> portion of a Digest authentication header.
		 * Both the server and user agent should compute the <code>response</code>
		 * independently. Provided as a static method to simplify the coding of user
		 * agents.
		 * @param username the user's login name.
		 * @param realm the name of the realm.
		 * @param password the user's password in plaintext or ready-encoded.
		 * @param httpMethod the HTTP request method (GET, POST etc.)
		 * @param uri the request URI.
		 * @param qop the qop directive, or null if not set.
		 * @param nonce the nonce supplied by the server
		 * @param nc the "nonce-count" as defined in RFC 2617.
		 * @param cnonce opaque string supplied by the client when qop is set.
		 * @return the MD5 of the digest authentication response, encoded in hex
		 * @throws IllegalArgumentException if the supplied qop value is unsupported.
		 */
		private static String generateDigest(String username, String realm, String password, String httpMethod,
				String uri, String qop, String nonce, String nc, String cnonce) throws IllegalArgumentException {
			String a1Md5 = encodePasswordInA1Format(username, realm, password);
			String a2 = httpMethod + ":" + uri;
			String a2Md5 = md5Hex(a2);

			String digest;

			if (qop == null) {
				// as per RFC 2069 compliant clients (also reaffirmed by RFC 2617)
				digest = a1Md5 + ":" + nonce + ":" + a2Md5;
			}
			else if ("auth".equals(qop)) {
				// As per RFC 2617 compliant clients
				digest = a1Md5 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + a2Md5;
			}
			else {
				throw new IllegalArgumentException("This method does not support a qop: '" + qop + "'");
			}

			return md5Hex(digest);
		}

		static String encodePasswordInA1Format(String username, String realm, String password) {
			String a1 = username + ":" + realm + ":" + password;

			return md5Hex(a1);
		}

		private static String md5Hex(String a2) {
			return DigestUtils.md5DigestAsHex(a2.getBytes(StandardCharsets.UTF_8));
		}

	}

	/**
	 * Support class for {@link RequestPostProcessor}'s that establish a Spring Security
	 * context
	 */
	private static abstract class SecurityContextRequestPostProcessorSupport {

		/**
		 * Saves the specified {@link Authentication} into an empty
		 * {@link SecurityContext} using the {@link SecurityContextRepository}.
		 * @param authentication the {@link Authentication} to save
		 * @param request the {@link HttpServletRequest} to use
		 */
		final void save(Authentication authentication, HttpServletRequest request) {
			SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
			securityContext.setAuthentication(authentication);
			save(securityContext, request);
		}

		/**
		 * Saves the {@link SecurityContext} using the {@link SecurityContextRepository}
		 * @param securityContext the {@link SecurityContext} to save
		 * @param request the {@link HttpServletRequest} to use
		 */
		final void save(SecurityContext securityContext, HttpServletRequest request) {
			SecurityContextRepository securityContextRepository = WebTestUtils.getSecurityContextRepository(request);
			boolean isTestRepository = securityContextRepository instanceof TestSecurityContextRepository;
			if (!isTestRepository) {
				securityContextRepository = new TestSecurityContextRepository(securityContextRepository);
				WebTestUtils.setSecurityContextRepository(request, securityContextRepository);
			}

			HttpServletResponse response = new MockHttpServletResponse();

			HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response);
			securityContextRepository.loadContext(requestResponseHolder);

			request = requestResponseHolder.getRequest();
			response = requestResponseHolder.getResponse();

			securityContextRepository.saveContext(securityContext, request, response);
		}

		/**
		 * Used to wrap the SecurityContextRepository to provide support for testing in
		 * stateless mode
		 */
		static final class TestSecurityContextRepository implements SecurityContextRepository {

			private final static String ATTR_NAME = TestSecurityContextRepository.class.getName().concat(".REPO");

			private final SecurityContextRepository delegate;

			private TestSecurityContextRepository(SecurityContextRepository delegate) {
				this.delegate = delegate;
			}

			@Override
			public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
				SecurityContext result = getContext(requestResponseHolder.getRequest());
				// always load from the delegate to ensure the request/response in the
				// holder are updated
				// remember the SecurityContextRepository is used in many different
				// locations
				SecurityContext delegateResult = this.delegate.loadContext(requestResponseHolder);
				return result == null ? delegateResult : result;
			}

			@Override
			public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
				request.setAttribute(ATTR_NAME, context);
				this.delegate.saveContext(context, request, response);
			}

			@Override
			public boolean containsContext(HttpServletRequest request) {
				return getContext(request) != null || this.delegate.containsContext(request);
			}

			private static SecurityContext getContext(HttpServletRequest request) {
				return (SecurityContext) request.getAttribute(ATTR_NAME);
			}

		}

	}

	/**
	 * Associates the {@link SecurityContext} found in
	 * {@link TestSecurityContextHolder#getContext()} with the
	 * {@link MockHttpServletRequest}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	private final static class TestSecurityContextHolderPostProcessor extends SecurityContextRequestPostProcessorSupport
			implements RequestPostProcessor {

		private SecurityContext EMPTY = SecurityContextHolder.createEmptyContext();

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			// TestSecurityContextHolder is only a default value
			SecurityContext existingContext = TestSecurityContextRepository.getContext(request);
			if (existingContext != null) {
				return request;
			}

			SecurityContext context = TestSecurityContextHolder.getContext();
			if (!this.EMPTY.equals(context)) {
				save(context, request);
			}

			return request;
		}

	}

	/**
	 * Associates the specified {@link SecurityContext} with the
	 * {@link MockHttpServletRequest}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	private final static class SecurityContextRequestPostProcessor extends SecurityContextRequestPostProcessorSupport
			implements RequestPostProcessor {

		private final SecurityContext securityContext;

		private SecurityContextRequestPostProcessor(SecurityContext securityContext) {
			this.securityContext = securityContext;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			save(this.securityContext, request);
			return request;
		}

	}

	/**
	 * Sets the specified {@link Authentication} on an empty {@link SecurityContext} and
	 * associates it to the {@link MockHttpServletRequest}
	 *
	 * @author Rob Winch
	 * @since 4.0
	 *
	 */
	private final static class AuthenticationRequestPostProcessor extends SecurityContextRequestPostProcessorSupport
			implements RequestPostProcessor {

		private final Authentication authentication;

		private AuthenticationRequestPostProcessor(Authentication authentication) {
			this.authentication = authentication;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(this.authentication);
			save(this.authentication, request);
			return request;
		}

	}

	/**
	 * Creates a {@link UsernamePasswordAuthenticationToken} and sets the
	 * {@link UserDetails} as the principal and associates it to the
	 * {@link MockHttpServletRequest}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	private final static class UserDetailsRequestPostProcessor implements RequestPostProcessor {

		private final RequestPostProcessor delegate;

		UserDetailsRequestPostProcessor(UserDetails user) {
			Authentication token = new UsernamePasswordAuthenticationToken(user, user.getPassword(),
					user.getAuthorities());

			this.delegate = new AuthenticationRequestPostProcessor(token);
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			return this.delegate.postProcessRequest(request);
		}

	}

	/**
	 * Creates a {@link UsernamePasswordAuthenticationToken} and sets the principal to be
	 * a {@link User} and associates it to the {@link MockHttpServletRequest}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	public final static class UserRequestPostProcessor extends SecurityContextRequestPostProcessorSupport
			implements RequestPostProcessor {

		private String username;

		private String password = "password";

		private static final String ROLE_PREFIX = "ROLE_";

		private Collection<? extends GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

		private boolean enabled = true;

		private boolean accountNonExpired = true;

		private boolean credentialsNonExpired = true;

		private boolean accountNonLocked = true;

		/**
		 * Creates a new instance with the given username
		 * @param username the username to use
		 */
		private UserRequestPostProcessor(String username) {
			Assert.notNull(username, "username cannot be null");
			this.username = username;
		}

		/**
		 * Specify the roles of the user to authenticate as. This method is similar to
		 * {@link #authorities(GrantedAuthority...)}, but just not as flexible.
		 * @param roles The roles to populate. Note that if the role does not start with
		 * {@link #ROLE_PREFIX} it will automatically be prepended. This means by default
		 * {@code roles("ROLE_USER")} and {@code roles("USER")} are equivalent.
		 * @return the UserRequestPostProcessor for further customizations
		 * @see #authorities(GrantedAuthority...)
		 * @see #ROLE_PREFIX
		 */
		public UserRequestPostProcessor roles(String... roles) {
			List<GrantedAuthority> authorities = new ArrayList<>(roles.length);
			for (String role : roles) {
				if (role.startsWith(ROLE_PREFIX)) {
					throw new IllegalArgumentException("Role should not start with " + ROLE_PREFIX
							+ " since this method automatically prefixes with this value. Got " + role);
				}
				else {
					authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role));
				}
			}
			this.authorities = authorities;
			return this;
		}

		/**
		 * Populates the user's {@link GrantedAuthority}'s. The default is ROLE_USER.
		 * @param authorities
		 * @return the UserRequestPostProcessor for further customizations
		 * @see #roles(String...)
		 */
		public UserRequestPostProcessor authorities(GrantedAuthority... authorities) {
			return authorities(Arrays.asList(authorities));
		}

		/**
		 * Populates the user's {@link GrantedAuthority}'s. The default is ROLE_USER.
		 * @param authorities
		 * @return the UserRequestPostProcessor for further customizations
		 * @see #roles(String...)
		 */
		public UserRequestPostProcessor authorities(Collection<? extends GrantedAuthority> authorities) {
			this.authorities = authorities;
			return this;
		}

		/**
		 * Populates the user's password. The default is "password"
		 * @param password the user's password
		 * @return the UserRequestPostProcessor for further customizations
		 */
		public UserRequestPostProcessor password(String password) {
			this.password = password;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			UserDetailsRequestPostProcessor delegate = new UserDetailsRequestPostProcessor(createUser());
			return delegate.postProcessRequest(request);
		}

		/**
		 * Creates a new {@link User}
		 * @return the {@link User} for the principal
		 */
		private User createUser() {
			return new User(this.username, this.password, this.enabled, this.accountNonExpired,
					this.credentialsNonExpired, this.accountNonLocked, this.authorities);
		}

	}

	private static class AnonymousRequestPostProcessor extends SecurityContextRequestPostProcessorSupport
			implements RequestPostProcessor {

		private AuthenticationRequestPostProcessor delegate = new AuthenticationRequestPostProcessor(
				new AnonymousAuthenticationToken("key", "anonymous",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			return this.delegate.postProcessRequest(request);
		}

	}

	private static final class HttpBasicRequestPostProcessor implements RequestPostProcessor {

		private String headerValue;

		private HttpBasicRequestPostProcessor(String username, String password) {
			byte[] toEncode;
			toEncode = (username + ":" + password).getBytes(StandardCharsets.UTF_8);
			this.headerValue = "Basic " + new String(Base64.getEncoder().encode(toEncode));
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			request.addHeader("Authorization", this.headerValue);
			return request;
		}

	}

	/**
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 * @author Josh Cummings
	 * @since 5.2
	 */
	public final static class JwtRequestPostProcessor implements RequestPostProcessor {

		private Jwt jwt;

		private Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter = new JwtGrantedAuthoritiesConverter();

		private JwtRequestPostProcessor() {
			this.jwt((jwt) -> {
			});
		}

		/**
		 * Use the given {@link Jwt.Builder} {@link Consumer} to configure the underlying
		 * {@link Jwt}
		 *
		 * This method first creates a default {@link Jwt.Builder} instance with default
		 * values for the {@code alg}, {@code sub}, and {@code scope} claims. The
		 * {@link Consumer} can then modify these or provide additional configuration.
		 *
		 * Calling {@link SecurityMockMvcRequestPostProcessors#jwt()} is the equivalent of
		 * calling {@code SecurityMockMvcRequestPostProcessors.jwt().jwt(() -> {})}.
		 * @param jwtBuilderConsumer For configuring the underlying {@link Jwt}
		 * @return the {@link JwtRequestPostProcessor} for additional customization
		 */
		public JwtRequestPostProcessor jwt(Consumer<Jwt.Builder> jwtBuilderConsumer) {
			Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").header("alg", "none").claim(SUB, "user").claim("scope",
					"read");
			jwtBuilderConsumer.accept(jwtBuilder);
			this.jwt = jwtBuilder.build();
			return this;
		}

		/**
		 * Use the given {@link Jwt}
		 * @param jwt The {@link Jwt} to use
		 * @return the {@link JwtRequestPostProcessor} for additional customization
		 */
		public JwtRequestPostProcessor jwt(Jwt jwt) {
			this.jwt = jwt;
			return this;
		}

		/**
		 * Use the provided authorities in the token
		 * @param authorities the authorities to use
		 * @return the {@link JwtRequestPostProcessor} for further configuration
		 */
		public JwtRequestPostProcessor authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authoritiesConverter = jwt -> authorities;
			return this;
		}

		/**
		 * Use the provided authorities in the token
		 * @param authorities the authorities to use
		 * @return the {@link JwtRequestPostProcessor} for further configuration
		 */
		public JwtRequestPostProcessor authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authoritiesConverter = jwt -> Arrays.asList(authorities);
			return this;
		}

		/**
		 * Provides the configured {@link Jwt} so that custom authorities can be derived
		 * from it
		 * @param authoritiesConverter the conversion strategy from {@link Jwt} to a
		 * {@link Collection} of {@link GrantedAuthority}s
		 * @return the {@link JwtRequestPostProcessor} for further configuration
		 */
		public JwtRequestPostProcessor authorities(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			Assert.notNull(authoritiesConverter, "authoritiesConverter cannot be null");
			this.authoritiesConverter = authoritiesConverter;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			CsrfFilter.skipRequest(request);
			JwtAuthenticationToken token = new JwtAuthenticationToken(this.jwt,
					this.authoritiesConverter.convert(this.jwt));
			return new AuthenticationRequestPostProcessor(token).postProcessRequest(request);
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OpaqueTokenRequestPostProcessor implements RequestPostProcessor {

		private Supplier<Map<String, Object>> attributes = this::defaultAttributes;

		private Supplier<Collection<GrantedAuthority>> authorities = this::defaultAuthorities;

		private Supplier<OAuth2AuthenticatedPrincipal> principal = this::defaultPrincipal;

		private OpaqueTokenRequestPostProcessor() {
		}

		/**
		 * Mutate the attributes using the given {@link Consumer}
		 * @param attributesConsumer The {@link Consumer} for mutating the {@Map} of
		 * attributes
		 * @return the {@link OpaqueTokenRequestPostProcessor} for further configuration
		 */
		public OpaqueTokenRequestPostProcessor attributes(Consumer<Map<String, Object>> attributesConsumer) {
			Assert.notNull(attributesConsumer, "attributesConsumer cannot be null");
			this.attributes = () -> {
				Map<String, Object> attributes = defaultAttributes();
				attributesConsumer.accept(attributes);
				return attributes;
			};
			this.principal = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the resulting principal
		 * @param authorities the authorities to use
		 * @return the {@link OpaqueTokenRequestPostProcessor} for further configuration
		 */
		public OpaqueTokenRequestPostProcessor authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> authorities;
			this.principal = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the resulting principal
		 * @param authorities the authorities to use
		 * @return the {@link OpaqueTokenRequestPostProcessor} for further configuration
		 */
		public OpaqueTokenRequestPostProcessor authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> Arrays.asList(authorities);
			this.principal = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided principal
		 * @param principal the principal to use
		 * @return the {@link OpaqueTokenRequestPostProcessor} for further configuration
		 */
		public OpaqueTokenRequestPostProcessor principal(OAuth2AuthenticatedPrincipal principal) {
			Assert.notNull(principal, "principal cannot be null");
			this.principal = () -> principal;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			CsrfFilter.skipRequest(request);
			OAuth2AuthenticatedPrincipal principal = this.principal.get();
			OAuth2AccessToken accessToken = getOAuth2AccessToken(principal);
			BearerTokenAuthentication token = new BearerTokenAuthentication(principal, accessToken,
					principal.getAuthorities());
			return new AuthenticationRequestPostProcessor(token).postProcessRequest(request);
		}

		private Map<String, Object> defaultAttributes() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put(OAuth2IntrospectionClaimNames.SUBJECT, "user");
			attributes.put(OAuth2IntrospectionClaimNames.SCOPE, "read");
			return attributes;
		}

		private Collection<GrantedAuthority> defaultAuthorities() {
			Map<String, Object> attributes = this.attributes.get();
			Object scope = attributes.get(OAuth2IntrospectionClaimNames.SCOPE);
			if (scope == null) {
				return Collections.emptyList();
			}
			if (scope instanceof Collection) {
				return getAuthorities((Collection) scope);
			}
			String scopes = scope.toString();
			if (StringUtils.isBlank(scopes)) {
				return Collections.emptyList();
			}
			return getAuthorities(Arrays.asList(scopes.split(" ")));
		}

		private OAuth2AuthenticatedPrincipal defaultPrincipal() {
			return new OAuth2IntrospectionAuthenticatedPrincipal(this.attributes.get(), this.authorities.get());
		}

		private Collection<GrantedAuthority> getAuthorities(Collection<?> scopes) {
			return scopes.stream().map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
					.collect(Collectors.toList());
		}

		private OAuth2AccessToken getOAuth2AccessToken(OAuth2AuthenticatedPrincipal principal) {
			Instant expiresAt = getInstant(principal.getAttributes(), "exp");
			Instant issuedAt = getInstant(principal.getAttributes(), "iat");
			return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token", issuedAt, expiresAt);
		}

		private Instant getInstant(Map<String, Object> attributes, String name) {
			Object value = attributes.get(name);
			if (value == null) {
				return null;
			}
			if (value instanceof Instant) {
				return (Instant) value;
			}
			throw new IllegalArgumentException(name + " attribute must be of type Instant");
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OAuth2LoginRequestPostProcessor implements RequestPostProcessor {

		private final String nameAttributeKey = "sub";

		private ClientRegistration clientRegistration;

		private OAuth2AccessToken accessToken;

		private Supplier<Collection<GrantedAuthority>> authorities = this::defaultAuthorities;

		private Supplier<Map<String, Object>> attributes = this::defaultAttributes;

		private Supplier<OAuth2User> oauth2User = this::defaultPrincipal;

		private OAuth2LoginRequestPostProcessor(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			this.clientRegistration = clientRegistrationBuilder().build();
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OAuth2LoginRequestPostProcessor} for further configuration
		 */
		public OAuth2LoginRequestPostProcessor authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> authorities;
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OAuth2LoginRequestPostProcessor} for further configuration
		 */
		public OAuth2LoginRequestPostProcessor authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> Arrays.asList(authorities);
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Mutate the attributes using the given {@link Consumer}
		 * @param attributesConsumer The {@link Consumer} for mutating the {@Map} of
		 * attributes
		 * @return the {@link OAuth2LoginRequestPostProcessor} for further configuration
		 */
		public OAuth2LoginRequestPostProcessor attributes(Consumer<Map<String, Object>> attributesConsumer) {
			Assert.notNull(attributesConsumer, "attributesConsumer cannot be null");
			this.attributes = () -> {
				Map<String, Object> attributes = defaultAttributes();
				attributesConsumer.accept(attributes);
				return attributes;
			};
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OAuth2User} as the authenticated user.
		 * @param oauth2User the {@link OAuth2User} to use
		 * @return the {@link OAuth2LoginRequestPostProcessor} for further configuration
		 */
		public OAuth2LoginRequestPostProcessor oauth2User(OAuth2User oauth2User) {
			this.oauth2User = () -> oauth2User;
			return this;
		}

		/**
		 * Use the provided {@link ClientRegistration} as the client to authorize.
		 *
		 * The supplied {@link ClientRegistration} will be registered into an
		 * {@link HttpSessionOAuth2AuthorizedClientRepository}. Tests relying on
		 * {@link org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient}
		 * annotations should register an
		 * {@link HttpSessionOAuth2AuthorizedClientRepository} bean to the application
		 * context.
		 * @param clientRegistration the {@link ClientRegistration} to use
		 * @return the {@link OAuth2LoginRequestPostProcessor} for further configuration
		 */
		public OAuth2LoginRequestPostProcessor clientRegistration(ClientRegistration clientRegistration) {
			this.clientRegistration = clientRegistration;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			OAuth2User oauth2User = this.oauth2User.get();
			OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(),
					this.clientRegistration.getRegistrationId());

			request = new AuthenticationRequestPostProcessor(token).postProcessRequest(request);
			return new OAuth2ClientRequestPostProcessor().clientRegistration(this.clientRegistration)
					.principalName(oauth2User.getName()).accessToken(this.accessToken).postProcessRequest(request);
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId("test").authorizationGrantType(AuthorizationGrantType.PASSWORD)
					.clientId("test-client").tokenUri("https://token-uri.example.org");
		}

		private Collection<GrantedAuthority> defaultAuthorities() {
			Set<GrantedAuthority> authorities = new LinkedHashSet<>();
			authorities.add(new OAuth2UserAuthority(this.attributes.get()));
			for (String authority : this.accessToken.getScopes()) {
				authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
			}
			return authorities;
		}

		private Map<String, Object> defaultAttributes() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put(this.nameAttributeKey, "user");
			return attributes;
		}

		private OAuth2User defaultPrincipal() {
			return new DefaultOAuth2User(this.authorities.get(), this.attributes.get(), this.nameAttributeKey);
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OidcLoginRequestPostProcessor implements RequestPostProcessor {

		private ClientRegistration clientRegistration;

		private OAuth2AccessToken accessToken;

		private OidcIdToken idToken;

		private OidcUserInfo userInfo;

		private Supplier<OidcUser> oidcUser = this::defaultPrincipal;

		private Collection<GrantedAuthority> authorities;

		private OidcLoginRequestPostProcessor(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			this.clientRegistration = clientRegistrationBuilder().build();
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OidcLoginRequestPostProcessor} for further configuration
		 */
		public OidcLoginRequestPostProcessor authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = authorities;
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OidcLoginRequestPostProcessor} for further configuration
		 */
		public OidcLoginRequestPostProcessor authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = Arrays.asList(authorities);
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OidcIdToken} when constructing the authenticated user
		 * @param idTokenBuilderConsumer a {@link Consumer} of a
		 * {@link OidcIdToken.Builder}
		 * @return the {@link OidcLoginRequestPostProcessor} for further configuration
		 */
		public OidcLoginRequestPostProcessor idToken(Consumer<OidcIdToken.Builder> idTokenBuilderConsumer) {
			OidcIdToken.Builder builder = OidcIdToken.withTokenValue("id-token");
			builder.subject("user");
			idTokenBuilderConsumer.accept(builder);
			this.idToken = builder.build();
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OidcUserInfo} when constructing the authenticated user
		 * @param userInfoBuilderConsumer a {@link Consumer} of a
		 * {@link OidcUserInfo.Builder}
		 * @return the {@link OidcLoginRequestPostProcessor} for further configuration
		 */
		public OidcLoginRequestPostProcessor userInfoToken(Consumer<OidcUserInfo.Builder> userInfoBuilderConsumer) {
			OidcUserInfo.Builder builder = OidcUserInfo.builder();
			userInfoBuilderConsumer.accept(builder);
			this.userInfo = builder.build();
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OidcUser} as the authenticated user.
		 * @param oidcUser the {@link OidcUser} to use
		 * @return the {@link OidcLoginRequestPostProcessor} for further configuration
		 */
		public OidcLoginRequestPostProcessor oidcUser(OidcUser oidcUser) {
			this.oidcUser = () -> oidcUser;
			return this;
		}

		/**
		 * Use the provided {@link ClientRegistration} as the client to authorize.
		 *
		 * The supplied {@link ClientRegistration} will be registered into an
		 * {@link HttpSessionOAuth2AuthorizedClientRepository}. Tests relying on
		 * {@link org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient}
		 * annotations should register an
		 * {@link HttpSessionOAuth2AuthorizedClientRepository} bean to the application
		 * context.
		 * @param clientRegistration the {@link ClientRegistration} to use
		 * @return the {@link OidcLoginRequestPostProcessor} for further configuration
		 */
		public OidcLoginRequestPostProcessor clientRegistration(ClientRegistration clientRegistration) {
			this.clientRegistration = clientRegistration;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			OidcUser oidcUser = this.oidcUser.get();
			return new OAuth2LoginRequestPostProcessor(this.accessToken).oauth2User(oidcUser)
					.clientRegistration(this.clientRegistration).postProcessRequest(request);
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId("test").authorizationGrantType(AuthorizationGrantType.PASSWORD)
					.clientId("test-client").tokenUri("https://token-uri.example.org");
		}

		private Collection<GrantedAuthority> getAuthorities() {
			if (this.authorities == null) {
				Set<GrantedAuthority> authorities = new LinkedHashSet<>();
				authorities.add(new OidcUserAuthority(getOidcIdToken(), getOidcUserInfo()));
				for (String authority : this.accessToken.getScopes()) {
					authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
				}
				return authorities;
			}
			else {
				return this.authorities;
			}
		}

		private OidcIdToken getOidcIdToken() {
			if (this.idToken == null) {
				return new OidcIdToken("id-token", null, null, Collections.singletonMap(IdTokenClaimNames.SUB, "user"));
			}
			else {
				return this.idToken;
			}
		}

		private OidcUserInfo getOidcUserInfo() {
			return this.userInfo;
		}

		private OidcUser defaultPrincipal() {
			return new DefaultOidcUser(getAuthorities(), getOidcIdToken(), this.userInfo);
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OAuth2ClientRequestPostProcessor implements RequestPostProcessor {

		private String registrationId = "test";

		private ClientRegistration clientRegistration;

		private String principalName = "user";

		private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token", null, null, Collections.singleton("read"));

		private OAuth2ClientRequestPostProcessor() {
		}

		private OAuth2ClientRequestPostProcessor(String registrationId) {
			this.registrationId = registrationId;
			clientRegistration(c -> {
			});
		}

		/**
		 * Use this {@link ClientRegistration}
		 * @param clientRegistration
		 * @return the {@link OAuth2ClientRequestPostProcessor} for further configuration
		 */
		public OAuth2ClientRequestPostProcessor clientRegistration(ClientRegistration clientRegistration) {
			this.clientRegistration = clientRegistration;
			return this;
		}

		/**
		 * Use this {@link Consumer} to configure a {@link ClientRegistration}
		 * @param clientRegistrationConfigurer the {@link ClientRegistration} configurer
		 * @return the {@link OAuth2ClientRequestPostProcessor} for further configuration
		 */
		public OAuth2ClientRequestPostProcessor clientRegistration(
				Consumer<ClientRegistration.Builder> clientRegistrationConfigurer) {

			ClientRegistration.Builder builder = clientRegistrationBuilder();
			clientRegistrationConfigurer.accept(builder);
			this.clientRegistration = builder.build();
			return this;
		}

		/**
		 * Use this as the resource owner's principal name
		 * @param principalName the resource owner's principal name
		 * @return the {@link OAuth2ClientRequestPostProcessor} for further configuration
		 */
		public OAuth2ClientRequestPostProcessor principalName(String principalName) {
			Assert.notNull(principalName, "principalName cannot be null");
			this.principalName = principalName;
			return this;
		}

		/**
		 * Use this {@link OAuth2AccessToken}
		 * @param accessToken the {@link OAuth2AccessToken} to use
		 * @return the {@link OAuth2ClientRequestPostProcessor} for further configuration
		 */
		public OAuth2ClientRequestPostProcessor accessToken(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			if (this.clientRegistration == null) {
				throw new IllegalArgumentException(
						"Please specify a ClientRegistration via one " + "of the clientRegistration methods");
			}
			OAuth2AuthorizedClient client = new OAuth2AuthorizedClient(this.clientRegistration, this.principalName,
					this.accessToken);

			OAuth2AuthorizedClientManager authorizationClientManager = OAuth2ClientServletTestUtils
					.getOAuth2AuthorizedClientManager(request);
			if (!(authorizationClientManager instanceof TestOAuth2AuthorizedClientManager)) {
				authorizationClientManager = new TestOAuth2AuthorizedClientManager(authorizationClientManager);
				OAuth2ClientServletTestUtils.setOAuth2AuthorizedClientManager(request, authorizationClientManager);
			}
			TestOAuth2AuthorizedClientManager.enable(request);
			request.setAttribute(TestOAuth2AuthorizedClientManager.TOKEN_ATTR_NAME, client);
			return request;
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId(this.registrationId)
					.authorizationGrantType(AuthorizationGrantType.PASSWORD).clientId("test-client")
					.clientSecret("test-secret").tokenUri("https://idp.example.org/oauth/token");
		}

		/**
		 * Used to wrap the {@link OAuth2AuthorizedClientManager} to provide support for
		 * testing when the request is wrapped
		 */
		private static final class TestOAuth2AuthorizedClientManager implements OAuth2AuthorizedClientManager {

			final static String TOKEN_ATTR_NAME = TestOAuth2AuthorizedClientManager.class.getName().concat(".TOKEN");

			final static String ENABLED_ATTR_NAME = TestOAuth2AuthorizedClientManager.class.getName()
					.concat(".ENABLED");

			private final OAuth2AuthorizedClientManager delegate;

			private TestOAuth2AuthorizedClientManager(OAuth2AuthorizedClientManager delegate) {
				this.delegate = delegate;
			}

			@Override
			public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
				HttpServletRequest request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
				if (isEnabled(request)) {
					return (OAuth2AuthorizedClient) request.getAttribute(TOKEN_ATTR_NAME);
				}
				else {
					return this.delegate.authorize(authorizeRequest);
				}
			}

			public static void enable(HttpServletRequest request) {
				request.setAttribute(ENABLED_ATTR_NAME, TRUE);
			}

			public boolean isEnabled(HttpServletRequest request) {
				return TRUE.equals(request.getAttribute(ENABLED_ATTR_NAME));
			}

		}

		private static final class OAuth2ClientServletTestUtils {

			private static final OAuth2AuthorizedClientRepository DEFAULT_CLIENT_REPO = new HttpSessionOAuth2AuthorizedClientRepository();

			/**
			 * Gets the {@link OAuth2AuthorizedClientManager} for the specified
			 * {@link HttpServletRequest}. If one is not found, one based off of
			 * {@link HttpSessionOAuth2AuthorizedClientRepository} is used.
			 * @param request the {@link HttpServletRequest} to obtain the
			 * {@link OAuth2AuthorizedClientManager}
			 * @return the {@link OAuth2AuthorizedClientManager} for the specified
			 * {@link HttpServletRequest}
			 */
			public static OAuth2AuthorizedClientManager getOAuth2AuthorizedClientManager(HttpServletRequest request) {
				OAuth2AuthorizedClientArgumentResolver resolver = findResolver(request,
						OAuth2AuthorizedClientArgumentResolver.class);
				if (resolver == null) {
					return authorizeRequest -> DEFAULT_CLIENT_REPO.loadAuthorizedClient(
							authorizeRequest.getClientRegistrationId(), authorizeRequest.getPrincipal(), request);
				}
				return (OAuth2AuthorizedClientManager) ReflectionTestUtils.getField(resolver,
						"authorizedClientManager");
			}

			/**
			 * Sets the {@link OAuth2AuthorizedClientManager} for the specified
			 * {@link HttpServletRequest}.
			 * @param request the {@link HttpServletRequest} to obtain the
			 * {@link OAuth2AuthorizedClientManager}
			 * @param manager the {@link OAuth2AuthorizedClientManager} to set
			 */
			public static void setOAuth2AuthorizedClientManager(HttpServletRequest request,
					OAuth2AuthorizedClientManager manager) {
				OAuth2AuthorizedClientArgumentResolver resolver = findResolver(request,
						OAuth2AuthorizedClientArgumentResolver.class);
				if (resolver == null) {
					return;
				}
				ReflectionTestUtils.setField(resolver, "authorizedClientManager", manager);
			}

			@SuppressWarnings("unchecked")
			static <T extends HandlerMethodArgumentResolver> T findResolver(HttpServletRequest request,
					Class<T> resolverClass) {
				if (!ClassUtils.isPresent(
						"org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter", null)) {
					return null;
				}
				return WebMvcClasspathGuard.findResolver(request, resolverClass);
			}

			private static class WebMvcClasspathGuard {

				static <T extends HandlerMethodArgumentResolver> T findResolver(HttpServletRequest request,
						Class<T> resolverClass) {
					ServletContext servletContext = request.getServletContext();
					RequestMappingHandlerAdapter mapping = getRequestMappingHandlerAdapter(servletContext);
					if (mapping == null) {
						return null;
					}
					List<HandlerMethodArgumentResolver> resolvers = mapping.getCustomArgumentResolvers();
					if (resolvers == null) {
						return null;
					}
					for (HandlerMethodArgumentResolver resolver : resolvers) {
						if (resolverClass.isAssignableFrom(resolver.getClass())) {
							return (T) resolver;
						}
					}
					return null;
				}

				private static RequestMappingHandlerAdapter getRequestMappingHandlerAdapter(
						ServletContext servletContext) {
					WebApplicationContext context = WebApplicationContextUtils.getWebApplicationContext(servletContext);
					if (context != null) {
						String[] names = context.getBeanNamesForType(RequestMappingHandlerAdapter.class);
						if (names.length > 0) {
							return (RequestMappingHandlerAdapter) context.getBean(names[0]);
						}
					}
					return null;
				}

			}

			private OAuth2ClientServletTestUtils() {
			}

		}

	}

	private SecurityMockMvcRequestPostProcessors() {
	}

}
