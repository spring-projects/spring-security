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

package org.springframework.security.config.annotation.web.configurers.saml2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Assertion;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.saml2.core.TestSaml2X509Credentials.relyingPartyVerifyingCredential;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationRequestContexts.authenticationRequestContext;
import static org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations.noCredentials;
import static org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations.relyingPartyRegistration;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for different Java configuration for {@link Saml2LoginConfigurer}
 */
public class Saml2LoginConfigurerTests {

	private static final Converter<Assertion, Collection<? extends GrantedAuthority>>
			AUTHORITIES_EXTRACTOR = a -> Arrays.asList(new SimpleGrantedAuthority("TEST"));
	private static final GrantedAuthoritiesMapper AUTHORITIES_MAPPER =
			authorities -> Arrays.asList(new SimpleGrantedAuthority("TEST CONVERTED"));
	private static final Duration RESPONSE_TIME_VALIDATION_SKEW = Duration.ZERO;
	private static final String SIGNED_RESPONSE =
			"PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9ycC5leGFtcGxlLm9yZy9hY3MiIElEPSJfYzE3MzM2YTAtNTM1My00MTQ5LWI3MmMtMDNkOWY5YWYzMDdlIiBJc3N1ZUluc3RhbnQ9IjIwMjAtMDgtMDRUMjI6MDQ6NDUuMDE2WiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5hcC1lbnRpdHktaWQ8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4KPGRzOlNpZ25lZEluZm8+CjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+CjxkczpSZWZlcmVuY2UgVVJJPSIjX2MxNzMzNmEwLTUzNTMtNDE0OS1iNzJjLTAzZDlmOWFmMzA3ZSI+CjxkczpUcmFuc2Zvcm1zPgo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgo8L2RzOlRyYW5zZm9ybXM+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4KPGRzOkRpZ2VzdFZhbHVlPjYzTmlyenFzaDVVa0h1a3NuRWUrM0hWWU5aYWFsQW1OQXFMc1lGMlRuRDA9PC9kczpEaWdlc3RWYWx1ZT4KPC9kczpSZWZlcmVuY2U+CjwvZHM6U2lnbmVkSW5mbz4KPGRzOlNpZ25hdHVyZVZhbHVlPgpLMVlvWWJVUjBTclY4RTdVMkhxTTIvZUNTOTNoV25mOExnNnozeGZWMUlyalgzSXhWYkNvMVlYcnRBSGRwRVdvYTJKKzVOMmFNbFBHJiMxMzsKN2VpbDBZRC9xdUVRamRYbTNwQTBjZmEvY25pa2RuKzVhbnM0ZWQwanU1amo2dkpvZ2w2Smt4Q25LWUpwTU9HNzhtampmb0phengrWCYjMTM7CkM2NktQVStBYUdxeGVwUEQ1ZlhRdTFKSy9Jb3lBaitaa3k4Z2Jwc3VyZHFCSEJLRWxjdnVOWS92UGY0OGtBeFZBKzdtRGhNNUMvL1AmIzEzOwp0L084Y3NZYXB2UjZjdjZrdk45QXZ1N3FRdm9qVk1McHVxZWNJZDJwTUVYb0NSSnE2Nkd4MStNTUVPeHVpMWZZQlRoMEhhYjRmK3JyJiMxMzsKOEY2V1NFRC8xZllVeHliRkJqZ1Q4d2lEWHFBRU8wSVY4ZWRQeEE9PQo8L2RzOlNpZ25hdHVyZVZhbHVlPgo8L2RzOlNpZ25hdHVyZT48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iQWUzZjQ5OGI4LTliMTctNDA3OC05ZDM1LTg2YTA4NDA4NDk5NSIgSXNzdWVJbnN0YW50PSIyMDIwLTA4LTA0VDIyOjA0OjQ1LjA3N1oiIFZlcnNpb249IjIuMCI+PHNhbWwyOklzc3Vlcj5hcC1lbnRpdHktaWQ8L3NhbWwyOklzc3Vlcj48c2FtbDI6U3ViamVjdD48c2FtbDI6TmFtZUlEPnRlc3RAc2FtbC51c2VyPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90QmVmb3JlPSIyMDIwLTA4LTA0VDIxOjU5OjQ1LjA5MFoiIE5vdE9uT3JBZnRlcj0iMjA0MC0wNy0zMFQyMjowNTowNi4wODhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vcnAuZXhhbXBsZS5vcmcvYWNzIi8+PC9zYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDI6U3ViamVjdD48c2FtbDI6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjAtMDgtMDRUMjE6NTk6NDUuMDgwWiIgTm90T25PckFmdGVyPSIyMDQwLTA3LTMwVDIyOjA1OjA2LjA4N1oiLz48L3NhbWwyOkFzc2VydGlvbj48L3NhbWwycDpSZXNwb25zZT4=";

	@Autowired
	private ConfigurableApplicationContext context;

	@Autowired
	private FilterChainProxy springSecurityFilterChain;

	@Autowired
	private RelyingPartyRegistrationRepository repository;

	@Autowired
	SecurityContextRepository securityContextRepository;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired(required = false)
	MockMvc mvc;

	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private MockFilterChain filterChain;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest("POST", "");
		this.request.setServletPath("/login/saml2/sso/test-rp");
		this.response = new MockHttpServletResponse();
		this.filterChain = new MockFilterChain();
	}

	@After
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void saml2LoginWhenConfiguringAuthenticationManagerThenTheManagerIsUsed() throws Exception {
		// setup application context
		this.spring.register(Saml2LoginConfigWithCustomAuthenticationManager.class).autowire();
		performSaml2Login("ROLE_AUTH_MANAGER");
	}

	@Test
	public void saml2LoginWhenConfiguringAuthenticationDefaultsUsingCustomizerThenTheProviderIsConfigured() throws Exception {
		// setup application context
		this.spring.register(Saml2LoginConfigWithAuthenticationDefaultsWithPostProcessor.class).autowire();
		validateSaml2WebSsoAuthenticationFilterConfiguration();
	}

	@Test
	public void saml2LoginWhenCustomAuthenticationRequestContextResolverThenUses() throws Exception {
		this.spring.register(CustomAuthenticationRequestContextResolver.class).autowire();

		Saml2AuthenticationRequestContext context = authenticationRequestContext().build();
		Saml2AuthenticationRequestContextResolver resolver =
				CustomAuthenticationRequestContextResolver.resolver;
		when(resolver.resolve(any(HttpServletRequest.class)))
				.thenReturn(context);
		this.mvc.perform(get("/saml2/authenticate/registration-id"))
				.andExpect(status().isFound());
		verify(resolver).resolve(any(HttpServletRequest.class));
	}

	@Test
	public void authenticationRequestWhenAuthnRequestConsumerResolverThenUses() throws Exception {
		this.spring.register(CustomAuthnRequestConsumerResolver.class).autowire();

		MvcResult result = this.mvc.perform(get("/saml2/authenticate/registration-id"))
				.andReturn();
		UriComponents components = UriComponentsBuilder
				.fromHttpUrl(result.getResponse().getRedirectedUrl()).build();
		String samlRequest = components.getQueryParams().getFirst("SAMLRequest");
		String decoded = URLDecoder.decode(samlRequest, "UTF-8");
		String inflated = samlInflate(samlDecode(decoded));
		assertThat(inflated).contains("ForceAuthn=\"true\"");
	}

	@Test
	public void authenticateWhenCustomAuthenticationConverterThenUses() throws Exception {
		this.spring.register(CustomAuthenticationConverter.class).autowire();
		RelyingPartyRegistration relyingPartyRegistration = noCredentials()
				.assertingPartyDetails(party -> party
					.verificationX509Credentials(c -> c.add(relyingPartyVerifyingCredential()))
				)
				.build();
		String response = new String(samlDecode(SIGNED_RESPONSE));
		when(CustomAuthenticationConverter.authenticationConverter.convert(any(HttpServletRequest.class)))
				.thenReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		this.mvc.perform(post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId())
				.param("SAMLResponse", SIGNED_RESPONSE))
				.andExpect(redirectedUrl("/"));
		verify(CustomAuthenticationConverter.authenticationConverter).convert(any(HttpServletRequest.class));
	}

	private void validateSaml2WebSsoAuthenticationFilterConfiguration() {
		// get the OpenSamlAuthenticationProvider
		Saml2WebSsoAuthenticationFilter filter = getSaml2SsoFilter(this.springSecurityFilterChain);
		AuthenticationManager manager =
				(AuthenticationManager) ReflectionTestUtils.getField(filter, "authenticationManager");
		ProviderManager pm = (ProviderManager) manager;
		AuthenticationProvider provider = pm.getProviders()
				.stream()
				.filter(p -> p instanceof OpenSamlAuthenticationProvider)
				.findFirst()
				.get();
		Assert.assertSame(AUTHORITIES_EXTRACTOR, ReflectionTestUtils.getField(provider, "authoritiesExtractor"));
		Assert.assertSame(AUTHORITIES_MAPPER, ReflectionTestUtils.getField(provider, "authoritiesMapper"));
		Assert.assertSame(RESPONSE_TIME_VALIDATION_SKEW, ReflectionTestUtils.getField(provider, "responseTimeValidationSkew"));
	}

	private Saml2WebSsoAuthenticationFilter getSaml2SsoFilter(FilterChainProxy chain) {
		return (Saml2WebSsoAuthenticationFilter) chain.getFilters("/login/saml2/sso/test")
				.stream()
				.filter(f -> f instanceof Saml2WebSsoAuthenticationFilter)
				.findFirst()
				.get();
	}

	private void performSaml2Login(String expected) throws IOException, ServletException {
		// setup authentication parameters
		this.request.setParameter(
				"SAMLResponse",
				Base64.getEncoder().encodeToString(
						"saml2-xml-response-object".getBytes()
				)
		);


		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		Assert.assertNotNull("Expected a valid authentication object.", authentication);
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
				.isInstanceOf(SimpleGrantedAuthority.class).hasToString(expected);
	}


	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LoginConfigWithCustomAuthenticationManager extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.saml2Login()
				.authenticationManager(
						getAuthenticationManagerMock("ROLE_AUTH_MANAGER")
				);
			super.configure(http);
		}
	}

	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LoginConfigWithAuthenticationDefaultsWithPostProcessor extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			ObjectPostProcessor<OpenSamlAuthenticationProvider> processor
					= new ObjectPostProcessor<OpenSamlAuthenticationProvider>() {
				@Override
				public <O extends OpenSamlAuthenticationProvider> O postProcess(O provider) {
					provider.setResponseTimeValidationSkew(RESPONSE_TIME_VALIDATION_SKEW);
					provider.setAuthoritiesMapper(AUTHORITIES_MAPPER);
					provider.setAuthoritiesExtractor(AUTHORITIES_EXTRACTOR);
					return provider;
				}
			};

			http.saml2Login()
					.addObjectPostProcessor(processor)
			;
			super.configure(http);
		}
	}

	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationRequestContextResolver extends WebSecurityConfigurerAdapter {
		private static final Saml2AuthenticationRequestContextResolver resolver =
				mock(Saml2AuthenticationRequestContextResolver.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authz -> authz
						.anyRequest().authenticated()
				)
				.saml2Login(withDefaults());
			// @formatter:on
		}

		@Bean
		Saml2AuthenticationRequestContextResolver resolver() {
			return resolver;
		}
	}

	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthnRequestConsumerResolver extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authz -> authz
					.anyRequest().authenticated()
				)
				.saml2Login(saml2 -> {});
			// @formatter:on
		}

		@Bean
		Saml2AuthenticationRequestFactory authenticationRequestFactory() {
			OpenSamlAuthenticationRequestFactory authenticationRequestFactory =
					new OpenSamlAuthenticationRequestFactory();
			authenticationRequestFactory.setAuthnRequestConsumerResolver(
					context -> authnRequest -> authnRequest.setForceAuthn(true));
			return authenticationRequestFactory;
		}
	}

	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationConverter extends WebSecurityConfigurerAdapter {
		static final AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests(authz -> authz
					.anyRequest().authenticated()
				)
				.saml2Login(saml2 -> saml2
					.authenticationConverter(authenticationConverter)
				);
		}
	}

	private static AuthenticationManager getAuthenticationManagerMock(String role) {
		return new AuthenticationManager() {

			@Override
			public Authentication authenticate(Authentication authentication)
					throws AuthenticationException {
				if (!supports(authentication.getClass())) {
					throw new AuthenticationServiceException("not supported");
				}
				return new Saml2Authentication(
						() -> "auth principal",
						"saml2 response",
						Collections.singletonList(
								new SimpleGrantedAuthority(role)
						)
				);
			}

			public boolean supports(Class<?> authentication) {
				return authentication.isAssignableFrom(Saml2AuthenticationToken.class);
			}
		};
	}

	static class Saml2LoginConfigBeans {

		@Bean
		SecurityContextRepository securityContextRepository() {
			return new HttpSessionSecurityContextRepository();
		}

		@Bean
		RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
			RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);
			when(repository.findByRegistrationId(anyString()))
					.thenReturn(relyingPartyRegistration().build());
			return repository;
		}
	}

	private static org.apache.commons.codec.binary.Base64 BASE64 =
			new org.apache.commons.codec.binary.Base64(0, new byte[]{'\n'});

	private static byte[] samlDecode(String s) {
		return BASE64.decode(s);
	}

	private static String samlInflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
			iout.write(b);
			iout.finish();
			return new String(out.toByteArray(), UTF_8);
		}
		catch (IOException e) {
			throw new Saml2Exception("Unable to inflate string", e);
		}
	}
}
