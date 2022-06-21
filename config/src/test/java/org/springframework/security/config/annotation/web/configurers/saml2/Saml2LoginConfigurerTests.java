/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.IOException;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.Collections;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextChangedListener;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2Utils;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.annotation.SecurityContextChangedListenerArgumentMatchers.setAuthentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for different Java configuration for {@link Saml2LoginConfigurer}
 */
@ExtendWith(SpringTestContextExtension.class)
public class Saml2LoginConfigurerTests {

	private static final String SIGNED_RESPONSE = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9ycC5leGFtcGxlLm9yZy9hY3MiIElEPSJfYzE3MzM2YTAtNTM1My00MTQ5LWI3MmMtMDNkOWY5YWYzMDdlIiBJc3N1ZUluc3RhbnQ9IjIwMjAtMDgtMDRUMjI6MDQ6NDUuMDE2WiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5hcC1lbnRpdHktaWQ8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4KPGRzOlNpZ25lZEluZm8+CjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+CjxkczpSZWZlcmVuY2UgVVJJPSIjX2MxNzMzNmEwLTUzNTMtNDE0OS1iNzJjLTAzZDlmOWFmMzA3ZSI+CjxkczpUcmFuc2Zvcm1zPgo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgo8L2RzOlRyYW5zZm9ybXM+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4KPGRzOkRpZ2VzdFZhbHVlPjYzTmlyenFzaDVVa0h1a3NuRWUrM0hWWU5aYWFsQW1OQXFMc1lGMlRuRDA9PC9kczpEaWdlc3RWYWx1ZT4KPC9kczpSZWZlcmVuY2U+CjwvZHM6U2lnbmVkSW5mbz4KPGRzOlNpZ25hdHVyZVZhbHVlPgpLMVlvWWJVUjBTclY4RTdVMkhxTTIvZUNTOTNoV25mOExnNnozeGZWMUlyalgzSXhWYkNvMVlYcnRBSGRwRVdvYTJKKzVOMmFNbFBHJiMxMzsKN2VpbDBZRC9xdUVRamRYbTNwQTBjZmEvY25pa2RuKzVhbnM0ZWQwanU1amo2dkpvZ2w2Smt4Q25LWUpwTU9HNzhtampmb0phengrWCYjMTM7CkM2NktQVStBYUdxeGVwUEQ1ZlhRdTFKSy9Jb3lBaitaa3k4Z2Jwc3VyZHFCSEJLRWxjdnVOWS92UGY0OGtBeFZBKzdtRGhNNUMvL1AmIzEzOwp0L084Y3NZYXB2UjZjdjZrdk45QXZ1N3FRdm9qVk1McHVxZWNJZDJwTUVYb0NSSnE2Nkd4MStNTUVPeHVpMWZZQlRoMEhhYjRmK3JyJiMxMzsKOEY2V1NFRC8xZllVeHliRkJqZ1Q4d2lEWHFBRU8wSVY4ZWRQeEE9PQo8L2RzOlNpZ25hdHVyZVZhbHVlPgo8L2RzOlNpZ25hdHVyZT48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iQWUzZjQ5OGI4LTliMTctNDA3OC05ZDM1LTg2YTA4NDA4NDk5NSIgSXNzdWVJbnN0YW50PSIyMDIwLTA4LTA0VDIyOjA0OjQ1LjA3N1oiIFZlcnNpb249IjIuMCI+PHNhbWwyOklzc3Vlcj5hcC1lbnRpdHktaWQ8L3NhbWwyOklzc3Vlcj48c2FtbDI6U3ViamVjdD48c2FtbDI6TmFtZUlEPnRlc3RAc2FtbC51c2VyPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90QmVmb3JlPSIyMDIwLTA4LTA0VDIxOjU5OjQ1LjA5MFoiIE5vdE9uT3JBZnRlcj0iMjA0MC0wNy0zMFQyMjowNTowNi4wODhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vcnAuZXhhbXBsZS5vcmcvYWNzIi8+PC9zYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDI6U3ViamVjdD48c2FtbDI6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjAtMDgtMDRUMjE6NTk6NDUuMDgwWiIgTm90T25PckFmdGVyPSIyMDQwLTA3LTMwVDIyOjA1OjA2LjA4N1oiLz48L3NhbWwyOkFzc2VydGlvbj48L3NhbWwycDpSZXNwb25zZT4=";

	private static final AuthenticationConverter AUTHENTICATION_CONVERTER = mock(AuthenticationConverter.class);

	@Autowired
	private ConfigurableApplicationContext context;

	@Autowired
	private FilterChainProxy springSecurityFilterChain;

	@Autowired
	private RelyingPartyRegistrationRepository repository;

	@Autowired
	SecurityContextRepository securityContextRepository;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private MockFilterChain filterChain;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest("POST", "");
		this.request.setServletPath("/login/saml2/sso/test-rp");
		this.response = new MockHttpServletResponse();
		this.filterChain = new MockFilterChain();
	}

	@AfterEach
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void saml2LoginWhenDefaultsThenSaml2AuthenticatedPrincipal() throws Exception {
		this.spring.register(Saml2LoginConfig.class, ResourceController.class).autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc
				.perform(post("/login/saml2/sso/registration-id")
				.param("SAMLResponse", SIGNED_RESPONSE))
				.andExpect(redirectedUrl("/")).andReturn().getRequest().getSession(false);
		this.mvc.perform(get("/").session(session))
				.andExpect(content().string("test@saml.user"));
		// @formatter:on
	}

	@Test
	public void saml2LoginWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring
				.register(Saml2LoginConfig.class, SecurityContextChangedListenerConfig.class, ResourceController.class)
				.autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc
				.perform(post("/login/saml2/sso/registration-id")
						.param("SAMLResponse", SIGNED_RESPONSE))
				.andExpect(redirectedUrl("/")).andReturn().getRequest().getSession(false);
		this.mvc.perform(get("/").session(session))
				.andExpect(content().string("test@saml.user"));
		// @formatter:on
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		verify(strategy, atLeastOnce()).getContext();
		SecurityContextChangedListener listener = this.spring.getContext()
				.getBean(SecurityContextChangedListener.class);
		verify(listener, times(2)).securityContextChanged(setAuthentication(Saml2Authentication.class));
	}

	@Test
	public void saml2LoginWhenConfiguringAuthenticationManagerThenTheManagerIsUsed() throws Exception {
		// setup application context
		this.spring.register(Saml2LoginConfigWithCustomAuthenticationManager.class).autowire();
		performSaml2Login("ROLE_AUTH_MANAGER");
	}

	@Test
	public void saml2LoginWhenDefaultAndSamlAuthenticationManagerThenSamlManagerIsUsed() throws Exception {
		this.spring.register(Saml2LoginConfigWithDefaultAndCustomAuthenticationManager.class).autowire();
		performSaml2Login("ROLE_AUTH_MANAGER");
	}

	@Test
	public void authenticationRequestWhenAuthenticationRequestResolverBeanThenUses() throws Exception {
		this.spring.register(CustomAuthenticationRequestResolverBean.class).autowire();
		MvcResult result = this.mvc.perform(get("/saml2/authenticate/registration-id")).andReturn();
		UriComponents components = UriComponentsBuilder.fromHttpUrl(result.getResponse().getRedirectedUrl()).build();
		String samlRequest = components.getQueryParams().getFirst("SAMLRequest");
		String decoded = URLDecoder.decode(samlRequest, "UTF-8");
		String inflated = Saml2Utils.samlInflate(Saml2Utils.samlDecode(decoded));
		assertThat(inflated).contains("ForceAuthn=\"true\"");
	}

	@Test
	public void authenticationRequestWhenAuthenticationRequestResolverDslThenUses() throws Exception {
		this.spring.register(CustomAuthenticationRequestResolverDsl.class).autowire();
		MvcResult result = this.mvc.perform(get("/saml2/authenticate/registration-id")).andReturn();
		UriComponents components = UriComponentsBuilder.fromHttpUrl(result.getResponse().getRedirectedUrl()).build();
		String samlRequest = components.getQueryParams().getFirst("SAMLRequest");
		String decoded = URLDecoder.decode(samlRequest, "UTF-8");
		String inflated = Saml2Utils.samlInflate(Saml2Utils.samlDecode(decoded));
		assertThat(inflated).contains("ForceAuthn=\"true\"");
	}

	@Test
	public void authenticateWhenCustomAuthenticationConverterThenUses() throws Exception {
		this.spring.register(CustomAuthenticationConverter.class).autowire();
		RelyingPartyRegistration relyingPartyRegistration = this.repository.findByRegistrationId("registration-id");
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(CustomAuthenticationConverter.authenticationConverter.convert(any(HttpServletRequest.class)))
				.willReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId())
				.param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(redirectedUrl("/"));
		verify(CustomAuthenticationConverter.authenticationConverter).convert(any(HttpServletRequest.class));
	}

	@Test
	public void authenticateWhenCustomAuthenticationConverterBeanThenUses() throws Exception {
		this.spring.register(CustomAuthenticationConverterBean.class).autowire();
		Saml2AuthenticationTokenConverter authenticationConverter = this.spring.getContext()
				.getBean(Saml2AuthenticationTokenConverter.class);
		RelyingPartyRegistration relyingPartyRegistration = this.repository.findByRegistrationId("registration-id");
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(authenticationConverter.convert(any(HttpServletRequest.class)))
				.willReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId())
				.param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(redirectedUrl("/"));
		verify(authenticationConverter).convert(any(HttpServletRequest.class));
	}

	@Test
	public void authenticateWithInvalidDeflatedSAMLResponseThenFailureHandlerUses() throws Exception {
		this.spring.register(CustomAuthenticationFailureHandler.class).autowire();
		byte[] invalidDeflated = "invalid".getBytes();
		String encoded = Saml2Utils.samlEncode(invalidDeflated);
		MockHttpServletRequestBuilder request = get("/login/saml2/sso/registration-id").queryParam("SAMLResponse",
				encoded);
		this.mvc.perform(request);
		ArgumentCaptor<Saml2AuthenticationException> captor = ArgumentCaptor
				.forClass(Saml2AuthenticationException.class);
		verify(CustomAuthenticationFailureHandler.authenticationFailureHandler).onAuthenticationFailure(
				any(HttpServletRequest.class), any(HttpServletResponse.class), captor.capture());
		Saml2AuthenticationException exception = captor.getValue();
		assertThat(exception.getSaml2Error().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_RESPONSE);
		assertThat(exception.getSaml2Error().getDescription()).isEqualTo("Unable to inflate string");
		assertThat(exception.getCause()).isInstanceOf(IOException.class);
	}

	@Test
	public void authenticationRequestWhenCustomAuthnRequestRepositoryThenUses() throws Exception {
		this.spring.register(CustomAuthenticationRequestRepository.class).autowire();
		MockHttpServletRequestBuilder request = get("/saml2/authenticate/registration-id");
		this.mvc.perform(request).andExpect(status().isFound());
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> repository = this.spring.getContext()
				.getBean(Saml2AuthenticationRequestRepository.class);
		verify(repository).saveAuthenticationRequest(any(AbstractSaml2AuthenticationRequest.class),
				any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void authenticateWhenCustomAuthnRequestRepositoryThenUses() throws Exception {
		this.spring.register(CustomAuthenticationRequestRepository.class).autowire();
		MockHttpServletRequestBuilder request = post("/login/saml2/sso/registration-id").param("SAMLResponse",
				SIGNED_RESPONSE);
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> repository = this.spring.getContext()
				.getBean(Saml2AuthenticationRequestRepository.class);
		this.mvc.perform(request);
		verify(repository).loadAuthenticationRequest(any(HttpServletRequest.class));
		verify(repository).removeAuthenticationRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void authenticationRequestWhenCustomAuthenticationRequestUriRepositoryThenUses() throws Exception {
		this.spring.register(CustomAuthenticationRequestUriCustomAuthenticationConverter.class).autowire();
		MockHttpServletRequestBuilder request = get("/custom/auth/registration-id");
		this.mvc.perform(request).andExpect(status().isFound());
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> repository = this.spring.getContext()
				.getBean(Saml2AuthenticationRequestRepository.class);
		verify(repository).saveAuthenticationRequest(any(AbstractSaml2AuthenticationRequest.class),
				any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void saml2LoginWhenLoginProcessingUrlWithoutRegistrationIdAndDefaultAuthenticationConverterThenValidates() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(CustomLoginProcessingUrlDefaultAuthenticationConverter.class)
						.autowire())
				.havingRootCause().isInstanceOf(IllegalStateException.class)
				.withMessage("loginProcessingUrl must contain {registrationId} path variable");
	}

	@Test
	public void authenticateWhenCustomLoginProcessingUrlAndCustomAuthenticationConverterThenAuthenticate()
			throws Exception {
		this.spring.register(CustomLoginProcessingUrlCustomAuthenticationConverter.class).autowire();
		RelyingPartyRegistration relyingPartyRegistration = this.repository.findByRegistrationId("registration-id");
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(AUTHENTICATION_CONVERTER.convert(any(HttpServletRequest.class)))
				.willReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/my/custom/url").param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(redirectedUrl("/"));
		verify(AUTHENTICATION_CONVERTER).convert(any(HttpServletRequest.class));
	}

	@Test
	public void authenticateWhenCustomLoginProcessingUrlAndSaml2AuthenticationTokenConverterBeanThenAuthenticate()
			throws Exception {
		this.spring.register(CustomLoginProcessingUrlSaml2AuthenticationTokenConverterBean.class).autowire();
		Saml2AuthenticationTokenConverter authenticationConverter = this.spring.getContext()
				.getBean(Saml2AuthenticationTokenConverter.class);
		RelyingPartyRegistration relyingPartyRegistration = this.repository.findByRegistrationId("registration-id");
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(authenticationConverter.convert(any(HttpServletRequest.class)))
				.willReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/my/custom/url").param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(redirectedUrl("/"));
		verify(authenticationConverter).convert(any(HttpServletRequest.class));
	}

	// gh-11657
	@Test
	public void getFaviconWhenDefaultConfigurationThenDoesNotSaveAuthnRequest() throws Exception {
		this.spring.register(Saml2LoginConfig.class).autowire();
		this.mvc.perform(get("/favicon.ico").accept(MediaType.TEXT_HTML)).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		this.mvc.perform(get("/").accept(MediaType.TEXT_HTML)).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/saml2/authenticate/registration-id"));
	}

	private void performSaml2Login(String expected) throws IOException, ServletException {
		// setup authentication parameters
		this.request.setRequestURI("/login/saml2/sso/registration-id");
		this.request.setServletPath("/login/saml2/sso/registration-id");
		this.request.setParameter("SAMLResponse",
				Base64.getEncoder().encodeToString("saml2-xml-response-object".getBytes()));
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response)).getAuthentication();
		Assertions.assertNotNull(authentication, "Expected a valid authentication object.");
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first().isInstanceOf(SimpleGrantedAuthority.class)
				.hasToString(expected);
	}

	private static AuthenticationManager getAuthenticationManagerMock(String role) {
		return new AuthenticationManager() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				if (!supports(authentication.getClass())) {
					throw new AuthenticationServiceException("not supported");
				}
				return new Saml2Authentication(() -> "auth principal", "saml2 response",
						Collections.singletonList(new SimpleGrantedAuthority(role)));
			}

			public boolean supports(Class<?> authentication) {
				return authentication.isAssignableFrom(Saml2AuthenticationToken.class);
			}
		};
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LoginConfig {

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
					.saml2Login(Customizer.withDefaults());

			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LoginConfigWithCustomAuthenticationManager {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.saml2Login().authenticationManager(getAuthenticationManagerMock("ROLE_AUTH_MANAGER"));
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LoginConfigWithDefaultAndCustomAuthenticationManager {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authenticationManager(getAuthenticationManagerMock("DEFAULT_AUTH_MANAGER"))
				.saml2Login((saml) -> saml
					.authenticationManager(getAuthenticationManagerMock("ROLE_AUTH_MANAGER"))
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationFailureHandler {

		static final AuthenticationFailureHandler authenticationFailureHandler = mock(
				AuthenticationFailureHandler.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.authorizeRequests((authz) -> authz.anyRequest().authenticated())
					.saml2Login((saml2) -> saml2.failureHandler(authenticationFailureHandler));
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationRequestResolverBean {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authz) -> authz
					.anyRequest().authenticated()
				)
				.saml2Login(Customizer.withDefaults());
			// @formatter:on

			return http.build();
		}

		@Bean
		Saml2AuthenticationRequestResolver authenticationRequestResolver(
				RelyingPartyRegistrationRepository registrations) {
			RelyingPartyRegistrationResolver registrationResolver = new DefaultRelyingPartyRegistrationResolver(
					registrations);
			OpenSaml4AuthenticationRequestResolver delegate = new OpenSaml4AuthenticationRequestResolver(
					registrationResolver);
			delegate.setAuthnRequestCustomizer((parameters) -> parameters.getAuthnRequest().setForceAuthn(true));
			return delegate;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationRequestResolverDsl {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, RelyingPartyRegistrationRepository registrations)
				throws Exception {
			// @formatter:off
			http
					.authorizeRequests((authz) -> authz
						.anyRequest().authenticated()
					)
					.saml2Login((saml2) -> saml2
						.authenticationRequestResolver(authenticationRequestResolver(registrations))
					);
			// @formatter:on

			return http.build();
		}

		Saml2AuthenticationRequestResolver authenticationRequestResolver(
				RelyingPartyRegistrationRepository registrations) {
			RelyingPartyRegistrationResolver registrationResolver = new DefaultRelyingPartyRegistrationResolver(
					registrations);
			OpenSaml4AuthenticationRequestResolver delegate = new OpenSaml4AuthenticationRequestResolver(
					registrationResolver);
			delegate.setAuthnRequestCustomizer((parameters) -> parameters.getAuthnRequest().setForceAuthn(true));
			return delegate;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationConverter {

		static final AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.authorizeRequests((authz) -> authz.anyRequest().authenticated())
					.saml2Login((saml2) -> saml2.authenticationConverter(authenticationConverter));
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationConverterBean {

		private final Saml2AuthenticationTokenConverter authenticationConverter = mock(
				Saml2AuthenticationTokenConverter.class);

		@Bean
		SecurityFilterChain app(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests((authz) -> authz.anyRequest().authenticated())
					.saml2Login(Customizer.withDefaults());
			return http.build();
		}

		@Bean
		Saml2AuthenticationTokenConverter authenticationConverter() {
			return this.authenticationConverter;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationRequestRepository {

		private final Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> repository = mock(
				Saml2AuthenticationRequestRepository.class);

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			http.authorizeRequests((authz) -> authz.anyRequest().authenticated());
			http.saml2Login(withDefaults());
			return http.build();
		}

		@Bean
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository() {
			return this.repository;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomLoginProcessingUrlDefaultAuthenticationConverter {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authz) -> authz.anyRequest().authenticated())
				.saml2Login((saml2) -> saml2.loginProcessingUrl("/my/custom/url"));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomAuthenticationRequestUriCustomAuthenticationConverter {

		private final Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> repository = mock(
				Saml2AuthenticationRequestRepository.class);

		@Bean
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository() {
			return this.repository;
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authz) -> authz.anyRequest().authenticated())
				.saml2Login((saml2) -> saml2.authenticationRequestUri("/custom/auth/{registrationId}"));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomLoginProcessingUrlCustomAuthenticationConverter {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests((authz) -> authz.anyRequest().authenticated())
					.saml2Login((saml2) -> saml2
						.loginProcessingUrl("/my/custom/url")
						.authenticationConverter(AUTHENTICATION_CONVERTER)
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class CustomLoginProcessingUrlSaml2AuthenticationTokenConverterBean {

		private final Saml2AuthenticationTokenConverter authenticationConverter = mock(
				Saml2AuthenticationTokenConverter.class);

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests((authz) -> authz.anyRequest().authenticated())
					.saml2Login((saml2) -> saml2.loginProcessingUrl("/my/custom/url"));
			// @formatter:on
			return http.build();
		}

		@Bean
		Saml2AuthenticationTokenConverter authenticationTokenConverter() {
			return this.authenticationConverter;
		}

	}

	static class Saml2LoginConfigBeans {

		@Bean
		SecurityContextRepository securityContextRepository() {
			return new HttpSessionSecurityContextRepository();
		}

		@Bean
		RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
			RelyingPartyRegistration registration = TestRelyingPartyRegistrations.noCredentials()
					.signingX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartySigningCredential()))
					.assertingPartyDetails((party) -> party.verificationX509Credentials(
							(c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
					.build();
			return spy(new InMemoryRelyingPartyRegistrationRepository(registration));
		}

	}

	@RestController
	static class ResourceController {

		@GetMapping("/")
		String user(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
			return principal.getName();
		}

	}

}
