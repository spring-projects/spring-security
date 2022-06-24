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

package org.springframework.security.config.http;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2Utils;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link Saml2LoginBeanDefinitionParser}
 *
 * @author Marcus da Coregio
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class Saml2LoginBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/Saml2LoginBeanDefinitionParserTests";

	private static final String SIGNED_RESPONSE = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9ycC5leGFtcGxlLm9yZy9hY3MiIElEPSJfYzE3MzM2YTAtNTM1My00MTQ5LWI3MmMtMDNkOWY5YWYzMDdlIiBJc3N1ZUluc3RhbnQ9IjIwMjAtMDgtMDRUMjI6MDQ6NDUuMDE2WiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5hcC1lbnRpdHktaWQ8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4KPGRzOlNpZ25lZEluZm8+CjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+CjxkczpSZWZlcmVuY2UgVVJJPSIjX2MxNzMzNmEwLTUzNTMtNDE0OS1iNzJjLTAzZDlmOWFmMzA3ZSI+CjxkczpUcmFuc2Zvcm1zPgo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgo8L2RzOlRyYW5zZm9ybXM+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4KPGRzOkRpZ2VzdFZhbHVlPjYzTmlyenFzaDVVa0h1a3NuRWUrM0hWWU5aYWFsQW1OQXFMc1lGMlRuRDA9PC9kczpEaWdlc3RWYWx1ZT4KPC9kczpSZWZlcmVuY2U+CjwvZHM6U2lnbmVkSW5mbz4KPGRzOlNpZ25hdHVyZVZhbHVlPgpLMVlvWWJVUjBTclY4RTdVMkhxTTIvZUNTOTNoV25mOExnNnozeGZWMUlyalgzSXhWYkNvMVlYcnRBSGRwRVdvYTJKKzVOMmFNbFBHJiMxMzsKN2VpbDBZRC9xdUVRamRYbTNwQTBjZmEvY25pa2RuKzVhbnM0ZWQwanU1amo2dkpvZ2w2Smt4Q25LWUpwTU9HNzhtampmb0phengrWCYjMTM7CkM2NktQVStBYUdxeGVwUEQ1ZlhRdTFKSy9Jb3lBaitaa3k4Z2Jwc3VyZHFCSEJLRWxjdnVOWS92UGY0OGtBeFZBKzdtRGhNNUMvL1AmIzEzOwp0L084Y3NZYXB2UjZjdjZrdk45QXZ1N3FRdm9qVk1McHVxZWNJZDJwTUVYb0NSSnE2Nkd4MStNTUVPeHVpMWZZQlRoMEhhYjRmK3JyJiMxMzsKOEY2V1NFRC8xZllVeHliRkJqZ1Q4d2lEWHFBRU8wSVY4ZWRQeEE9PQo8L2RzOlNpZ25hdHVyZVZhbHVlPgo8L2RzOlNpZ25hdHVyZT48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iQWUzZjQ5OGI4LTliMTctNDA3OC05ZDM1LTg2YTA4NDA4NDk5NSIgSXNzdWVJbnN0YW50PSIyMDIwLTA4LTA0VDIyOjA0OjQ1LjA3N1oiIFZlcnNpb249IjIuMCI+PHNhbWwyOklzc3Vlcj5hcC1lbnRpdHktaWQ8L3NhbWwyOklzc3Vlcj48c2FtbDI6U3ViamVjdD48c2FtbDI6TmFtZUlEPnRlc3RAc2FtbC51c2VyPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90QmVmb3JlPSIyMDIwLTA4LTA0VDIxOjU5OjQ1LjA5MFoiIE5vdE9uT3JBZnRlcj0iMjA0MC0wNy0zMFQyMjowNTowNi4wODhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vcnAuZXhhbXBsZS5vcmcvYWNzIi8+PC9zYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDI6U3ViamVjdD48c2FtbDI6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjAtMDgtMDRUMjE6NTk6NDUuMDgwWiIgTm90T25PckFmdGVyPSIyMDQwLTA3LTMwVDIyOjA1OjA2LjA4N1oiLz48L3NhbWwyOkFzc2VydGlvbj48L3NhbWwycDpSZXNwb25zZT4=";

	private static final String IDP_SSO_URL = "https://sso-url.example.com/IDP/SSO";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	private RequestCache requestCache;

	@Autowired(required = false)
	private AuthenticationFailureHandler authenticationFailureHandler;

	@Autowired(required = false)
	private AuthenticationSuccessHandler authenticationSuccessHandler;

	@Autowired(required = false)
	private RelyingPartyRegistrationRepository repository;

	@Autowired(required = false)
	private ApplicationListener<AuthenticationSuccessEvent> authenticationSuccessListener;

	@Autowired(required = false)
	private AuthenticationConverter authenticationConverter;

	@Autowired(required = false)
	private Saml2AuthenticationRequestResolver authenticationRequestResolver;

	@Autowired(required = false)
	private Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository;

	@Autowired(required = false)
	private ApplicationContext applicationContext;

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenSingleRelyingPartyRegistrationThenAutoRedirect() throws Exception {
		this.spring.configLocations(this.xml("SingleRelyingPartyRegistration")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/saml2/authenticate/one"));
		// @formatter:on
		verify(this.requestCache).saveRequest(any(), any());
	}

	@Test
	public void requestWhenMultiRelyingPartyRegistrationThenRedirectToLoginWithRelyingParties() throws Exception {
		this.spring.configLocations(this.xml("MultiRelyingPartyRegistration")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void requestLoginWhenMultiRelyingPartyRegistrationThenReturnLoginPageWithRelyingParties() throws Exception {
		this.spring.configLocations(this.xml("MultiRelyingPartyRegistration")).autowire();
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/login"))
				.andExpect(status().is2xxSuccessful())
				.andReturn();
		// @formatter:on
		String pageContent = mvcResult.getResponse().getContentAsString();
		assertThat(pageContent).contains("<a href=\"/saml2/authenticate/two\">two</a>");
		assertThat(pageContent).contains("<a href=\"/saml2/authenticate/one\">one</a>");
	}

	@Test
	public void authenticateWhenAuthenticationResponseNotValidThenThrowAuthenticationException() throws Exception {
		this.spring.configLocations(this.xml("SingleRelyingPartyRegistration-WithCustomAuthenticationFailureHandler"))
				.autowire();
		this.mvc.perform(get("/login/saml2/sso/one").param(Saml2ParameterNames.SAML_RESPONSE, "samlResponse123"));
		ArgumentCaptor<AuthenticationException> exceptionCaptor = ArgumentCaptor
				.forClass(AuthenticationException.class);
		verify(this.authenticationFailureHandler).onAuthenticationFailure(any(), any(), exceptionCaptor.capture());
		AuthenticationException exception = exceptionCaptor.getValue();
		assertThat(exception).isInstanceOf(Saml2AuthenticationException.class);
		assertThat(((Saml2AuthenticationException) exception).getSaml2Error().getErrorCode())
				.isEqualTo("invalid_response");
	}

	@Test
	public void authenticateWhenAuthenticationResponseValidThenAuthenticate() throws Exception {
		this.spring.configLocations(this.xml("WithCustomRelyingPartyRepository")).autowire();
		RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationWithVerifyingCredential();
		// @formatter:off
		this.mvc.perform(post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId()).param(Saml2ParameterNames.SAML_RESPONSE, SIGNED_RESPONSE))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().is2xxSuccessful());
		// @formatter:on
		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), authenticationCaptor.capture());
		Authentication authentication = authenticationCaptor.getValue();
		assertThat(authentication.getPrincipal()).isInstanceOf(Saml2AuthenticatedPrincipal.class);
	}

	@Test
	public void authenticateWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.configLocations(this.xml("WithCustomSecurityContextHolderStrategy")).autowire();
		RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationWithVerifyingCredential();
		// @formatter:off
		this.mvc.perform(post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId()).param(Saml2ParameterNames.SAML_RESPONSE, SIGNED_RESPONSE))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().is2xxSuccessful());
		// @formatter:on
		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), authenticationCaptor.capture());
		Authentication authentication = authenticationCaptor.getValue();
		assertThat(authentication.getPrincipal()).isInstanceOf(Saml2AuthenticatedPrincipal.class);
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		verify(strategy, atLeastOnce()).getContext();
	}

	@Test
	public void authenticateWhenAuthenticationResponseValidThenAuthenticationSuccessEventPublished() throws Exception {
		this.spring.configLocations(this.xml("WithCustomRelyingPartyRepository")).autowire();
		RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationWithVerifyingCredential();
		// @formatter:off
		this.mvc.perform(post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId()).param(Saml2ParameterNames.SAML_RESPONSE, SIGNED_RESPONSE))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().is2xxSuccessful());
		// @formatter:on
		verify(this.authenticationSuccessListener).onApplicationEvent(any(AuthenticationSuccessEvent.class));
	}

	@Test
	public void authenticateWhenCustomAuthenticationConverterThenUses() throws Exception {
		this.spring.configLocations(this.xml("WithCustomRelyingPartyRepository-WithCustomAuthenticationConverter"))
				.autowire();
		RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationWithVerifyingCredential();
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(this.authenticationConverter.convert(any(HttpServletRequest.class)))
				.willReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId())
				.param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));
		verify(this.authenticationConverter).convert(any(HttpServletRequest.class));
	}

	@Test
	public void authenticateWhenCustomAuthenticationManagerThenUses() throws Exception {
		this.spring.configLocations(this.xml("WithCustomRelyingPartyRepository-WithCustomAuthenticationManager"))
				.autowire();
		RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationWithVerifyingCredential();
		AuthenticationManager authenticationManager = this.applicationContext.getBean("customAuthenticationManager",
				AuthenticationManager.class);
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(authenticationManager.authenticate(any()))
				.willReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/login/saml2/sso/" + relyingPartyRegistration.getRegistrationId())
				.param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));
		verify(authenticationManager).authenticate(any());
	}

	@Test
	public void authenticationRequestWhenCustomAuthenticationRequestContextResolverThenUses() throws Exception {
		this.spring
				.configLocations(this.xml("WithCustomRelyingPartyRepository-WithCustomAuthenticationRequestResolver"))
				.autowire();
		Saml2RedirectAuthenticationRequest request = Saml2RedirectAuthenticationRequest
				.withRelyingPartyRegistration(TestRelyingPartyRegistrations.noCredentials().build())
				.samlRequest("request").authenticationRequestUri(IDP_SSO_URL).build();
		given(this.authenticationRequestResolver.resolve(any(HttpServletRequest.class))).willReturn(request);
		this.mvc.perform(get("/saml2/authenticate/registration-id")).andExpect(status().isFound());
		verify(this.authenticationRequestResolver).resolve(any(HttpServletRequest.class));
	}

	@Test
	public void authenticationRequestWhenCustomAuthnRequestRepositoryThenUses() throws Exception {
		this.spring.configLocations(this.xml("WithCustomRelyingPartyRepository-WithCustomAuthnRequestRepository"))
				.autowire();
		given(this.repository.findByRegistrationId(anyString()))
				.willReturn(TestRelyingPartyRegistrations.relyingPartyRegistration().build());
		MockHttpServletRequestBuilder request = get("/saml2/authenticate/registration-id");
		this.mvc.perform(request).andExpect(status().isFound());
		verify(this.authenticationRequestRepository).saveAuthenticationRequest(
				any(AbstractSaml2AuthenticationRequest.class), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void authenticateWhenCustomAuthnRequestRepositoryThenUses() throws Exception {
		this.spring.configLocations(this.xml("WithCustomRelyingPartyRepository-WithCustomAuthnRequestRepository"))
				.autowire();
		RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);
		given(this.repository.findByRegistrationId(anyString()))
				.willReturn(TestRelyingPartyRegistrations.relyingPartyRegistration().build());
		MockHttpServletRequestBuilder request = post("/login/saml2/sso/registration-id").param("SAMLResponse",
				SIGNED_RESPONSE);
		this.mvc.perform(request);
		verify(this.authenticationRequestRepository).loadAuthenticationRequest(any(HttpServletRequest.class));
		verify(this.authenticationRequestRepository).removeAuthenticationRequest(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void saml2LoginWhenLoginProcessingUrlWithoutRegistrationIdAndDefaultAuthenticationConverterThenValidates() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("WithCustomLoginProcessingUrl")).autowire())
				.withMessageContaining("loginProcessingUrl must contain {registrationId} path variable");
	}

	@Test
	public void authenticateWhenCustomLoginProcessingUrlAndCustomAuthenticationConverterThenAuthenticate()
			throws Exception {
		this.spring.configLocations(this.xml("WithCustomLoginProcessingUrl-WithCustomAuthenticationConverter"))
				.autowire();
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.noCredentials()
				.assertingPartyDetails((party) -> party.verificationX509Credentials(
						(c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
				.build();
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(this.authenticationConverter.convert(any(HttpServletRequest.class)))
				.willReturn(new Saml2AuthenticationToken(relyingPartyRegistration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/my/custom/url").param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(redirectedUrl("/"));
		verify(this.authenticationConverter).convert(any(HttpServletRequest.class));
	}

	private RelyingPartyRegistration relyingPartyRegistrationWithVerifyingCredential() {
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.noCredentials()
				.assertingPartyDetails((party) -> party.verificationX509Credentials(
						(c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
				.build();
		given(this.repository.findByRegistrationId(anyString())).willReturn(relyingPartyRegistration);
		return relyingPartyRegistration;
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
