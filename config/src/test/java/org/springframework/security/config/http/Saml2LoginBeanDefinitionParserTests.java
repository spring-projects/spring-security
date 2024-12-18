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

import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.w3c.dom.Element;

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
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2Utils;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
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

	static {
		OpenSamlInitializationService.initialize();
	}

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/Saml2LoginBeanDefinitionParserTests";

	private static final RelyingPartyRegistration registration = TestRelyingPartyRegistrations.noCredentials()
		.signingX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartySigningCredential()))
		.assertingPartyDetails((party) -> party
			.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
		.build();

	private static String SIGNED_RESPONSE;

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

	@BeforeAll
	static void createResponse() throws Exception {
		String destination = registration.getAssertionConsumerServiceLocation();
		String assertingPartyEntityId = registration.getAssertingPartyDetails().getEntityId();
		String relyingPartyEntityId = registration.getEntityId();
		Response response = TestOpenSamlObjects.response(destination, assertingPartyEntityId);
		Assertion assertion = TestOpenSamlObjects.assertion("test@saml.user", assertingPartyEntityId,
				relyingPartyEntityId, destination);
		response.getAssertions().add(assertion);
		Response signed = TestOpenSamlObjects.signed(response,
				registration.getSigningX509Credentials().iterator().next(), relyingPartyEntityId);
		Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signed);
		Element element = marshaller.marshall(signed);
		String serialized = SerializeSupport.nodeToString(element);
		SIGNED_RESPONSE = Saml2Utils.samlEncode(serialized.getBytes(StandardCharsets.UTF_8));
	}

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
			.samlRequest("request")
			.authenticationRequestUri(IDP_SSO_URL)
			.build();
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
		String response = new String(Saml2Utils.samlDecode(SIGNED_RESPONSE));
		given(this.authenticationConverter.convert(any(HttpServletRequest.class)))
			.willReturn(new Saml2AuthenticationToken(registration, response));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/my/custom/url").param("SAMLResponse", SIGNED_RESPONSE);
		// @formatter:on
		this.mvc.perform(request).andExpect(redirectedUrl("/"));
		verify(this.authenticationConverter).convert(any(HttpServletRequest.class));
	}

	private RelyingPartyRegistration relyingPartyRegistrationWithVerifyingCredential() {
		given(this.repository.findByRegistrationId(anyString())).willReturn(registration);
		return registration;
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
