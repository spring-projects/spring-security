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
import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.core.Saml2Utils;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link Saml2LogoutBeanDefinitionParser}
 *
 * @author Marcus da Coregio
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class Saml2LogoutBeanDefinitionParserTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	private final Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/Saml2LogoutBeanDefinitionParserTests";

	String apLogoutRequest = "nZFBa4MwGIb/iuQeE2NTXFDLQAaC26Hrdtgt1dQFNMnyxdH9+zlboeyww275SN7nzcOX787jEH0qD9qaAiUxRZEyre206Qv0cnjAGdqVOchxYE40trdT2KuPSUGI5qQBcbkq0OSNsBI0CCNHBSK04vn+sREspsJ5G2xrBxRVc1AbGZa29xAcCEK8i9VZjm5QsfU9GZYWsoCJv5ShqK4K1Ow5p5LyU4aP6XaLN3cpw9mGctydjrxNaZt1XM5vASZVGwjShAIxyhJMU8z4gSWCM8GSmDH+hqLX1Xv+JLpaiiXsb+3+lpMAyv8IoVI6rEzQ4QvrLie3uBX+NMfr6l/waT6t0AumvI6/FlN+Aw==";

	String apLogoutRequestSigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;

	String apLogoutRequestRelayState = "33591874-b123-4f2c-ab0d-2d0d84aa8b56";

	String apLogoutRequestSignature = "oKqdzrmn2YAqXcwkow2lzRXr5PNHm0s/gWsRnaZYhC+Oq5ekK5uIKQYvtmNR94HJjDe1VRs+vVQCYivgdoTzBV2ZlffTXZmYsCsY9q4jbCWR6R5CbhU73/MkKQsPcyVvMhNYxnDYapIlxDsfoZNTboDEz3GM+HRoGRfl9emCXY0lPRYwqC4kpu7oMDBkafR0A09jPIxFuNpqlLPwUxL9m+DGkvDK3mFDN1xJcgZaK73HcuJe7Qh4huOrKNFetwc5EvqfiwgiWF6sfq9A+rZBfCIYo10NNLY7fNQAR2IqwcKtawHgTGWbeshRyFrwVYMR64EnClfxUHsHKf5kiZ2dlw==";

	String apLogoutResponse = "fZHRa4MwEMb/Fcl7jEadGqplrAwK3Uvb9WFvZ4ydoInk4uj++1nXbmWMvhwcd9/3Jb9bLE99530oi63RBQn9gHhKS1O3+liQ1/0zzciyXCD0HR/ExhzN6LYKB6NReZNUo/ieFWS0WhjAFoWGXqFwUuweXzaC+4EYrHFGmo54K4Wu1eDmuHfnBhSM2cFXJ+iHTvnGHlk3x7DZmNlLGvHWq4Jstk0GUSjjiIZJI2lcpQnNeRLTAOo4fwCeQg3Trr6+cm/OqmnWVHECVGWQ0jgCSatsKvXUxhFvZF7xSYU4qrVGB9oVhAc8pEFEebLnkeBc8NyPePpGvMOV1/Q3cqEjZrG9hXKfCSAqe+ZAShio0q51n7StF+zW7gf9zoEb8U/7ZGrlHaAb1f0onLfFbpRSIRJWXkJ+bdm/Fy6/AA==";

	String apLogoutResponseSigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;

	String apLogoutResponseRelayState = "8f63887a-ec7e-4149-b6a0-dd730017f315";

	String apLogoutResponseSignature = "h2fDqSIBfmnkRHKDMY4IxkCXcI0w98ydNsnPmv1b7GTZCWLbJ+oxaP2yZNPw7wOWXTv86cTPwKLjx5halKy5C+hhWnT0haKhuMcUvHlsgAMBbJKLV+1afzL4O77cvAQJmMNRK7ugXGNV5PTEnd1U4voy134OgdD5XycYiFVRZOwP5H84eJ9xxlvqQwqDvZTcgiF/ZS4ioZgzgnIFcbagZQ12LWNh26OMaUpIW04kCeO6t2dUsxOL6nZWvNrX/Zx1sORIpu4doDUa1RYC8YnjZeQEzDqUVC/dBO/mbVJ/hbF9tD0jBUx7YIgoXpqsWK4TcCsvmlmhrJXvGxDyoAWu2Q==";

	String rpLogoutRequest = "nZFBa4MwGIb/iuQeY6NlGtQykIHgdui6HXaLmrqAJlm+OLp/v0wrlB122CXkI3mfNw/JD5dpDD6FBalVgXZhhAKhOt1LNRTo5fSAU3Qoc+DTSA1r9KBndxQfswAX+KQCth4VaLaKaQ4SmOKTAOY69nz/2DAaRsxY7XSnRxRUPigVd0vbu3MGGCHchOLCJzOKUNuBjEsLWcDErmUoqKsCNcc+yc5tsudYpPwOJzHvcJv6pfdjEtNzl7XU3wWYRa3AceUKRCO6w1GM6f5EY0Ypo1lIk+gNBa+bt38kulqyJWxv7f6W4wDC/gih0hoslJPuC8s+J7e4Df7k43X1L/jsdxt0xZTX8dfHlN8=";

	String rpLogoutRequestId = "LRd49fb45a-e8a7-43ac-b8ac-d8a7432fc9b2";

	String rpLogoutRequestRelayState = "8f63887a-ec7e-4149-b6a0-dd730017f315";

	String rpLogoutRequestSignature = "h2fDqSIBfmnkRHKDMY4IxkCXcI0w98ydNsnPmv1b7GTZCWLbJ+oxaP2yZNPw7wOWXTv86cTPwKLjx5halKy5C+hhWnT0haKhuMcUvHlsgAMBbJKLV+1afzL4O77cvAQJmMNRK7ugXGNV5PTEnd1U4voy134OgdD5XycYiFVRZOwP5H84eJ9xxlvqQwqDvZTcgiF/ZS4ioZgzgnIFcbagZQ12LWNh26OMaUpIW04kCeO6t2dUsxOL6nZWvNrX/Zx1sORIpu4doDUa1RYC8YnjZeQEzDqUVC/dBO/mbVJ/hbF9tD0jBUx7YIgoXpqsWK4TcCsvmlmhrJXvGxDyoAWu2Q==";

	@Autowired(required = false)
	private RelyingPartyRegistrationRepository repository;

	@Autowired
	private MockMvc mvc;

	private Saml2Authentication saml2User;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@BeforeEach
	public void setup() {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("registration-id");
		this.saml2User = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		this.request = new MockHttpServletRequest("POST", "");
		this.request.setServletPath("/login/saml2/sso/test-rp");
		this.response = new MockHttpServletResponse();
	}

	@Test
	public void logoutWhenLogoutSuccessHandlerAndNotSaml2LoginThenDefaultLogoutSuccessHandler() throws Exception {
		this.spring.configLocations(this.xml("LogoutSuccessHandler")).autowire();
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password");
		MvcResult result = this.mvc.perform(post("/logout").with(authentication(user)).with(csrf()))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).isEqualTo("/logoutSuccessEndpoint");
	}

	@Test
	public void saml2LogoutWhenDefaultsThenLogsOutAndSendsLogoutRequest() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		MvcResult result = this.mvc.perform(post("/logout").with(authentication(this.saml2User)).with(csrf()))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/request");
	}

	@Test
	public void saml2LogoutWhenUnauthenticatedThenEntryPoint() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		this.mvc.perform(post("/logout").with(csrf())).andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
	}

	@Test
	public void saml2LogoutWhenMissingCsrfThen403() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		this.mvc.perform(post("/logout").with(authentication(this.saml2User))).andExpect(status().isForbidden());
	}

	@Test
	public void saml2LogoutWhenGetThenDefaultLogoutPage() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		MvcResult result = this.mvc.perform(get("/logout").with(authentication(this.saml2User)))
				.andExpect(status().isOk()).andReturn();
		assertThat(result.getResponse().getContentAsString()).contains("Are you sure you want to log out?");
	}

	@Test
	public void saml2LogoutWhenPutOrDeleteThen404() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		this.mvc.perform(put("/logout").with(authentication(this.saml2User)).with(csrf()))
				.andExpect(status().isNotFound());
		this.mvc.perform(delete("/logout").with(authentication(this.saml2User)).with(csrf()))
				.andExpect(status().isNotFound());
	}

	@Test
	public void saml2LogoutWhenNoRegistrationThen401() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("wrong");
		Saml2Authentication authentication = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		this.mvc.perform(post("/logout").with(authentication(authentication)).with(csrf()))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void saml2LogoutWhenCsrfDisabledAndNoAuthenticationThenFinalRedirect() throws Exception {
		this.spring.configLocations(this.xml("CsrfDisabled-MockLogoutSuccessHandler")).autowire();
		this.mvc.perform(post("/logout"));
		LogoutSuccessHandler logoutSuccessHandler = this.spring.getContext().getBean(LogoutSuccessHandler.class);
		verify(logoutSuccessHandler).onLogoutSuccess(any(), any(), any());
	}

	@Test
	public void saml2LogoutWhenCustomLogoutRequestResolverThenUses() throws Exception {
		this.spring.configLocations(this.xml("CustomComponents")).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		given(getBean(Saml2LogoutRequestResolver.class).resolve(any(), any())).willReturn(logoutRequest);
		this.mvc.perform(post("/logout").with(authentication(this.saml2User)).with(csrf()));
		verify(getBean(Saml2LogoutRequestResolver.class)).resolve(any(), any());
	}

	@Test
	public void saml2LogoutRequestWhenDefaultsThenLogsOutAndSendsLogoutResponse() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("get");
		Saml2Authentication user = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MvcResult result = this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.param("Signature", this.apLogoutRequestSignature).with(samlQueryString()).with(authentication(user)))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/response");
	}

	@Test
	public void saml2LogoutRequestWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.configLocations(this.xml("WithSecurityContextHolderStrategy")).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("get");
		Saml2Authentication user = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MvcResult result = this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.param("Signature", this.apLogoutRequestSignature).with(samlQueryString()).with(authentication(user)))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/response");
		verify(getBean(SecurityContextHolderStrategy.class), atLeastOnce()).getContext();
	}

	@Test
	public void saml2LogoutRequestWhenNoRegistrationThen400() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("wrong");
		Saml2Authentication user = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.param("Signature", this.apLogoutRequestSignature).with(authentication(user)))
				.andExpect(status().isBadRequest());
	}

	@Test
	public void saml2LogoutRequestWhenInvalidSamlRequestThen401() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.with(authentication(this.saml2User))).andExpect(status().isUnauthorized());
	}

	@Test
	public void saml2LogoutRequestWhenCustomLogoutRequestHandlerThenUses() throws Exception {
		this.spring.configLocations(this.xml("CustomComponents")).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.setIssueInstant(Instant.now());
		given(getBean(Saml2LogoutRequestValidator.class).validate(any()))
				.willReturn(Saml2LogoutValidatorResult.success());
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration).build();
		given(getBean(Saml2LogoutResponseResolver.class).resolve(any(), any())).willReturn(logoutResponse);
		this.mvc.perform(
				post("/logout/saml2/slo").param("SAMLRequest", "samlRequest").with(authentication(this.saml2User)))
				.andReturn();
		verify(getBean(Saml2LogoutRequestValidator.class)).validate(any());
		verify(getBean(Saml2LogoutResponseResolver.class)).resolve(any(), any());
	}

	@Test
	public void saml2LogoutResponseWhenDefaultsThenRedirects() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("get");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, this.request, this.response);
		this.request.setParameter("RelayState", logoutRequest.getRelayState());
		assertThat(this.logoutRequestRepository.loadLogoutRequest(this.request)).isNotNull();
		this.mvc.perform(get("/logout/saml2/slo").session(((MockHttpSession) this.request.getSession()))
				.param("SAMLResponse", this.apLogoutResponse).param("RelayState", this.apLogoutResponseRelayState)
				.param("SigAlg", this.apLogoutResponseSigAlg).param("Signature", this.apLogoutResponseSignature)
				.with(samlQueryString())).andExpect(status().isFound()).andExpect(redirectedUrl("/login?logout"));
		assertThat(this.logoutRequestRepository.loadLogoutRequest(this.request)).isNull();
	}

	@Test
	public void saml2LogoutResponseWhenInvalidSamlResponseThen401() throws Exception {
		this.spring.configLocations(this.xml("Default")).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, this.request, this.response);
		String deflatedApLogoutResponse = Saml2Utils.samlEncode(
				Saml2Utils.samlInflate(Saml2Utils.samlDecode(this.apLogoutResponse)).getBytes(StandardCharsets.UTF_8));
		this.mvc.perform(post("/logout/saml2/slo").session((MockHttpSession) this.request.getSession())
				.param("SAMLResponse", deflatedApLogoutResponse).param("RelayState", this.rpLogoutRequestRelayState)
				.param("SigAlg", this.apLogoutRequestSigAlg).param("Signature", this.apLogoutResponseSignature)
				.with(samlQueryString())).andExpect(status().reason(containsString("invalid_signature")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void saml2LogoutResponseWhenCustomLogoutResponseHandlerThenUses() throws Exception {
		this.spring.configLocations(this.xml("CustomComponents")).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("get");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		given(getBean(Saml2LogoutRequestRepository.class).removeLogoutRequest(any(), any())).willReturn(logoutRequest);
		given(getBean(Saml2LogoutResponseValidator.class).validate(any()))
				.willReturn(Saml2LogoutValidatorResult.success());
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLResponse", "samlResponse")).andReturn();
		verify(getBean(Saml2LogoutResponseValidator.class)).validate(any());
	}

	private <T> T getBean(Class<T> clazz) {
		return this.spring.getContext().getBean(clazz);
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	private SamlQueryStringRequestPostProcessor samlQueryString() {
		return new SamlQueryStringRequestPostProcessor();
	}

	static class SamlQueryStringRequestPostProcessor implements RequestPostProcessor {

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			UriComponentsBuilder builder = UriComponentsBuilder.newInstance();
			for (Map.Entry<String, String[]> entries : request.getParameterMap().entrySet()) {
				builder.queryParam(entries.getKey(),
						UriUtils.encode(entries.getValue()[0], StandardCharsets.ISO_8859_1));
			}
			request.setQueryString(builder.build(true).toUriString().substring(1));
			return request;
		}

	}

}
