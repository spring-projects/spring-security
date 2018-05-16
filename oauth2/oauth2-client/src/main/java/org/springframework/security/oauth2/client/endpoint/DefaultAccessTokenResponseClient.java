/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.util.AccessTokenResponseJackson2Deserializer;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by XYUU <xyuu@xyuu.net> on 2018/4/25.
 */
public class DefaultAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>, ApplicationContextAware {

	private static final String OAUTH2_RESTTEMPLATE_BEAN_NAME = "oauth2RestTemplate";
	private static final String OAUTH2_OBJECTMAPPER_BEAN_NAME = "oauth2ObjectMapper";
	private final Map<ClientAuthenticationMethod, PlainClientSecret> methodMap = new HashMap<>();
	private final Map<String, ResponseExtractor<OAuth2AccessTokenResponse>> extractors = new HashMap<>();
	private final PlainClientSecret defaultMethod;
	private final ResponseExtractor<OAuth2AccessTokenResponse> defaultExtractor;

	private RestTemplate restTemplate;
	private ObjectMapper objectMapper;

	public DefaultAccessTokenResponseClient() {
		FormHttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
		defaultMethod = new ClientSecretBasic(formHttpMessageConverter);
		methodMap.put(ClientAuthenticationMethod.BASIC, defaultMethod);
		methodMap.put(ClientAuthenticationMethod.POST, new ClientSecretPost(formHttpMessageConverter));
		defaultExtractor = response -> objectMapper.readValue(response.getBody(), OAuth2AccessTokenResponse.class);
		extractors.put(OAuth2ParameterNames.JSON_EXTRACTOR, defaultExtractor);
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.restTemplate = applicationContext.containsBean(OAUTH2_RESTTEMPLATE_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_RESTTEMPLATE_BEAN_NAME, RestTemplate.class) :
				new RestTemplate();
		this.objectMapper = applicationContext.containsBean(OAUTH2_OBJECTMAPPER_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_OBJECTMAPPER_BEAN_NAME, ObjectMapper.class) :
				Jackson2ObjectMapperBuilder.json()
						.deserializerByType(OAuth2AccessTokenResponse.class, new AccessTokenResponseJackson2Deserializer()).build();
		BeanFactoryUtils.
				beansOfTypeIncludingAncestors(applicationContext, PlainClientSecret.class).forEach(this::addMethod);
		BeanFactoryUtils.
				beansOfTypeIncludingAncestors(applicationContext, ResponseExtractor.class).forEach(this::addExtractor);
	}

	public DefaultAccessTokenResponseClient addMethod(String name, PlainClientSecret method) {
		methodMap.put(new ClientAuthenticationMethod(name), method);
		return this;
	}

	public DefaultAccessTokenResponseClient addExtractor(String name, ResponseExtractor<OAuth2AccessTokenResponse> extractor) {
		extractors.put(name, extractor);
		return this;
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest)
			throws OAuth2AuthenticationException {
		ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
		RequestCallback requestCallback = methodMap.getOrDefault(clientRegistration.getClientAuthenticationMethod(), defaultMethod)
				.doWithRequest(authorizationGrantRequest);
		ResponseExtractor<OAuth2AccessTokenResponse> responseExtractor = extractors.getOrDefault(clientRegistration
				.getProviderDetails().getTokenExtractorName(), defaultExtractor);
		return restTemplate.execute(clientRegistration.getProviderDetails().getTokenUri(), HttpMethod.POST, requestCallback, responseExtractor);
	}

	public interface PlainClientSecret {
		RequestCallback doWithRequest(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest);
	}

	public abstract class FormClientSecret implements PlainClientSecret {

		private FormHttpMessageConverter formHttpMessageConverter;

		public FormClientSecret(FormHttpMessageConverter formHttpMessageConverter) {
			this.formHttpMessageConverter = formHttpMessageConverter;
		}

		public RequestCallback doWithRequest(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
			OAuth2AuthorizationExchange authorizationExchange = authorizationGrantRequest.getAuthorizationExchange();
			OAuth2AuthorizationRequest authorizationRequest = authorizationExchange.getAuthorizationRequest();
			MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
			body.add(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
			body.add(OAuth2ParameterNames.GRANT_TYPE, OAuth2ParameterNames.AUTHORIZATION_CODE);
			body.add(OAuth2ParameterNames.REDIRECT_URI, authorizationRequest.getRedirectUri());
			//body.addAll("scope", new ArrayList<>(clientRegistration.getScopes()));
			return request -> {
				andThen(request.getHeaders(), body, authorizationGrantRequest);
				formHttpMessageConverter.write(body, MediaType.APPLICATION_FORM_URLENCODED, request);
			};
		}

		abstract void andThen(HttpHeaders headers, MultiValueMap<String, String> body, OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest);
	}

	class ClientSecretPost extends FormClientSecret {

		public ClientSecretPost(FormHttpMessageConverter formHttpMessageConverter) {
			super(formHttpMessageConverter);
		}

		@Override
		public void andThen(HttpHeaders headers, MultiValueMap<String, String> body, OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
			ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
			body.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			body.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
	}

	class ClientSecretBasic extends FormClientSecret {

		public ClientSecretBasic(FormHttpMessageConverter formHttpMessageConverter) {
			super(formHttpMessageConverter);
		}

		@Override
		public void andThen(HttpHeaders headers, MultiValueMap<String, String> body, OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
			ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
			headers.add(OAuth2ParameterNames.AUTHORIZATION, "Basic " + Base64Utils.encodeToString(String.join(":",
					UriUtils.encode(clientRegistration.getClientId(), StandardCharsets.UTF_8),
					UriUtils.encode(clientRegistration.getClientSecret(), StandardCharsets.UTF_8)).
					getBytes(StandardCharsets.UTF_8)));
		}
	}

}
