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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
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
import java.util.*;

/**
 * Created by XYUU <xyuu@xyuu.net> on 2018/4/25.
 */
public class DefaultAuthorizationCodeTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>,
		ApplicationContextAware {

	private static final String OAUTH2_RESTTEMPLATE_BEAN_NAME = "oauth2RestTemplate";
	private static final String OAUTH2_OBJECTMAPPER_BEAN_NAME = "oauth2ObjectMapper";
	private final Map<ClientAuthenticationMethod, PlainClientSecret> methodMap = new HashMap<>();
	private final Map<String, TokenExtractor> extractors = new HashMap<>();
	private final PlainClientSecret defaultMethod;
	private TokenExtractor defaultExtractor;

	private RestTemplate restTemplate;

	public DefaultAuthorizationCodeTokenResponseClient() {
		FormHttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
		defaultMethod = new ClientSecretBasic(formHttpMessageConverter);
		methodMap.put(ClientAuthenticationMethod.BASIC, defaultMethod);
		methodMap.put(ClientAuthenticationMethod.POST, new ClientSecretPost(formHttpMessageConverter));
		extractors.put(FormOAuth2AccessTokenExtractor.NAME, new FormOAuth2AccessTokenExtractor(formHttpMessageConverter));
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.restTemplate = applicationContext.containsBean(OAUTH2_RESTTEMPLATE_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_RESTTEMPLATE_BEAN_NAME, RestTemplate.class) :
				new RestTemplate();
		ObjectMapper objectMapper = applicationContext.containsBean(OAUTH2_OBJECTMAPPER_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_OBJECTMAPPER_BEAN_NAME, ObjectMapper.class) :
				Jackson2ObjectMapperBuilder.json().build();
		defaultExtractor = new DefaultTokenExtractor(objectMapper.getFactory());
		extractors.put(OAuth2ParameterNames.JSON_EXTRACTOR, defaultExtractor);
		BeanFactoryUtils.
				beansOfTypeIncludingAncestors(applicationContext, PlainClientSecret.class).forEach(this::addMethod);
		BeanFactoryUtils.
				beansOfTypeIncludingAncestors(applicationContext, TokenExtractor.class).forEach(this::addExtractor);
	}

	public DefaultAuthorizationCodeTokenResponseClient addMethod(String name, PlainClientSecret method) {
		methodMap.put(new ClientAuthenticationMethod(name), method);
		return this;
	}

	public DefaultAuthorizationCodeTokenResponseClient addExtractor(String name, TokenExtractor extractor) {
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
				.getProviderDetails().getTokenExtractorName(), defaultExtractor).doWithRequest(authorizationGrantRequest);
		return restTemplate.execute(clientRegistration.getProviderDetails().getTokenUri(), HttpMethod.POST, requestCallback, responseExtractor);
	}

	public interface PlainClientSecret {
		RequestCallback doWithRequest(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest);
	}

	public interface TokenExtractor {
		ResponseExtractor<OAuth2AccessTokenResponse> doWithRequest(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest);
	}

	public class DefaultTokenExtractor implements TokenExtractor {

		private JsonFactory jsonFactory;

		public DefaultTokenExtractor(JsonFactory jsonFactory) {
			this.jsonFactory = jsonFactory;
		}

		@Override
		public ResponseExtractor<OAuth2AccessTokenResponse> doWithRequest(OAuth2AuthorizationCodeGrantRequest request) {
			return response -> {
				String tokenValue = null;
				String tokenType = null;
				String refreshToken = null;
				Long expiresIn = 0L;
				Set<String> scope = null;
				Map<String, Object> additionalInformation = new LinkedHashMap<>();
				// TODO What should occur if a parameter exists twice
				try (JsonParser jp = jsonFactory.createParser(response.getBody())) {
					if (jp.nextToken() == JsonToken.START_OBJECT) {
						while (jp.nextToken() != JsonToken.END_OBJECT) {
							String name = jp.getCurrentName();
							jp.nextToken();
							switch (name) {
								case OAuth2ParameterNames.ACCESS_TOKEN:
									tokenValue = jp.getText();
									break;
								case OAuth2ParameterNames.TOKEN_TYPE:
									tokenType = jp.getText();
									break;
								case OAuth2ParameterNames.REFRESH_TOKEN:
									refreshToken = jp.getText();
									break;
								case OAuth2ParameterNames.EXPIRES_IN:
									try {
										expiresIn = jp.getLongValue();
									} catch (JsonParseException e) {
										expiresIn = Long.valueOf(jp.getText());
									}
									break;
								case OAuth2ParameterNames.SCOPE:
									if (jp.getCurrentToken() == JsonToken.START_ARRAY) {
										scope = new TreeSet<>();
										while (jp.nextToken() != JsonToken.END_ARRAY) {
											scope.add(jp.getValueAsString());
										}
									} else {
										String values = jp.getText();
										if (values != null && values.trim().length() > 0) {
											// the spec says the scope is separated by spaces
											String[] tokens = values.split("[\\s+]");
											scope = new TreeSet<>(Arrays.asList(tokens));
										}
									}
									break;
								default:
									additionalInformation.put(name, jp.readValueAs(Object.class));
							}
						}
					}
				}
				if (scope == null || scope.isEmpty()) {
					scope = request.getAuthorizationExchange().getAuthorizationRequest().getScopes();
				}
				// TODO What should occur if a required parameter (tokenValue or tokenType) is missing?
				return OAuth2AccessTokenResponse.withToken(tokenValue)
						.tokenType(OAuth2AccessToken.TokenType.BEARER)
						.expiresIn(expiresIn)
						.additionalParameters(additionalInformation)
						.scopes(scope).build();
			};
		}
	}

	public class FormOAuth2AccessTokenExtractor implements TokenExtractor {

		public static final String NAME = "form";

		private final FormHttpMessageConverter delegateMessageConverter;

		public FormOAuth2AccessTokenExtractor(FormHttpMessageConverter delegateMessageConverter) {
			this.delegateMessageConverter = delegateMessageConverter;
		}

		@Override
		public ResponseExtractor<OAuth2AccessTokenResponse> doWithRequest(OAuth2AuthorizationCodeGrantRequest request) {
			return response -> {
				MultiValueMap<String, String> data = delegateMessageConverter.read(null, response);
				String tokenValue = null;
				String tokenType = null;
				String refreshToken = null;
				Long expiresIn = 0L;
				Set<String> scope = null;
				Map<String, Object> additionalInformation = new LinkedHashMap<>();
				for (Map.Entry<String, List<String>> entry : data.entrySet()) {
					String name = entry.getKey();
					List<String> values = entry.getValue();
					switch (name) {
						case OAuth2ParameterNames.ACCESS_TOKEN:
							tokenValue = values.get(0);
							break;
						case OAuth2ParameterNames.TOKEN_TYPE:
							tokenType = values.get(0);
							break;
						case OAuth2ParameterNames.REFRESH_TOKEN:
							refreshToken = values.get(0);
							break;
						case OAuth2ParameterNames.EXPIRES_IN:
							expiresIn = Long.valueOf(values.get(0));
							break;
						case OAuth2ParameterNames.SCOPE:
							if (values.size() > 1) {
								scope = new TreeSet<>(values);
							} else {
								String value = values.get(0);
								if (value != null && value.trim().length() > 0) {
									// the spec says the scope is separated by spaces
									String[] tokens = value.split("[\\s+]");
									scope = new TreeSet<>(Arrays.asList(tokens));
								}
							}
							break;
						default:
							additionalInformation.put(name, values.get(0));
					}
				}
				if (scope == null || scope.isEmpty()) {
					scope = request.getAuthorizationExchange().getAuthorizationRequest().getScopes();
				}
				return OAuth2AccessTokenResponse.withToken(tokenValue)
						.tokenType(OAuth2AccessToken.TokenType.BEARER)
						.expiresIn(expiresIn)
						.scopes(scope)
						.additionalParameters(additionalInformation).build();
			};
		}
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
