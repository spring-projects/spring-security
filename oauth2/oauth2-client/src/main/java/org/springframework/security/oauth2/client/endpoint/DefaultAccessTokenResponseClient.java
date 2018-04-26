package org.springframework.security.oauth2.client.endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.http.converter.FormOAuth2AccessTokenMessageConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.util.AccessTokenResponseJackson2Deserializer;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by XYUU <xyuu@xyuu.net> on 2018/4/25.
 */
public class DefaultAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

	private static final String AUTHORIZATION_CODE = "authorization_code";
	private static final String CODE = "code";
	private static final String GRANT_TYPE = "grant_type";
	private static final String REDIRECT_URI = "redirect_uri";
	private static final String CLIENT_ID = "client_id";
	private static final String CLIENT_SECRET = "client_secret";
	private static final String AUTHORIZATION = "Authorization";

	private final Map<ClientAuthenticationMethod, PlainClientSecret> methodMap = new HashMap<>();
	private final PlainClientSecret DEFAULT_METHOD = new ClientSecretBasic();
	private final RestTemplate restTemplate;


	public DefaultAccessTokenResponseClient() {
		methodMap.put(ClientAuthenticationMethod.BASIC, DEFAULT_METHOD);
		methodMap.put(ClientAuthenticationMethod.POST, new ClientSecretPost());

		FormHttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
		ObjectMapper objectMapper = new ObjectMapper().registerModule(new SimpleModule()
				.addDeserializer(OAuth2AccessTokenResponse.class, new AccessTokenResponseJackson2Deserializer()));
		this.restTemplate = new RestTemplate(Arrays.asList(formHttpMessageConverter,
				new MappingJackson2HttpMessageConverter(objectMapper)
				, new FormOAuth2AccessTokenMessageConverter(formHttpMessageConverter)));
	}

	public DefaultAccessTokenResponseClient addMethod(ClientAuthenticationMethod name, PlainClientSecret method) {
		methodMap.put(name, method);
		return this;
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest)
			throws OAuth2AuthenticationException {
		ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
		OAuth2AuthorizationExchange authorizationExchange = authorizationGrantRequest.getAuthorizationExchange();
		OAuth2AuthorizationRequest authorizationRequest = authorizationExchange.getAuthorizationRequest();
		String code = authorizationExchange.getAuthorizationResponse().getCode();
		String redirectUri = authorizationRequest.getRedirectUri();
		HttpHeaders headers = new HttpHeaders();
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add(CODE, code);
		body.add(GRANT_TYPE, AUTHORIZATION_CODE);
		body.add(REDIRECT_URI, redirectUri);
		//body.addAll("scope", new ArrayList<>(clientRegistration.getScopes()));
		methodMap.getOrDefault(clientRegistration.getClientAuthenticationMethod(), DEFAULT_METHOD)
				.getRequest(headers, body, authorizationGrantRequest);
		HttpEntity request = new HttpEntity<>(body, headers);
		return restTemplate.postForObject(clientRegistration.getProviderDetails().getTokenUri(), request,
				OAuth2AccessTokenResponse.class);
	}

	public interface PlainClientSecret {
		void getRequest(HttpHeaders headers, MultiValueMap<String, String> body, OAuth2AuthorizationCodeGrantRequest
				authorizationGrantRequest);
	}

	class ClientSecretPost implements PlainClientSecret {
		@Override
		public void getRequest(HttpHeaders headers, MultiValueMap<String, String> body,
							   OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
			ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
			body.add(CLIENT_ID, clientRegistration.getClientId());
			body.add(CLIENT_SECRET, clientRegistration.getClientSecret());
		}
	}

	class ClientSecretBasic implements PlainClientSecret {
		@Override
		public void getRequest(HttpHeaders headers, MultiValueMap<String, String> body,
							   OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
			ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
			headers.add(AUTHORIZATION, "Basic " + Base64Utils.encodeToString(String.join(":",
					UriUtils.encode(clientRegistration.getClientId(), StandardCharsets.UTF_8),
					UriUtils.encode(clientRegistration.getClientSecret(), StandardCharsets.UTF_8)).
					getBytes(StandardCharsets.UTF_8)));
		}
	}

}
