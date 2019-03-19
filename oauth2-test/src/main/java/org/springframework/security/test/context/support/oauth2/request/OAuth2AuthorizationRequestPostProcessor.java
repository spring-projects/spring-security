package org.springframework.security.test.context.support.oauth2.request;

import java.util.HashMap;
import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.test.context.support.oauth2.support.OidcIdSupport;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

public class OAuth2AuthorizationRequestPostProcessor
		implements
		OidcIdTokenRequestPostProcessor.Nested,
		RequestPostProcessor {
	private final OAuth2AuthorizationRequest.Builder delegate;
	private final Map<String, Object> additionalParameters;
	private final OidcIdTokenRequestPostProcessor root;

	public OAuth2AuthorizationRequestPostProcessor(
			final OidcIdTokenRequestPostProcessor root,
			final AuthorizationGrantType authorizationGrantType) {
		this.additionalParameters = new HashMap<>();
		this.delegate = OidcIdSupport.authorizationRequestBuilder(authorizationGrantType)
				.additionalParameters(this.additionalParameters);
		this.root = root;
	}

	public static OAuth2AuthorizationRequestPostProcessor withDefaults(
			final OidcIdTokenRequestPostProcessor root,
			final AuthorizationGrantType authorizationGrantType) {
		return new OAuth2AuthorizationRequestPostProcessor(root, authorizationGrantType)
				.authorizationUri(OidcIdSupport.REQUEST_AUTHORIZATION_URI)
				.clientId(OidcIdSupport.CLIENT_ID)
				.redirectUri(OidcIdSupport.REQUEST_REDIRECT_URI);
	}

	public static OAuth2AuthorizationRequestPostProcessor
			withDefaults(final OidcIdTokenRequestPostProcessor root) {
		return withDefaults(
				root,
				new AuthorizationGrantType(OidcIdSupport.REQUEST_GRANT_TYPE));
	}

	@Override
	public OidcIdTokenRequestPostProcessor and() {
		return root;
	}

	@Override
	public MockHttpServletRequest
			postProcessRequest(final MockHttpServletRequest request) {
		return root.postProcessRequest(request);
	}

	public OAuth2AuthorizationRequest.Builder builder() {
		return delegate;
	}

	public OAuth2AuthorizationRequestPostProcessor
			additionalParameter(final String name, final Object value) {
		additionalParameters.put(name, value);
		return this;
	}

	public OAuth2AuthorizationRequestPostProcessor
			authorizationRequestUri(final String authorizationRequestUri) {
		delegate.authorizationRequestUri(authorizationRequestUri);
		return this;
	}

	public OAuth2AuthorizationRequestPostProcessor
			authorizationUri(final String authorizationUri) {
		delegate.authorizationUri(authorizationUri);
		return this;
	}

	public OAuth2AuthorizationRequestPostProcessor clientId(final String clientId) {
		delegate.clientId(clientId);
		return this;
	}

	public OAuth2AuthorizationRequestPostProcessor redirectUri(final String redirectUri) {
		delegate.redirectUri(redirectUri);
		return this;
	}

	public OAuth2AuthorizationRequestPostProcessor state(final String state) {
		delegate.state(state);
		return this;
	}
}
