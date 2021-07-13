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
package org.springframework.security.oauth2.client.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * An cookie-based implementation of an {@link AuthorizationRequestRepository}
 * {@link OAuth2AuthorizationRequest} useful for stateless OAuth2 clients.
 *
 * @author Gittenburg
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public class HttpCookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
	private static final String COOKIE_NAME =
		HttpCookieOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";

	private final ObjectMapper objectMapper = new ObjectMapper();

	private final ConversionService conversionService = new DefaultConversionService();

	@Override
	public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");

		if (request.getCookies() == null)
			return null;

		Cookie cookie = Arrays.stream(request.getCookies()).filter(c -> c.getName().equals(COOKIE_NAME)).findFirst().get();
		if (cookie == null)
			return null;

		// We do not use (de)serialization for untrusted data because that can lead to security vulnerabilities.

		JsonNode node = null;
		try {
			node = objectMapper.reader().readTree(Base64.getDecoder().decode(cookie.getValue().getBytes()));
		} catch (IOException e) {
			return null;
		}

		Map<String, Object> attributesMap = new HashMap<>();
		node.get("attributes").fields().forEachRemaining(entry -> {
			attributesMap.put(entry.getKey(), entry.getValue().textValue());
		});
		Map<String, Object> additionalParamsMap = new HashMap<>();
		node.get("additionalParams").fields().forEachRemaining(entry -> {
			additionalParamsMap.put(entry.getKey(), entry.getValue().textValue());
		});
		Set<String> scopes = new HashSet<>();
		node.withArray("scopes").forEach(scopeNode -> scopes.add(scopeNode.asText()));

		return OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(node.get("authorizationUri").textValue())
			.authorizationRequestUri(node.get("authorizationRequestUri").textValue())
			.clientId(node.get("clientId").textValue())
			.redirectUri(node.get("redirectUri").textValue())
			.state(node.get("state").textValue())
			.scopes(scopes)
			.attributes(attributesMap)
			.additionalParameters(additionalParamsMap)
			.build();
	}

	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");

		if (authorizationRequest == null){
			response.addCookie(expiredCookie(request));
			return;
		}

		ObjectNode node = objectMapper.createObjectNode();
		node.put("authorizationUri", authorizationRequest.getAuthorizationUri());
		node.put("authorizationRequestUri", authorizationRequest.getAuthorizationRequestUri());

		node.put("clientId", authorizationRequest.getClientId());
		node.put("redirectUri", authorizationRequest.getRedirectUri());
		ArrayNode scopeArrayNode = node.putArray("scopes");
		authorizationRequest.getScopes().forEach(scopeArrayNode::add);
		node.put("state", authorizationRequest.getState());

		ObjectNode attributesNode = node.putObject("attributes");
		authorizationRequest.getAttributes().forEach((key, value) -> {
			attributesNode.put(key, conversionService.convert(value, String.class));
		});

		ObjectNode additionalParamsNode = node.putObject("additionalParams");
		authorizationRequest.getAdditionalParameters().forEach((key, value) -> {
			additionalParamsNode.put(key, conversionService.convert(value, String.class));
		});
		response.addCookie(buildCookie(Base64.getEncoder().encodeToString(node.toString().getBytes()), request));
	}

	/**
	 * Builds a cookie to store the authorization request
	 * @param value the value to save in the cookie
	 * @param request the request to which we will respond with the cookie
	 * @return the created cookie
	 */
	private Cookie buildCookie(String value, HttpServletRequest request){
		Cookie cookie = new Cookie(COOKIE_NAME, value);
		cookie.setPath("/");
		cookie.setHttpOnly(true);
		cookie.setSecure(request.isSecure());
		cookie.setMaxAge(120); // expire after two minutes
		return cookie;
	}

	/**
	 * Builds an expired cookie
	 * @param request the request to which we will respond with the cookie
	 * @return the expired cookie
	 */
	private Cookie expiredCookie(HttpServletRequest request){
		Cookie cookie = buildCookie("", request);
		cookie.setMaxAge(0);
		return cookie;
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		response.addCookie(expiredCookie(request));
		return loadAuthorizationRequest(request);
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		// we cannot actually remove the authorizationRequest here because we don't have access to the httpServletResponse
		return loadAuthorizationRequest(request);
	}
}
