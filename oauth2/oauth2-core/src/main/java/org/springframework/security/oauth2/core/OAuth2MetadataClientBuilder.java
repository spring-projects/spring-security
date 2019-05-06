/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.core;


import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.util.UriComponentsBuilder;

public class OAuth2MetadataClientBuilder {
	private final Function<URI, Map<String, Object>> oauth2AuthorizationMetadataClient;

	private Map<String, List<DiscoveryClient>> clientsMap = new LinkedHashMap<>();

	// for added readability
	private interface DiscoveryClient extends Function<URI, Map<String, Object>> {}

	public OAuth2MetadataClientBuilder(
			Function<URI, Map<String, Object>> oauth2AuthorizationServerMetadataClient) {
		this.oauth2AuthorizationMetadataClient = oauth2AuthorizationServerMetadataClient;
	}

	public OAuth2MetadataClientBuilder useOAuth2Discovery() {
		this.clientsMap.put("oauth2", Arrays.asList(client(this::injectOAuth2Path)));
		return this;
	}

	public OAuth2MetadataClientBuilder useOAuth2Discovery(String oauth2MetadataUri) {
		this.clientsMap.put("oauth2", Arrays.asList(client(issuer -> URI.create(oauth2MetadataUri))));
		return this;
	}

	public OAuth2MetadataClientBuilder useOidcDiscovery() {
		return useOidcDiscovery(true);
	}

	public OAuth2MetadataClientBuilder useOidcDiscovery(String oidcMetadataUri) {
		this.clientsMap.put("openid", Arrays.asList(client(issuer -> URI.create(oidcMetadataUri))));
		return this;
	}

	public OAuth2MetadataClientBuilder useOidcDiscovery(boolean useRfc8414) {
		List<DiscoveryClient> clients = new ArrayList<>();
		if (useRfc8414) {
			clients.add(client(this::injectOidcPath));
		}
		clients.add(client(this::appendOidcPath));
		this.clientsMap.put("openid", clients);
		return this;
	}

	public OAuth2MetadataClientBuilder useDiscoveryEndpoint(String uri, Function<URI, Map<String, Object>> client) {
		this.clientsMap.put(uri, Arrays.asList(client(issuer -> URI.create(uri))));
		return this;
	}

	private DiscoveryClient client(Function<URI, URI> uriResolver) {
		return issuer -> {
			URI uri = uriResolver.apply(issuer);
			return validate(this.oauth2AuthorizationMetadataClient.apply(uri), issuer);
		};
	}

	public Function<URI, Map<String, Object>> build() {
		Assert.notEmpty(this.clientsMap, "Must configure at least one client");
		return issuer -> {
			List<DiscoveryClient> clients = new ArrayList<>();
			for (List<DiscoveryClient> clientList : this.clientsMap.values()) {
				clients.addAll(clientList);
			}

			for (DiscoveryClient client : clients) {
				try {
					return client.apply(issuer);
				} catch (HttpClientErrorException ex) {
					if (!ex.getStatusCode().is4xxClientError()) {
						throw ex;
					}
				} catch (RuntimeException ex) {
					throw new IllegalStateException("Unable to resolve configuration with the provided issuer of \"" + issuer + "\"", ex);
				}
			}

			throw new IllegalStateException("Unable to resolve configuration with the provided issuer of \"" + issuer + "\"");
		};
	}

	private Map<String, Object> validate(Map<String, Object> metadata, URI issuer) {
		String metadataIssuer = Optional.ofNullable(metadata.get("issuer"))
				.map(Objects::toString)
				.orElseThrow(() -> new IllegalStateException("No issuer specified in configuration response from the requested issuer \"" + issuer + "\""));
		if (!issuer.toASCIIString().equals(metadataIssuer)) {
			throw new IllegalStateException("The issuer \"" + metadataIssuer + "\" provided in the configuration response did not match the requested issuer \"" + issuer + "\"");
		}
		return metadata;
	}

	private URI appendOidcPath(URI uri) {
		String path = uri.getPath();
		return UriComponentsBuilder.fromUri(uri)
				.replacePath("/.well-known/openid-configuration" + path).build().toUri();
	}

	private URI injectOidcPath(URI uri) {
		String path = uri.getPath();
		return UriComponentsBuilder.fromUri(uri)
				.replacePath(path + "/.well-known/openid-configuration").build().toUri();
	}

	private URI injectOAuth2Path(URI uri) {
		String path = uri.getPath();
		return UriComponentsBuilder.fromUri(uri)
				.replacePath("/.well-known/oauth2-authorization-server" + path).build().toUri();
	}
}
