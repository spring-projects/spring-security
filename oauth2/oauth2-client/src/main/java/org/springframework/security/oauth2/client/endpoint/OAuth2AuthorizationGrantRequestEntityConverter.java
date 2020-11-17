/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.util.MultiValueMap;

/**
 * Implementations of this interface are responsible for {@link Converter#convert(Object)
 * converting} the provided {@link AbstractOAuth2AuthorizationGrantRequest authorization
 * grant credential} to a {@link RequestEntity} representation of an OAuth 2.0 Access
 * Token Request.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see Converter
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see RequestEntity
 * @param <T> the type of {@link AbstractOAuth2AuthorizationGrantRequest}
 */
@FunctionalInterface
public interface OAuth2AuthorizationGrantRequestEntityConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		extends Converter<T, RequestEntity<?>> {

	/**
	 * Implementations of this interface are provided the opportunity to customize the
	 * {@link RequestEntity} representation of the OAuth 2.0 Access Token Request.
	 *
	 * @param <T> the type of {@link AbstractOAuth2AuthorizationGrantRequest}
	 */
	@FunctionalInterface
	interface Customizer<T> {

		/**
		 * Customize the {@link HttpHeaders headers} and/or {@link MultiValueMap
		 * parameters} of the OAuth 2.0 Access Token Request.
		 * @param authorizationGrantRequest the authorization grant request
		 * @param headers the headers
		 * @param parameters the parameters
		 */
		void customize(T authorizationGrantRequest, HttpHeaders headers, MultiValueMap<String, String> parameters);

	}

}
