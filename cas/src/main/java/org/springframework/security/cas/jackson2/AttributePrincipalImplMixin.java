/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.cas.jackson2;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apereo.cas.client.proxy.ProxyRetriever;

/**
 * Helps in deserialize
 * {@link org.apereo.cas.client.authentication.AttributePrincipalImpl} which is used with
 * {@link org.springframework.security.cas.authentication.CasAuthenticationToken}. Type
 * information will be stored in property named @class.
 *
 * <p>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CasJackson2Module());
 * </pre>
 *
 * @author Jitendra Singh
 * @since 4.2
 * @see CasJackson2Module
 * @see org.springframework.security.jackson2.SecurityJackson2Modules
 * @deprecated as of 7.0 in favor of
 * {@code org.springframework.security.cas.jackson.AttributePrincipalImplMixin} based on
 * Jackson 3
 */
@SuppressWarnings("removal")
@Deprecated(forRemoval = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
class AttributePrincipalImplMixin {

	/**
	 * Mixin Constructor helps in deserialize
	 * {@link org.apereo.cas.client.authentication.AttributePrincipalImpl}
	 * @param name the unique identifier for the principal.
	 * @param attributes the key/value pairs for this principal.
	 * @param proxyGrantingTicket the ticket associated with this principal.
	 * @param proxyRetriever the ProxyRetriever implementation to call back to the CAS
	 * server.
	 */
	@JsonCreator
	AttributePrincipalImplMixin(@JsonProperty("name") String name,
			@JsonProperty("attributes") Map<String, Object> attributes,
			@JsonProperty("proxyGrantingTicket") String proxyGrantingTicket,
			@JsonProperty("proxyRetriever") ProxyRetriever proxyRetriever) {
	}

}
