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

package org.springframework.security.cas.jackson;

import java.util.Date;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apereo.cas.client.authentication.AttributePrincipal;

/**
 * Helps in jackson deserialization of class
 * {@link org.apereo.cas.client.validation.AssertionImpl}, which is used with
 * {@link org.springframework.security.cas.authentication.CasAuthenticationToken}.
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see CasJacksonModule
 * @see org.springframework.security.jackson.SecurityJacksonModules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
class AssertionImplMixin {

	/**
	 * Mixin Constructor helps in deserialize
	 * {@link org.apereo.cas.client.validation.AssertionImpl}
	 * @param principal the Principal to associate with the Assertion.
	 * @param validFromDate when the assertion is valid from.
	 * @param validUntilDate when the assertion is valid to.
	 * @param authenticationDate when the assertion is authenticated.
	 * @param attributes the key/value pairs for this attribute.
	 */
	@JsonCreator
	AssertionImplMixin(@JsonProperty("principal") AttributePrincipal principal,
			@JsonProperty("validFromDate") Date validFromDate, @JsonProperty("validUntilDate") Date validUntilDate,
			@JsonProperty("authenticationDate") Date authenticationDate,
			@JsonProperty("attributes") Map<String, Object> attributes) {
	}

}
