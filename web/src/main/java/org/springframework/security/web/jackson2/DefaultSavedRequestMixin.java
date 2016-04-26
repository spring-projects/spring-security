/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

import java.util.Map;

/**
` * Jackson mixin class to serialize/deserialize {@link DefaultSavedRequest}. This mixin use
 * {@link org.springframework.security.web.savedrequest.DefaultSavedRequest.Builder} to
 * deserialized josn.In order to use this mixin class you also need to register
 * {@link CookieMixin}.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.addMixIn(Cookie.class, CookieMixin.class);
 *     mapper.addMixIn(DefaultSavedRequest.class, DefaultSavedRequestMixin.class);
 * </pre>
 *
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonDeserialize(builder = DefaultSavedRequest.Builder.class)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.PUBLIC_ONLY)
@JsonIgnoreProperties(
		value = {"headerNames", "headerValues", "parameterNames", "redirectUrl"}
)
public abstract class DefaultSavedRequestMixin {

	/**
	 * This method will ensure that all the request parameters will must in 'parameters' key.
	 * @return
	 */
	@JsonProperty("parameters")
	public abstract Map<String, String[]> getParameterMap();
}
