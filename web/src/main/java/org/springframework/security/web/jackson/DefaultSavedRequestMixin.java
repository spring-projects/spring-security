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

package org.springframework.security.web.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import tools.jackson.databind.annotation.JsonDeserialize;

import org.springframework.security.web.savedrequest.DefaultSavedRequest;

/**
 * Jackson mixin class to serialize/deserialize {@link DefaultSavedRequest}. This mixin
 * use {@link DefaultSavedRequest.Builder} to deserialized json.In order to use this mixin
 * class you also need to register {@link CookieMixin}.
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see WebServletJacksonModule
 * @see org.springframework.security.jackson.SecurityJacksonModules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(builder = DefaultSavedRequest.Builder.class)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
abstract class DefaultSavedRequestMixin {

	@JsonInclude(JsonInclude.Include.NON_NULL)
	String matchingRequestParameterName;

}
