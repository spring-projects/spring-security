/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.jackson2;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * This mixin class used to deserialize java.util.Collections$UnmodifiableRandomAccessList
 * and used with various AuthenticationToken implementation's mixin classes.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CoreJackson2Module());
 * </pre>
 *
 * @author Rob Winch
 * @since 5.0.2
 * @see UnmodifiableListDeserializer
 * @see CoreJackson2Module
 * @see SecurityJackson2Modules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonDeserialize(using = UnmodifiableListDeserializer.class)
class UnmodifiableListMixin {

	/**
	 * Mixin Constructor
	 * @param s the Set
	 */
	@JsonCreator
	UnmodifiableListMixin(Set<?> s) {
	}

}
