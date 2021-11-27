/*
 * Copyright 2015-2016 the original author or authors.
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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * This mixin class helps in serialize/deserialize
 * {@link org.springframework.security.core.userdetails.User}. This class also register a
 * custom deserializer {@link UserDeserializer} to deserialize User object successfully.
 * In order to use this mixin you need to register two more mixin classes in your
 * ObjectMapper configuration.
 * <ol>
 * <li>{@link SimpleGrantedAuthorityMixin}</li>
 * <li>{@link UnmodifiableSetMixin}</li>
 * </ol>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CoreJackson2Module());
 * </pre>
 *
 * @author Jitendra Singh
 * @since 4.2
 * @see UserDeserializer
 * @see CoreJackson2Module
 * @see SecurityJackson2Modules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonDeserialize(using = UserDeserializer.class)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class UserMixin {

}
