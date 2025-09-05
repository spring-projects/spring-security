/*
 * Copyright 2020-2021 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.jackson2;

import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * This mixin class is used to serialize/deserialize {@link HashSet}.
 *
 * @author Steve Riesenberg
 * @since 0.1.2
 * @see HashSet
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
abstract class HashSetMixin {

	@JsonCreator
	HashSetMixin(Set<?> set) {
	}

}
