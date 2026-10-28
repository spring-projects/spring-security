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

package org.springframework.security.oauth2.server.authorization.jackson2;

import java.time.Clock;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;

/**
 * This mixin class is used to serialize/deserialize {@link OAuth2Authorization.Token}.
 *
 * @author Dawid Szczepaniak
 * @since 7.1.1
 * @see OAuth2Authorization.Token
 * @see OAuth2AuthorizationServerJackson2Module
 * @see OAuth2AuthorizationServerJacksonModule
 */
@SuppressWarnings("removal")
public abstract class OAuth2AuthorizationTokenMixin {

	@JsonIgnore
	@Nullable private Clock clock;

}
