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

package org.springframework.security.web.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;

/**
 * Jackson mixin for {@link PublicKeyCredentialType}
 *
 * @author Rob Winch
 * @since 6.4
 * @deprecated as of 7.0 in favor of
 * {@link org.springframework.security.web.webauthn.jackson.PublicKeyCredentialTypeMixin}
 * based on Jackson 3
 */
@SuppressWarnings("removal")
@Deprecated(forRemoval = true)
@JsonSerialize(using = PublicKeyCredentialTypeJackson2Serializer.class)
@JsonDeserialize(using = PublicKeyCredentialTypeJackson2Deserializer.class)
abstract class PublicKeyCredentialTypeJackson2Mixin {

}
