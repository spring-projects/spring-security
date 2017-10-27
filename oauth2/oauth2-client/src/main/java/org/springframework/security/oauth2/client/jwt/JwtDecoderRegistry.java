/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.jwt;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * A registry of {@link JwtDecoder}'s that are associated to a {@link ClientRegistration}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see JwtDecoder
 * @see ClientRegistration
 */
public interface JwtDecoderRegistry {

	JwtDecoder getJwtDecoder(ClientRegistration registration);

}
