/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.jwt;

/**
 * A factory for {@link ReactiveJwtDecoder}(s). This factory should be supplied with a
 * type that provides contextual information used to create a specific
 * {@code ReactiveJwtDecoder}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ReactiveJwtDecoder
 * @param <C> The type that provides contextual information used to create a specific
 * {@code ReactiveJwtDecoder}.
 */
@FunctionalInterface
public interface ReactiveJwtDecoderFactory<C> {

	/**
	 * Creates a {@code ReactiveJwtDecoder} using the supplied "contextual" type.
	 * @param context the type that provides contextual information
	 * @return a {@link ReactiveJwtDecoder}
	 */
	ReactiveJwtDecoder createDecoder(C context);

}
