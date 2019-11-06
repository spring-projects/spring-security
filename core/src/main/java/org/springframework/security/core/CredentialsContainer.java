/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.core;

/**
 * Indicates that the implementing object contains sensitive data, which can be erased
 * using the {@code eraseCredentials} method. Implementations are expected to invoke the
 * method on any internal objects which may also implement this interface.
 * <p>
 * For internal framework use only. Users who are writing their own
 * {@code AuthenticationProvider} implementations should create and return an appropriate
 * {@code Authentication} object there, minus any sensitive data, rather than using this
 * interface.
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public interface CredentialsContainer {
	void eraseCredentials();
}
