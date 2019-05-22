/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config;

/**
 * Callback interface that accepts a single input argument and returns no result,
 * with the ability to throw a (checked) exception.
 *
 * @author Eleftheria Stein
 * @param <T> the type of the input to the operation
 * @since 5.2
 */
@FunctionalInterface
public interface Customizer<T> {

	/**
	 * Performs the customizations on the input argument.
	 *
	 * @param t the input argument
	 * @throws Exception if any error occurs
	 */
	void customize(T t) throws Exception;

	/**
	 * Returns a {@link Customizer} that does not alter the input argument.
	 *
	 * @return a {@link Customizer} that does not alter the input argument.
	 */
	static <T> Customizer<T> withDefaults() {
		return t -> {};
	}
}
