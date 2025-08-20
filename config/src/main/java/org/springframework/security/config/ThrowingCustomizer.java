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

package org.springframework.security.config;

/**
 * A {@link Customizer} that allows invocation of code that throws a checked exception.
 *
 * @param <T> The type of input.
 */
@FunctionalInterface
public interface ThrowingCustomizer<T> extends Customizer<T> {

	/**
	 * Default {@link Customizer#customize(Object)} that wraps any thrown checked
	 * exceptions (by default in a {@link RuntimeException}).
	 * @param t the object to customize
	 */
	default void customize(T t) {
		try {
			customizeWithException(t);
		}
		catch (RuntimeException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	/**
	 * Performs the customization on the given object, possibly throwing a checked
	 * exception.
	 * @param t the object to customize
	 * @throws Exception on error
	 */
	void customizeWithException(T t) throws Exception;

}
