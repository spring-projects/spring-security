/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
 * An {@link Authentication} that is also buildable.
 *
 * @author Josh Cummings
 * @since 7.0
 */
public interface BuildableAuthentication extends Authentication {

	/**
	 * Return an {@link Builder} based on this instance.
	 * <p>
	 * Although a {@code default} method, all {@link BuildableAuthentication}
	 * implementations should implement this. The reason is to ensure that the
	 * {@link BuildableAuthentication} type is preserved when {@link Builder#build} is
	 * invoked. This is especially important in the event that your authentication
	 * implementation contains custom fields.
	 * </p>
	 * <p>
	 * This isn't strictly necessary since it is recommended that applications code to the
	 * {@link Authentication} interface and that custom information is often contained in
	 * the {@link Authentication#getPrincipal} value.
	 * </p>
	 * @return an {@link Builder} for building a new {@link Authentication} based on this
	 * instance
	 */
	Builder<?> toBuilder();

}
