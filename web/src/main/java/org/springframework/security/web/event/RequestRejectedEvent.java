/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.event;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.event.EventFailureAccessor;
import org.springframework.security.event.SecurityEvent;

/**
 * An event representing a rejected request and its corresponding exception
 *
 * @param <T> the type of exception
 * @author Josh Cummings
 * @since 6.0
 */
public class RequestRejectedEvent<T extends Throwable> extends SecurityEvent implements EventFailureAccessor<T> {

	private final T error;

	public RequestRejectedEvent(HttpServletRequest request, T error) {
		super(request);
		this.error = error;
	}

	/**
	 * Get the error associated with this rejected request
	 * @return the error
	 */
	@Override
	public T getError() {
		return this.error;
	}

}
