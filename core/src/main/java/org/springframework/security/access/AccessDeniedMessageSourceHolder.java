/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.access;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

/**
 * Provide a {@link org.springframework.context.support.MessageSourceAccessor} singleton
 *
 * @author Dayan Kodippily
 * @since 5.6
 */
final class AccessDeniedMessageSourceHolder {

	private AccessDeniedMessageSourceHolder() {
	}

	static MessageSourceAccessor getInstance() {
		return MessageSourceAccessorHolder.INSTANCE;
	}

	private static class MessageSourceAccessorHolder {

		private static final MessageSourceAccessor INSTANCE = SpringSecurityMessageSource.getAccessor();

	}

}
