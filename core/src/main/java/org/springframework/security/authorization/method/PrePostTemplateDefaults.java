/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization.method;

import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;

/**
 * A component for configuring various cross-cutting aspects of pre/post method security
 *
 * @author Josh Cummings
 * @since 6.3
 * @see org.springframework.security.access.prepost.PreAuthorize
 * @see org.springframework.security.access.prepost.PostAuthorize
 * @see org.springframework.security.access.prepost.PreFilter
 * @see org.springframework.security.access.prepost.PostFilter
 * @deprecated Please use {@link AnnotationTemplateExpressionDefaults} instead
 */
@Deprecated
public final class PrePostTemplateDefaults {

	private boolean ignoreUnknown = true;

	/**
	 * Whether template resolution should ignore placeholders it doesn't recognize.
	 * <p>
	 * By default, this value is <code>true</code>.
	 */
	public boolean isIgnoreUnknown() {
		return this.ignoreUnknown;
	}

	/**
	 * Configure template resolution to ignore unknown placeholders. When set to
	 * <code>false</code>, template resolution will throw an exception for unknown
	 * placeholders.
	 * <p>
	 * By default, this value is <code>true</code>.
	 * @param ignoreUnknown - whether to ignore unknown placeholders parameters
	 */
	public void setIgnoreUnknown(boolean ignoreUnknown) {
		this.ignoreUnknown = ignoreUnknown;
	}

}
