/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.csrf;

import java.util.function.Supplier;

/**
 * An interface that allows delayed access to a {@link CsrfToken} that may be generated.
 *
 * @author Rob Winch
 * @author Steve Riesenberg
 * @author Daeho Kwon
 * @since 5.8
 */
public interface DeferredCsrfToken extends Supplier<CsrfToken> {

	/**
	 * Gets the {@link CsrfToken}
	 * @return a non-null {@link CsrfToken}
	 */
	CsrfToken get();

	/**
	 * Returns true if {@link #get()} refers to a generated {@link CsrfToken} or false if
	 * it already existed.
	 * @return true if {@link #get()} refers to a generated {@link CsrfToken} or false if
	 * it already existed.
	 */
	boolean isGenerated();

}
