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

/**
 * Classes related to the caching of an {@code HttpServletRequest} which requires
 * authentication. While the user is logging in, the request is cached (using the
 * RequestCache implementation) by the ExceptionTranslationFilter. Once the user has been
 * authenticated, the original request is restored following a redirect to a matching URL,
 * and the {@code RequestCache} is queried to obtain the original (matching) request.
 */
@NullMarked
package org.springframework.security.web.savedrequest;

import org.jspecify.annotations.NullMarked;
