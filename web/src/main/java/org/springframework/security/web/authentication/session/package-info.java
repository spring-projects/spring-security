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
 * Strategy interface and implementations for handling session-related behaviour for a
 * newly authenticated user.
 * <p>
 * Comes with support for:
 * <ul>
 * <li>Protection against session-fixation attacks</li>
 * <li>Controlling the number of sessions an authenticated user can have open</li>
 * </ul>
 */
@NullMarked
package org.springframework.security.web.authentication.session;

import org.jspecify.annotations.NullMarked;
