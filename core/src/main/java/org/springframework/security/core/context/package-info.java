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
/**
 * Classes related to the establishment of a security context for the duration of a request (such as
 * an HTTP or RMI invocation).
 * <p>
 * A security context is usually associated with the current execution thread for the duration of the request,
 * making the authentication information it contains available throughout all the layers of an application.
 * <p>
 * The {@link org.springframework.security.core.context.SecurityContext SecurityContext} can be accessed at any point
 * by calling the {@link org.springframework.security.core.context.SecurityContextHolder SecurityContextHolder}.
 */
package org.springframework.security.core.context;

