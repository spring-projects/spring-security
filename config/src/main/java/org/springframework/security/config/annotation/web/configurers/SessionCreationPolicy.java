/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;

/**
 * Specifies the various session creation policies for Spring Security.
 *
 * FIXME this should be removed once {@link org.springframework.security.config.http.SessionCreationPolicy} is made public.
 *
 * @author Rob Winch
 * @since 3.2
 */
public enum SessionCreationPolicy {
    /** Always create an {@link HttpSession} */
    always,
    /** Spring Security will never create an {@link HttpSession}, but will use the {@link HttpSession} if it already exists */
    never,
    /** Spring Security will only create an {@link HttpSession} if required */
    ifRequired,
    /** Spring Security will never create an {@link HttpSession} and it will never use it to obtain the {@link SecurityContext} */
    stateless
}