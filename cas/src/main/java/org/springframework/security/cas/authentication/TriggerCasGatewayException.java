/*
 * Copyright 2013-2013 the original author or authors.
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

package org.springframework.security.cas.authentication;

import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.core.AuthenticationException;

/**
 * Exception used to indicate the {@link CasAuthenticationEntryPoint} to make a CAS gateway authentication request.
 *
 * @author Michael Remond
 *
 */
public class TriggerCasGatewayException extends AuthenticationException {
 

	private static final long serialVersionUID = 4864856111227081697L;

	//~ Constructors ===================================================================================================

	/**
     * Constructs an {@code InitiateCasGatewayAuthenticationException} with the specified message and no root cause.
     *
     * @param msg the detail message
     */
    public TriggerCasGatewayException(String msg) {
        super(msg);
    }

    /**
     * Constructs an {@code InitiateCasGatewayAuthenticationException} with the specified message and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public TriggerCasGatewayException(String msg, Throwable t) {
        super(msg, t);
    }

}