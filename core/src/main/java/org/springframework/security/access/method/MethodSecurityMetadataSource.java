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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.authorization.AuthorizationManager;

/**
 * Interface for <code>SecurityMetadataSource</code> implementations that are designed to
 * perform lookups keyed on <code>Method</code>s.
 *
 * @author Ben Alex
 * @see org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager
 * @see org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager
 * @deprecated Use the {@code use-authorization-manager} attribute for
 * {@code <method-security>} and {@code <intercept-methods>} instead or use
 * annotation-based or {@link AuthorizationManager}-based authorization
 */
@Deprecated
public interface MethodSecurityMetadataSource extends SecurityMetadataSource {

	Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass);

}
