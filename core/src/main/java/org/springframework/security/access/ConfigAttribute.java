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

package org.springframework.security.access;

import java.io.Serializable;

import org.springframework.security.access.intercept.RunAsManager;

/**
 * Stores a security system related configuration attribute.
 *
 * <p>
 * When an
 * {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor} is
 * set up, a list of configuration attributes is defined for secure object patterns. These
 * configuration attributes have special meaning to a {@link RunAsManager},
 * {@link AccessDecisionManager} or <code>AccessDecisionManager</code> delegate.
 *
 * <p>
 * Stored at runtime with other <code>ConfigAttribute</code>s for the same secure object
 * target.
 *
 * @author Ben Alex
 */
public interface ConfigAttribute extends Serializable {
	// ~ Methods
	// ========================================================================================================

	/**
	 * If the <code>ConfigAttribute</code> can be represented as a <code>String</code> and
	 * that <code>String</code> is sufficient in precision to be relied upon as a
	 * configuration parameter by a {@link RunAsManager}, {@link AccessDecisionManager} or
	 * <code>AccessDecisionManager</code> delegate, this method should return such a
	 * <code>String</code>.
	 * <p>
	 * If the <code>ConfigAttribute</code> cannot be expressed with sufficient precision
	 * as a <code>String</code>, <code>null</code> should be returned. Returning
	 * <code>null</code> will require any relying classes to specifically support the
	 * <code>ConfigAttribute</code> implementation, so returning <code>null</code> should
	 * be avoided unless actually required.
	 *
	 * @return a representation of the configuration attribute (or <code>null</code> if
	 * the configuration attribute cannot be expressed as a <code>String</code> with
	 * sufficient precision).
	 */
	String getAttribute();
}
