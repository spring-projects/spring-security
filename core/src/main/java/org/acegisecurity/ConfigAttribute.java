/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity;

/**
 * Stores a security system related configuration attribute.
 * 
 * <p>
 * When the {@link SecurityInterceptor} is setup, a list of configuration
 * attributes is defined for secure method patterns. These configuration
 * attributes have special meaning to a {@link RunAsManager}, {@link
 * AccessDecisionManager} or <code>AccessDecisionManager</code> delegate.
 * </p>
 * 
 * <P>
 * Stored at runtime with other <code>ConfigAttribute</code>s for the same
 * method within a {@link ConfigAttributeDefinition}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ConfigAttribute {
    //~ Methods ================================================================

    /**
     * If the <code>ConfigAttribute</code> can be represented as a
     * <code>String</code> and that <code>String</code> is sufficient in
     * precision to be relied upon as a configuration parameter by a {@link
     * RunAsManager}, {@link AccessDecisionManager} or
     * <code>AccessDecisionManager</code> delegate, this method should  return
     * such a <code>String</code>.
     * 
     * <p>
     * If the <code>ConfigAttribute</code> cannot be expressed with sufficient
     * precision as a <code>String</code>,  <code>null</code> should be
     * returned. Returning <code>null</code> will require an relying classes
     * to specifically support the  <code>ConfigAttribute</code>
     * implementation, so returning  <code>null</code> should be avoided
     * unless actually  required.
     * </p>
     *
     * @return a representation of the configuration attribute (or
     *         <code>null</code> if the configuration attribute cannot be
     *         expressed as a <code>String</code> with sufficient precision).
     */
    public String getAttribute();
}
