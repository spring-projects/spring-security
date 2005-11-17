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

package org.acegisecurity;

/**
 * Represents an authority granted to an {@link Authentication} object.
 * 
 * <p>
 * A <code>GrantedAuthority</code> must either represent itself as a
 * <code>String</code> or be specifically supported by an  {@link
 * AccessDecisionManager}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface GrantedAuthority {
    //~ Methods ================================================================

    /**
     * If the <code>GrantedAuthority</code> can be represented as a
     * <code>String</code> and that <code>String</code> is sufficient in
     * precision to be relied upon for an access control decision by an {@link
     * AccessDecisionManager} (or delegate), this method should return such a
     * <code>String</code>.
     * 
     * <p>
     * If the <code>GrantedAuthority</code> cannot be expressed with sufficient
     * precision as a <code>String</code>,  <code>null</code> should be
     * returned. Returning <code>null</code> will require an
     * <code>AccessDecisionManager</code> (or delegate) to  specifically
     * support the <code>GrantedAuthority</code> implementation,  so returning
     * <code>null</code> should be avoided unless actually  required.
     * </p>
     *
     * @return a representation of the granted authority (or <code>null</code>
     *         if the granted authority cannot be expressed as a
     *         <code>String</code> with sufficient precision).
     */
    public String getAuthority();
}
