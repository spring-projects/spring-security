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

package org.acegisecurity.providers.rcp;

import org.acegisecurity.GrantedAuthority;


/**
 * Allows remote clients to attempt authentication.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface RemoteAuthenticationManager {
    //~ Methods ================================================================

    /**
     * Attempts to authenticate the remote client using the presented username
     * and password. If authentication is successful, an array of
     * <code>GrantedAuthority[]</code> objects will be returned.
     * 
     * <P>
     * In order to maximise remoting protocol compatibility, a design decision
     * was taken to operate with minimal arguments and return only the minimal
     * amount information required for remote clients to enable/disable
     * relevant user interface commands etc. There is nothing preventing users
     * from implementing their own equivalent package that works with more
     * complex object types.
     * </p>
     *
     * @param username the username the remote client wishes to authenticate
     *        with
     * @param password the password the remote client wishes to authenticate
     *        wish
     *
     * @return all of the granted authorities the specified username and
     *         password have access to
     *
     * @throws RemoteAuthenticationException if the authentication failed
     */
    public GrantedAuthority[] attemptAuthentication(String username,
        String password) throws RemoteAuthenticationException;
}
