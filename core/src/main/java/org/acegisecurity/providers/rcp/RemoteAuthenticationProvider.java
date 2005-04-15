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

package net.sf.acegisecurity.providers.rcp;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;


/**
 * Client-side object which queries a  {@link RemoteAuthenticationManager} to
 * validate an authentication request.
 * 
 * <P>
 * A new <code>Authentication</code> object is created by this class comprising
 * the request <code>Authentication</code> object's <code>principal</code>,
 * <code>credentials</code> and the <code>GrantedAuthority</code>[]s returned
 * by the <code>RemoteAuthenticationManager</code>.
 * </p>
 * 
 * <P>
 * The <code>RemoteAuthenticationManager</code> should not require any special
 * username or password setting on the remoting client proxy factory to
 * execute the call. Instead the entire authentication request must be
 * encapsulated solely within the <code>Authentication</code> request object.
 * In practical terms this means the <code>RemoteAuthenticationManager</code>
 * will <B>not</B> be protected by BASIC or any other HTTP-level
 * authentication.
 * </p>
 * 
 * <P>
 * If authentication fails, a <code>RemoteAuthenticationException</code> will
 * be thrown. This exception should be caught and displayed to the user,
 * enabling them to retry with alternative credentials etc.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RemoteAuthenticationProvider implements AuthenticationProvider,
    InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(RemoteAuthenticationProvider.class);

    //~ Instance fields ========================================================

    private RemoteAuthenticationManager remoteAuthenticationManager;

    //~ Methods ================================================================

    public void setRemoteAuthenticationManager(
        RemoteAuthenticationManager remoteAuthenticationManager) {
        this.remoteAuthenticationManager = remoteAuthenticationManager;
    }

    public RemoteAuthenticationManager getRemoteAuthenticationManager() {
        return remoteAuthenticationManager;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.remoteAuthenticationManager, "remoteAuthenticationManager is mandatory");
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        String username = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();
        GrantedAuthority[] authorities = remoteAuthenticationManager
            .attemptAuthentication(username, password);

        return new UsernamePasswordAuthenticationToken(username, password,
            authorities);
    }

    public boolean supports(Class authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
