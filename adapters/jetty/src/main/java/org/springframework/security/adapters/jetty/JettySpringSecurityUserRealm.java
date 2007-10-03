/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.adapters.jetty;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.mortbay.http.HttpRequest;
import org.mortbay.http.UserPrincipal;
import org.mortbay.http.UserRealm;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.Map;


/**
 * Adapter to enable Jetty to authenticate via Spring Security.<p>Returns a {@link
 * JettySpringSecurityUserToken} to Jetty's authentication system, which is subsequently available via
 * <code>HttpServletRequest.getUserPrincipal()</code>.</p>
 *
 * @author Ben Alex
 * @version $Id:JettySpringSecurityUserRealm.java 2151 2007-09-22 11:54:13Z luke_t $
 */
public final class JettySpringSecurityUserRealm implements UserRealm {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(JettySpringSecurityUserRealm.class);

    //~ Instance fields ================================================================================================

    private AuthenticationManager authenticationManager;
    private String key;
    private String realm;

    //~ Constructors ===================================================================================================

/**
     * Construct a <code>SpringUserRealm</code>.
     *
     * @param realm the name of the authentication realm (within Jetty)
     * @param providerKey a password to sign all authentication objects
     * @param appContextLocation the classpath location of the bean context XML
     *        file
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public JettySpringSecurityUserRealm(String realm, String providerKey, String appContextLocation) {
        this.realm = realm;
        this.key = providerKey;

        if ((realm == null) || "".equals(realm)) {
            throw new IllegalArgumentException("realm must be specified");
        }

        if ((key == null) || "".equals(key)) {
            throw new IllegalArgumentException("key must be specified");
        }

        if ((appContextLocation == null) || "".equals(appContextLocation)) {
            throw new IllegalArgumentException("appContextLocation must be specified");
        }

        if (Thread.currentThread().getContextClassLoader().getResource(appContextLocation) == null) {
            throw new IllegalArgumentException("Cannot locate " + appContextLocation);
        }

        ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext(appContextLocation);
        Map beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);

        if (beans.size() == 0) {
            throw new IllegalArgumentException(
                "Bean context must contain at least one bean of type AuthenticationManager");
        }

        String beanName = (String) beans.keySet().iterator().next();
        authenticationManager = (AuthenticationManager) beans.get(beanName);
    }

    protected JettySpringSecurityUserRealm() {
        throw new IllegalArgumentException("Cannot use default constructor");
    }

    //~ Methods ========================================================================================================

    public UserPrincipal authenticate(String username, Object password, HttpRequest httpRequest) {
        if (username == null) {
            return null;
        }

        if (password == null) {
            password = "";
        }

        Authentication request = new UsernamePasswordAuthenticationToken(username.toString(), password.toString());
        Authentication response = null;

        try {
            response = authenticationManager.authenticate(request);
        } catch (AuthenticationException failed) {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication request for user: " + username + " failed: " + failed.toString());
            }

            return null;
        }

        return new JettySpringSecurityUserToken(this.key, response.getPrincipal().toString(),
            response.getCredentials().toString(), response.getAuthorities());
    }

    public void disassociate(UserPrincipal userPrincipal) {
        // No action required
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    /**
     * Accesses the realm name.
     *
     * @return the name of the realm as defined when <code>SpringUserRealm</code> was created
     */
    public String getName() {
        return this.realm;
    }

    public void logout(UserPrincipal arg0) {
        // Not supported
    }

    public UserPrincipal popRole(UserPrincipal userPrincipal) {
        // Not supported
        return userPrincipal;
    }

    public UserPrincipal pushRole(UserPrincipal userPrincipal, String role) {
        // Not supported
        return userPrincipal;
    }
}
