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

package org.springframework.security.adapters.catalina;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;

import org.springframework.security.adapters.PrincipalSpringSecurityUserToken;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.apache.catalina.Container;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.realm.RealmBase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.support.FileSystemXmlApplicationContext;

import java.io.File;

import java.security.Principal;
import java.security.cert.X509Certificate;

import java.util.Map;


/**
 * Adapter to enable Catalina (Tomcat) to authenticate via the Spring Security.<p>Returns a {@link
 * PrincipalSpringSecurityUserToken} to Catalina's authentication system, which is subsequently available via
 * <code>HttpServletRequest.getUserPrincipal()</code>.</p>
 *
 * @author Ben Alex
 * @version $Id:CatalinaSpringSecurityUserRealm.java 2151 2007-09-22 11:54:13Z luke_t $
 */
public class CatalinaSpringSecurityUserRealm extends RealmBase {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(CatalinaSpringSecurityUserRealm.class);

    //~ Instance fields ================================================================================================

    private AuthenticationManager authenticationManager;
    private Container container;
    private String appContextLocation;
    private String key;
    protected final String name = "CatalinaSpringUserRealm / $Id:CatalinaSpringSecurityUserRealm.java 2151 2007-09-22 11:54:13Z luke_t $";

    //~ Methods ========================================================================================================

    public Principal authenticate(String username, String credentials) {
        if (username == null) {
            return null;
        }

        if (credentials == null) {
            credentials = "";
        }

        Authentication request = new UsernamePasswordAuthenticationToken(username, credentials);
        Authentication response = null;

        try {
            response = authenticationManager.authenticate(request);
        } catch (AuthenticationException failed) {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication request for user: " + username + " failed: " + failed.toString());
            }

            return null;
        }

        return new PrincipalSpringSecurityUserToken(this.key, response.getPrincipal().toString(),
            response.getCredentials().toString(), response.getAuthorities(), response.getPrincipal());
    }

    public Principal authenticate(String username, byte[] credentials) {
        return authenticate(username, new String(credentials));
    }

    /**
     * Not supported, returns null
     *
     * @param username DOCUMENT ME!
     * @param digest DOCUMENT ME!
     * @param nonce DOCUMENT ME!
     * @param nc DOCUMENT ME!
     * @param cnonce DOCUMENT ME!
     * @param qop DOCUMENT ME!
     * @param realm DOCUMENT ME!
     * @param md5a2 DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public java.security.Principal authenticate(java.lang.String username, java.lang.String digest,
        java.lang.String nonce, java.lang.String nc, java.lang.String cnonce, java.lang.String qop,
        java.lang.String realm, java.lang.String md5a2) {
        return null;
    }

    /**
     * Not supported, returns null
     *
     * @param x509Certificates DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Principal authenticate(X509Certificate[] x509Certificates) {
        return null;
    }

    public String getAppContextLocation() {
        return appContextLocation;
    }

    public String getKey() {
        return key;
    }

    protected String getName() {
        return this.name;
    }

    /**
     * Always returns null (we override authenticate methods)
     *
     * @param arg0 DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected String getPassword(String arg0) {
        return null;
    }

    /**
     * Always returns null (we override authenticate methods)
     *
     * @param arg0 DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected Principal getPrincipal(String arg0) {
        return null;
    }

    public boolean hasRole(Principal principal, String role) {
        if ((principal == null) || (role == null)) {
            return false;
        }

        if (!(principal instanceof PrincipalSpringSecurityUserToken)) {
            logger.warn("Expected passed principal to be of type PrincipalSpringSecurityUserToken but was "
                + principal.getClass().getName());

            return false;
        }

        PrincipalSpringSecurityUserToken test = (PrincipalSpringSecurityUserToken) principal;

        return test.isUserInRole(role);
    }

    public void setAppContextLocation(String appContextLocation) {
        this.appContextLocation = appContextLocation;
    }

    public void setKey(String key) {
        this.key = key;
    }

    /**
     * Provides the method that Catalina will use to start the container.
     *
     * @throws LifecycleException if a problem is detected
     */
    public void start() throws LifecycleException {
        this.start(true);
    }

    private void start(boolean startParent) throws LifecycleException {
        if (startParent) {
            super.start();
        }

        if ((appContextLocation == null) || "".equals(appContextLocation)) {
            throw new LifecycleException("appContextLocation must be defined");
        }

        if ((key == null) || "".equals(key)) {
            throw new LifecycleException("key must be defined");
        }

        File xml = new File(System.getProperty("catalina.base"), appContextLocation);

        if (!xml.exists()) {
            throw new LifecycleException("appContextLocation does not seem to exist in " + xml.toString());
        }

        FileSystemXmlApplicationContext ctx = new FileSystemXmlApplicationContext("file:" + xml.getAbsolutePath());
        Map beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);

        if (beans.size() == 0) {
            throw new IllegalArgumentException(
                "Bean context must contain at least one bean of type AuthenticationManager");
        }

        String beanName = (String) beans.keySet().iterator().next();
        authenticationManager = (AuthenticationManager) beans.get(beanName);
        logger.info("CatalinaSpringSecurityUserRealm Started");
    }

    /**
     * Provides a method to load the container adapter without delegating to the superclass, which cannot
     * operate outside the Catalina container.
     *
     * @throws LifecycleException if a problem is detected
     */
    protected void startForTest() throws LifecycleException {
        this.start(false);
    }
}
