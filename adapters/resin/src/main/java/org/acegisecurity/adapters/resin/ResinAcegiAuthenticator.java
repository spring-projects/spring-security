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

package net.sf.acegisecurity.adapters.resin;

import com.caucho.http.security.AbstractAuthenticator;

import com.caucho.vfs.Path;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.adapters.PrincipalAcegiUserToken;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.support.FileSystemXmlApplicationContext;

import java.io.File;

import java.security.Principal;

import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Adapter to enable Resin to authenticate via the Acegi Security System for
 * Spring.
 * 
 * <p>
 * Returns a {@link PrincipalAcegiUserToken} to Resin's authentication system,
 * which is subsequently available via
 * <code>HttpServletRequest.getUserPrincipal()</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ResinAcegiAuthenticator extends AbstractAuthenticator {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(ResinAcegiAuthenticator.class);

    //~ Instance fields ========================================================

    private AuthenticationManager authenticationManager;
    private Path appContextLocation;
    private String key;

    //~ Methods ================================================================

    public void setAppContextLocation(Path appContextLocation) {
        this.appContextLocation = appContextLocation;
    }

    public Path getAppContextLocation() {
        return appContextLocation;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public boolean isUserInRole(HttpServletRequest request,
        HttpServletResponse response, ServletContext application,
        Principal principal, String role) {
        if (!(principal instanceof PrincipalAcegiUserToken)) {
            if (logger.isWarnEnabled()) {
                logger.warn(
                    "Expected passed principal to be of type PrincipalSpringUserToken but was "
                    + principal.getClass().getName());
            }

            return false;
        }

        PrincipalAcegiUserToken test = (PrincipalAcegiUserToken) principal;

        return test.isUserInRole(role);
    }

    public void init() throws ServletException {
        super.init();

        if (appContextLocation == null) {
            throw new ServletException("appContextLocation must be defined");
        }

        if (key == null) {
            throw new ServletException("key must be defined");
        }

        File xml = new File(appContextLocation.getPath());

        if (!xml.exists()) {
            throw new ServletException(
                "appContextLocation does not seem to exist - try specifying WEB-INF/resin-springsecurity.xml");
        }

        FileSystemXmlApplicationContext ctx = new FileSystemXmlApplicationContext(xml
                .getAbsolutePath());
        Map beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);

        if (beans.size() == 0) {
            throw new ServletException(
                "Bean context must contain at least one bean of type AuthenticationManager");
        }

        String beanName = (String) beans.keySet().iterator().next();
        authenticationManager = (AuthenticationManager) beans.get(beanName);
        logger.info("ResinSpringAuthenticator Started");
    }

    protected Principal loginImpl(String username, String credentials) {
        if (username == null) {
            return null;
        }

        if (credentials == null) {
            credentials = "";
        }

        Authentication request = new UsernamePasswordAuthenticationToken(username,
                credentials);
        Authentication response = null;

        try {
            response = authenticationManager.authenticate(request);
        } catch (AuthenticationException failed) {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication request for user: " + username
                    + " failed: " + failed.toString());
            }

            return null;
        }

        return new PrincipalAcegiUserToken(this.key,
            response.getPrincipal().toString(),
            response.getCredentials().toString(), response.getAuthorities());
    }

    protected Principal loginImpl(HttpServletRequest request,
        HttpServletResponse response, ServletContext application,
        String userName, String password) throws ServletException {
        return loginImpl(userName, password);
    }
}
