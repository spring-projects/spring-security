/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters.jetty;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.mortbay.http.HttpRequest;
import org.mortbay.http.UserPrincipal;
import org.mortbay.http.UserRealm;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.Map;


/**
 * Adapter to enable Jetty to authenticate via the Acegi Security System for
 * Spring.
 * 
 * <p>
 * Returns a {@link JettyAcegiUserToken} to Jetty's authentication system,
 * which is subsequently available via
 * <code>HttpServletRequest.getUserPrincipal()</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public final class JettyAcegiUserRealm implements UserRealm {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(JettyAcegiUserRealm.class);

    //~ Instance fields ========================================================

    private AuthenticationManager authenticationManager;
    private String key;
    private String realm;

    //~ Constructors ===========================================================

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
    public JettyAcegiUserRealm(String realm, String providerKey,
        String appContextLocation) {
        this.realm = realm;
        this.key = providerKey;

        ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext(appContextLocation);
        Map beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);

        if (beans.size() == 0) {
            throw new IllegalArgumentException(
                "Bean context must contain at least one bean of type AuthenticationManager");
        }

        String beanName = (String) beans.keySet().iterator().next();
        authenticationManager = (AuthenticationManager) beans.get(beanName);
    }

    private JettyAcegiUserRealm() {
        super();
    }

    //~ Methods ================================================================

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    /**
     * DOCUMENT ME!
     *
     * @return the name of the realm as defined when
     *         <code>SpringUserRealm</code> was created
     */
    public String getName() {
        return this.realm;
    }

    public UserPrincipal authenticate(String username, Object password,
        HttpRequest httpRequest) {
        if (username == null) {
            return null;
        }

        if (password == null) {
            password = "";
        }

        Authentication request = new UsernamePasswordAuthenticationToken(username
                .toString(), password.toString());
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

        return new JettyAcegiUserToken(this.key,
            response.getPrincipal().toString(),
            response.getCredentials().toString(), response.getAuthorities());
    }

    public void disassociate(UserPrincipal userPrincipal) {
        // No action required
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
