package org.springframework.security.ldap;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.StringTokenizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.util.Assert;

/**
 * ContextSource implementation which uses Spring LDAP's <tt>LdapContextSource</tt> as a base
 * class. Used internally by the Spring Security LDAP namespace configuration.
 * <p>
 * From Spring Security 3.0, Spring LDAP 1.3 is used and the <tt>ContextSource</tt> interface
 * provides support for binding with a username and password. As a result, Spring LDAP <tt>ContextSource</tt>
 * implementations such as <tt>LdapContextSource</tt> may be used directly with Spring Security.
 * <p>
 * Spring LDAP 1.3 doesn't have JVM-level LDAP connection pooling enabled by default. This class sets the
 * <tt>pooled</tt> property to true, but customizes the {@link DirContextAuthenticationStrategy} used to disable
 * pooling when the <tt>DN</tt> doesn't match the <tt>userDn</tt> property. This prevents pooling for calls
 * to {@link #getContext(String, String)} to authenticate as specific users.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class DefaultSpringSecurityContextSource extends LdapContextSource {
    protected final Log logger = LogFactory.getLog(getClass());

    private String rootDn;

    /**
     * Create and initialize an instance which will connect to the supplied LDAP URL.
     *
     * @param providerUrl an LDAP URL of the form <code>ldap://localhost:389/base_dn<code>
     */
    public DefaultSpringSecurityContextSource(String providerUrl) {
        Assert.hasLength(providerUrl, "An LDAP connection URL must be supplied.");

        StringTokenizer st = new StringTokenizer(providerUrl);

        ArrayList<String> urls = new ArrayList<String>();

        // Work out rootDn from the first URL and check that the other URLs (if any) match
        while (st.hasMoreTokens()) {
            String url = st.nextToken();
            String urlRootDn = LdapUtils.parseRootDnFromUrl(url);

            urls.add(url.substring(0, url.lastIndexOf(urlRootDn)));

            logger.info(" URL '" + url + "', root DN is '" + urlRootDn + "'");

            if (rootDn == null) {
                rootDn = urlRootDn;
            } else if (!rootDn.equals(urlRootDn)) {
                throw new IllegalArgumentException("Root DNs must be the same when using multiple URLs");
            }
        }

        setUrls(urls.toArray(new String[urls.size()]));
        setBase(rootDn);
        setPooled(true);
        setAuthenticationStrategy(new SimpleDirContextAuthenticationStrategy() {
            @Override
            @SuppressWarnings("unchecked")
            public void setupEnvironment(Hashtable env, String dn, String password) {
                super.setupEnvironment(env, dn, password);
                // Remove the pooling flag unless we are authenticating as the 'manager' user.
                if (!userDn.equals(dn) && env.containsKey(SUN_LDAP_POOLING_FLAG)) {
                    logger.debug("Removing pooling flag for user " + dn);
                    env.remove(SUN_LDAP_POOLING_FLAG);
                }
            }
        });
    }
}
