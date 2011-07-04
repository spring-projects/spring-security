package org.springframework.security.ldap;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
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
     * Create and initialize an instance which will connect to the supplied LDAP URL. If you
     * want to use more than one server for fail-over, rather use
     * the {@link #DefaultSpringSecurityContextSource(List, String)} constructor.
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

    /**
     * Create and initialize an instance which will connect of the LDAP Spring Security
     * Context Source. It will connect to any of the provided LDAP server URLs.
     * 
     * @param urls
     *          A list of string values which are LDAP server URLs. An example would be
     *          <code>ldap://ldap.company.com:389</code>. LDAPS URLs (SSL-secured) may be used as well,
     *          given that Spring Security is able to connect to the server.
     *          Note that these <b>URLs must not include the base DN</b>!
     * @param baseDn
     *          The common Base DN for all provided servers, e.g.
     *          <pre>dc=company,dc=com</pre>.
     */
    public DefaultSpringSecurityContextSource(List<String> urls, String baseDn) {
        this(buildProviderUrl(urls, baseDn));
    }

    /**
     * Builds a Spring LDAP-compliant Provider URL string, i.e. a space-separated list of LDAP servers
     * with their base DNs. As the base DN must be identical for all servers, it needs to be supplied
     * only once.
     * 
     * @param urls
     *          A list of string values which are LDAP server URLs. An example would be
     *          <pre>ldap://ldap.company.com:389</pre>. LDAPS URLs may be used as well,
     *          given that Spring Security is able to connect to the server.
     * @param baseDn
     *          The common Base DN for all provided servers, e.g.
     *          <pre>dc=company,dc=com</pre>.
     * @return A Spring Security/Spring LDAP-compliant Provider URL string.
     */
    private static String buildProviderUrl(List<String> urls, String baseDn) {
        Assert.notNull(baseDn, "The Base DN for the LDAP server must not be null.");
        Assert.notEmpty(urls, "At least one LDAP server URL must be provided.");

        String trimmedBaseDn = baseDn.trim();
        StringBuilder providerUrl = new StringBuilder();

        for (String serverUrl : urls) {
            String trimmedUrl = serverUrl.trim();
            if ("".equals(trimmedUrl)) {
                continue;
            }
            if (trimmedUrl.contains(trimmedBaseDn)) {
                throw new IllegalArgumentException("LDAP URL string must not include the base DN! '" + trimmedUrl + "'");
            }

            providerUrl.append(trimmedUrl);
            if (! trimmedUrl.endsWith("/")) {
                providerUrl.append("/");
            }
            providerUrl.append(trimmedBaseDn);
            providerUrl.append(" ");
        }

        return providerUrl.toString();

    }

}
