package org.springframework.security.ldap;

import java.util.ArrayList;
import java.util.StringTokenizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.util.Assert;

/**
 * ContextSource implementation which uses Spring LDAP's <tt>LdapContextSource</tt> as a base
 * class. Used internally by the Spring Security LDAP namespace configuration.
 * <p>
 * From Spring Security 2.5, Spring LDAP 1.3 is used and the <tt>ContextSource</tt> interface
 * provides support for binding with a username and password. As a result, Spring LDAP <tt>ContextSource</tt>
 * implementations such as <tt>LdapContextSource</tt> may be used directly with Spring Security.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class DefaultSpringSecurityContextSource extends LdapContextSource {

    private static final Log logger = LogFactory.getLog(DefaultSpringSecurityContextSource.class);
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

        super.setUrls(urls.toArray(new String[urls.size()]));
        super.setBase(rootDn);
    }
}
