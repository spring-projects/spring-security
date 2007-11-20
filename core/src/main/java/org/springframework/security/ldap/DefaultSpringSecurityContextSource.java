package org.springframework.security.ldap;

import org.springframework.security.BadCredentialsException;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.StringTokenizer;

/**
 * SpringSecurityContextSource implementation which uses Spring LDAP's <tt>LdapContextSource</tt> as a base
 * class. Intended as a replacement for <tt>DefaultInitialDirContextFactory</tt> from versions of the framework prior
 * to 2.0.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class DefaultSpringSecurityContextSource extends LdapContextSource implements SpringSecurityContextSource,
        MessageSourceAware {

    private static final Log logger = LogFactory.getLog(DefaultSpringSecurityContextSource.class);
    private String rootDn;

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    /**
     * Create and initialize an instance which will connect to the supplied LDAP URL.
     *
     * @param providerUrl an LDAP URL of the form <code>ldap://localhost:389/base_dn<code>
     */
    public DefaultSpringSecurityContextSource(String providerUrl) {
        Assert.hasLength(providerUrl, "An LDAP connection URL must be supplied.");

        StringTokenizer st = new StringTokenizer(providerUrl);

        ArrayList urls = new ArrayList();

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

        super.setUrls((String[]) urls.toArray(new String[urls.size()]));
        super.setBase(rootDn);
    }

    public DirContext getReadWriteContext(String userDn, Object credentials) {
        Hashtable env = new Hashtable(getAnonymousEnv());

        env.put(Context.SECURITY_PRINCIPAL, userDn);
        env.put(Context.SECURITY_CREDENTIALS, credentials);

        if (logger.isDebugEnabled()) {
            logger.debug("Creating context with principal: '" + userDn + "'");
        }

        try {
            return createContext(env);
        } catch (org.springframework.ldap.NamingException e) {
            if ((e instanceof org.springframework.ldap.AuthenticationException)
                    || (e instanceof org.springframework.ldap.OperationNotSupportedException)) {
                throw new BadCredentialsException(
                        messages.getMessage("DefaultSpringSecurityContextSource.badCredentials", "Bad credentials"), e);
            }
            throw e;
        }
    }

    /** Copied from parent <tt>AbstractContextSource</tt> as package private */
    DirContext createContext(Hashtable environment) {
		DirContext ctx = null;

		try {
			ctx = getDirContextInstance(environment);

			if (logger.isInfoEnabled()) {
				Hashtable ctxEnv = ctx.getEnvironment();
				String ldapUrl = (String) ctxEnv.get(Context.PROVIDER_URL);
				logger.debug("Got Ldap context on server '" + ldapUrl + "'");
			}

			return ctx;
		}
		catch (NamingException e) {
			LdapUtils.closeContext(ctx);
			throw org.springframework.ldap.support.LdapUtils.convertLdapException(e);
		}
	}

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }
}
