package org.springframework.security.ldap.authentication.ad;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.LdapUtils;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.*;

/**
 * Specialized LDAP authentication provider which uses Active Directory configuration conventions.
 * <p>
 * It will authenticate using the Active Directory {@code userPrincipalName} (in the form {@code username@domain}).
 * If the {@code usernameIncludesDomain} property is set to {@code true}, it is assumed that the user types in the
 * full value, including the domain. Otherwise (the default), the {@code userPrincipalName} will be built from the
 * username supplied in the authentication request.
 * <p>
 * The user authorities are obtained from the data contained in the {@code memberOf} attribute.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public final class ActiveDirectoryLdapAuthenticationProvider extends AbstractLdapAuthenticationProvider {
    private final String domain;
    private final String rootDn;
    private final String url;
    private boolean usernameIncludesDomain = false;

    /**
     * @param domain the domain for which authentication should take place
     */
//    public ActiveDirectoryLdapAuthenticationProvider(String domain) {
//        this (domain, null);
//    }

    /**
     * @param domain the domain name
     * @param url an LDAP url (or multiple URLs)
     */
    public ActiveDirectoryLdapAuthenticationProvider(String domain, String url) {
        Assert.isTrue(StringUtils.hasText(domain) || StringUtils.hasText(url), "Domain and url cannot both be empty");
        this.domain = StringUtils.hasText(domain) ? domain : null;
        this.url = StringUtils.hasText(url) ? url : null;
        rootDn = this.domain == null ? null : rootDnFromDomain(this.domain);
    }

    @Override
    protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken auth) {
        String username = auth.getName();
        String password = (String)auth.getCredentials();

        LdapContext ctx = bindAsUser(username, password);

        try {
            return searchForUser(ctx, username);

        } catch (NamingException e) {
            logger.error("Failed to locate directory entry for authentication user: " + username, e);
            throw authenticationFailure();
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    /**
     * Creates the user authority list from the values of the {@code memberOf} attribute obtained from the user's
     * Active Directory entry.
     */
    @Override
    protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations userData, String username, String password) {
        String[] groups = userData.getStringAttributes("memberOf");

        if (groups == null) {
            logger.debug("No values for 'memberOf' attribute.");

            return AuthorityUtils.NO_AUTHORITIES;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("'memberOf' attribute values: " + Arrays.asList(groups));
        }

        ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(groups.length);

        for (String group : groups) {
            authorities.add(new SimpleGrantedAuthority(new DistinguishedName(group).removeLast().getValue()));
        }

        return authorities;
    }

    private LdapContext bindAsUser(String username, String password) {
        // TODO. add DNS lookup based on domain
        final String bindUrl = url;

        Hashtable<String,String> env = new Hashtable<String,String>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, createBindPrincipal(username));
        env.put(Context.PROVIDER_URL, bindUrl);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            return new InitialLdapContext(env, null);
        } catch (NamingException e) {
            logger.debug("Authentication failed", e);
            throw authenticationFailure();
        }
    }

    private BadCredentialsException authenticationFailure() {
        return new BadCredentialsException(messages.getMessage(
                        "LdapAuthenticationProvider.badCredentials", "Bad credentials"));
    }

    private DirContextOperations searchForUser(LdapContext ctx, String username) throws NamingException {
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String searchFilter = "(&(objectClass=user)(userPrincipalName={0}))";

        final String bindPrincipal = createBindPrincipal(username);

        String searchRoot = rootDn != null ? rootDn : searchRootFromPrincipal(bindPrincipal);

        return SpringSecurityLdapTemplate.searchForSingleEntryInternal(ctx, searchCtls, searchRoot, searchFilter,
                new Object[]{bindPrincipal});
    }

    private String searchRootFromPrincipal(String bindPrincipal) {
        return rootDnFromDomain(bindPrincipal.substring(bindPrincipal.lastIndexOf('@') + 1, bindPrincipal.length()));
    }

    private String rootDnFromDomain(String domain) {
        String[] tokens = StringUtils.tokenizeToStringArray(domain, ".");
        StringBuilder root = new StringBuilder();

        for (String token : tokens) {
            if (root.length() > 0) {
                root.append(',');
            }
            root.append("dc=").append(token);
        }

        return root.toString();
    }

    private String createBindPrincipal(String username) {
        if (usernameIncludesDomain || domain == null) {
            return username;
        }

        return username + "@" + domain;
    }

    public void setUsernameIncludesDomain(boolean usernameIncludesDomain) {
        Assert.isTrue(domain != null || usernameIncludesDomain,
                "If the domain name is not included in the username, a domain must be set in the constructor");
        this.usernameIncludesDomain = usernameIncludesDomain;
    }

}
