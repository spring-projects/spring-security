package org.springframework.security.ldap;

import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.ContextSource;

import javax.naming.directory.DirContext;

/**
 * Extension of {@link ContextSource} which allows binding explicitly as a particular user.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 *
 * @deprecated As of Spring LDAP 1.3, ContextSource provides this method itself.
 */
public interface SpringSecurityContextSource extends BaseLdapPathContextSource {

    /**
     * Obtains a context using the supplied distinguished name and credentials.
     *
     * @param userDn the distinguished name of the user to authenticate as
     * @param credentials the user's password
     * @return a context authenticated as the supplied user
     */
    DirContext getReadWriteContext(String userDn, Object credentials);

}
