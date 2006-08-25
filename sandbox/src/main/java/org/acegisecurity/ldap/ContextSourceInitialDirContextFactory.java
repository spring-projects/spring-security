package org.acegisecurity.ldap;

import net.sf.ldaptemplate.ContextSource;

import javax.naming.directory.DirContext;

import org.springframework.dao.DataAccessException;

/**
 * A version of InitialDirContextFactory that implements the ldaptemplate ContextSource interface.
 *
 * DefaultInitialDirContextFactory should be modified to implement this when it is possible to
 * introduce a dependency on ldaptemplate in the main code. 
 *
 * @author Luke
 * @version $Id$
 */
public class ContextSourceInitialDirContextFactory extends DefaultInitialDirContextFactory implements ContextSource {
    public ContextSourceInitialDirContextFactory(String providerUrl) {
        super(providerUrl);
    }

    public DirContext getReadOnlyContext() throws DataAccessException {
        return newInitialDirContext();
    }

    public DirContext getReadWriteContext() throws DataAccessException {
        return newInitialDirContext();
    }
}
