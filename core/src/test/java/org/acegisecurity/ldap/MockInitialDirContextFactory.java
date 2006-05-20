package org.acegisecurity.ldap;

import javax.naming.directory.DirContext;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class MockInitialDirContextFactory implements InitialDirContextFactory {
    DirContext ctx;
    String baseDn;

    public MockInitialDirContextFactory(DirContext ctx, String baseDn) {
        this.baseDn = baseDn;
        this.ctx = ctx;
    }

    public DirContext newInitialDirContext() {
        return ctx;
    }

    public DirContext newInitialDirContext(String username, String password) {
        return ctx;
    }

    public String getRootDn() {
        return baseDn;
    }
}
