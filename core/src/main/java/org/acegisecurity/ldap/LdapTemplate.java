/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.ldap;

import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;

/**
 * LDAP equivalent of the Spring JdbcTemplate class.
 *
 * @author Ben Alex
 * @author Luke Taylor
 *
 */
public class LdapTemplate {
    public static final String[] NO_ATTRS = new String[0];

    private InitialDirContextFactory dirContextFactory;
    private String userDn = null;
    private String password = null;

    public LdapTemplate(InitialDirContextFactory dirContextFactory) {
        Assert.notNull(dirContextFactory, "An InitialDirContextFactory is required");
        this.dirContextFactory = dirContextFactory;
    }

    public LdapTemplate(InitialDirContextFactory dirContextFactory, String userDn, String password) {
        this(dirContextFactory);

        Assert.hasLength(userDn, "userDn must not be null or empty");
        Assert.notNull(password, "password cannot be null");

        this.userDn = userDn;
        this.password = password;
    }

    public Object execute(LdapCallback callback) throws DataAccessException {
        DirContext ctx = null;

        try {
            ctx = (userDn == null) ?
                    dirContextFactory.newInitialDirContext() :
                    dirContextFactory.newInitialDirContext(userDn, password);

            return callback.execute(ctx);

        } catch (NamingException exception) {
            // TODO: Write a static method in separate NamingExceptionExceptionTranslator class called public DataAccessException convert(NamingException);
            throw new LdapDataAccessException("xxxx", exception);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }


    public boolean compare(final String dn, final String attributeName, final Object value) {
        final String comparisonFilter = "(" + attributeName + "={0})";

        class LdapCompareCallback implements LdapCallback {

            public Object execute(DirContext ctx) throws NamingException {
                SearchControls ctls = new SearchControls();
                ctls.setReturningAttributes(NO_ATTRS);
                ctls.setSearchScope(SearchControls.OBJECT_SCOPE);

                NamingEnumeration results =
                        ctx.search(dn, comparisonFilter, new Object[]{value}, ctls);

                return Boolean.valueOf(results.hasMore());
            }
        }


        Boolean matches = (Boolean)execute(new LdapCompareCallback());

        return matches.booleanValue();
    }
}
