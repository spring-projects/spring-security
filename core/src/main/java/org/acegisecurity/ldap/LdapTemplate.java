/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;


/**
 * LDAP equivalent of the Spring JdbcTemplate class.<p>This is mainly intended to simplify Ldap access within Acegi
 * Security's LDAP-related services.</p>
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class LdapTemplate {
    //~ Static fields/initializers =====================================================================================

    public static final String[] NO_ATTRS = new String[0];

    //~ Instance fields ================================================================================================

    private InitialDirContextFactory dirContextFactory;
    private NamingExceptionTranslator exceptionTranslator = new LdapExceptionTranslator();

    /** Default search controls */
    private SearchControls searchControls = new SearchControls();
    private String password = null;
    private String principalDn = null;

    //~ Constructors ===================================================================================================

    public LdapTemplate(InitialDirContextFactory dirContextFactory) {
        Assert.notNull(dirContextFactory, "An InitialDirContextFactory is required");
        this.dirContextFactory = dirContextFactory;

        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

/**
     *
     * @param dirContextFactory the source of DirContexts
     * @param userDn the user name to authenticate as when obtaining new contexts
     * @param password the user's password
     */
    public LdapTemplate(InitialDirContextFactory dirContextFactory, String userDn, String password) {
        this(dirContextFactory);

        Assert.hasLength(userDn, "userDn must not be null or empty");
        Assert.notNull(password, "password cannot be null");

        this.principalDn = userDn;
        this.password = password;
    }

    //~ Methods ========================================================================================================

    /**
     * Performs an LDAP compare operation of the value of an attribute for a particular directory entry.
     *
     * @param dn the entry who's attribute is to be used
     * @param attributeName the attribute who's value we want to compare
     * @param value the value to be checked against the directory value
     *
     * @return true if the supplied value matches that in the directory
     */
    public boolean compare(final String dn, final String attributeName, final Object value) {
        final String comparisonFilter = "(" + attributeName + "={0})";

        class LdapCompareCallback implements LdapCallback {
            public Object doInDirContext(DirContext ctx)
                throws NamingException {
                SearchControls ctls = new SearchControls();
                ctls.setReturningAttributes(NO_ATTRS);
                ctls.setSearchScope(SearchControls.OBJECT_SCOPE);

                String relativeName = LdapUtils.getRelativeName(dn, ctx);

                NamingEnumeration results = ctx.search(relativeName, comparisonFilter, new Object[] {value}, ctls);

                return Boolean.valueOf(results.hasMore());
            }
        }

        Boolean matches = (Boolean) execute(new LdapCompareCallback());

        return matches.booleanValue();
    }

    public Object execute(LdapCallback callback) throws DataAccessException {
        DirContext ctx = null;

        try {
            ctx = (principalDn == null) ? dirContextFactory.newInitialDirContext()
                                        : dirContextFactory.newInitialDirContext(principalDn, password);

            return callback.doInDirContext(ctx);
        } catch (NamingException exception) {
            throw exceptionTranslator.translate("LdapCallback", exception);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    public boolean nameExists(final String dn) {
        Boolean exists = (Boolean) execute(new LdapCallback() {
                    public Object doInDirContext(DirContext ctx)
                        throws NamingException {
                        try {
                            ctx.lookup(LdapUtils.getRelativeName(dn, ctx));
                        } catch (NameNotFoundException nnfe) {
                            return Boolean.FALSE;
                        }

                        return Boolean.TRUE;
                    }
                });

        return exists.booleanValue();
    }

    /**
     * Composes an object from the attributes of the given DN.
     *
     * @param dn the directory entry which will be read
     * @param mapper maps the attributes to the required object
     * @param attributesToRetrieve the named attributes which will be retrieved from the directory entry.
     *
     * @return the object created by the mapper
     */
    public Object retrieveEntry(final String dn, final LdapEntryMapper mapper, final String[] attributesToRetrieve) {
        return execute(new LdapCallback() {
                public Object doInDirContext(DirContext ctx)
                    throws NamingException {
                    return mapper.mapAttributes(dn,
                        ctx.getAttributes(LdapUtils.getRelativeName(dn, ctx), attributesToRetrieve));
                }
            });
    }

    /**
     * Performs a search using the supplied filter and returns the union of the values of the named attribute
     * found in all entries matched by the search. Note that one directory entry may have several values for the
     * attribute. Intended for role searches and similar scenarios.
     *
     * @param base the DN to search in
     * @param filter search filter to use
     * @param params the parameters to substitute in the search filter
     * @param attributeName the attribute who's values are to be retrieved.
     *
     * @return the set of String values for the attribute as a union of the values found in all the matching entries.
     */
    public Set searchForSingleAttributeValues(final String base, final String filter, final Object[] params,
        final String attributeName) {
        class SingleAttributeSearchCallback implements LdapCallback {
            public Object doInDirContext(DirContext ctx)
                throws NamingException {
                Set unionOfValues = new HashSet();

                // We're only interested in a single attribute for this method, so we make a copy of
                // the search controls and override the returningAttributes property
                SearchControls ctls = new SearchControls();

                ctls.setSearchScope(searchControls.getSearchScope());
                ctls.setTimeLimit(searchControls.getTimeLimit());
                ctls.setDerefLinkFlag(searchControls.getDerefLinkFlag());
                ctls.setReturningAttributes(new String[] {attributeName});

                NamingEnumeration matchingEntries = ctx.search(base, filter, params, ctls);

                while (matchingEntries.hasMore()) {
                    SearchResult result = (SearchResult) matchingEntries.next();
                    Attributes attrs = result.getAttributes();

                    // There should only be one attribute in each matching entry.
                    NamingEnumeration returnedAttributes = attrs.getAll();

                    while (returnedAttributes.hasMore()) {
                        Attribute returnedAttribute = (Attribute) returnedAttributes.next();
                        NamingEnumeration attributeValues = returnedAttribute.getAll();

                        while (attributeValues.hasMore()) {
                            Object value = attributeValues.next();

                            unionOfValues.add(value.toString());
                        }
                    }
                }

                return unionOfValues;
            }
        }

        return (Set) execute(new SingleAttributeSearchCallback());
    }

    /**
     * Performs a search, with the requirement that the search shall return a single directory entry, and uses
     * the supplied mapper to create the object from that entry.
     *
     * @param base
     * @param filter
     * @param params
     * @param mapper
     *
     * @return the object created by the mapper from the matching entry
     *
     * @throws IncorrectResultSizeDataAccessException if no results are found or the search returns more than one result.
     */
    public Object searchForSingleEntry(final String base, final String filter, final Object[] params,
        final LdapEntryMapper mapper) {
        return execute(new LdapCallback() {
                public Object doInDirContext(DirContext ctx)
                    throws NamingException {
                    NamingEnumeration results = ctx.search(base, filter, params, searchControls);

                    if (!results.hasMore()) {
                        throw new IncorrectResultSizeDataAccessException(1, 0);
                    }

                    SearchResult searchResult = (SearchResult) results.next();

                    if (results.hasMore()) {
                        // We don't know how many results but set to 2 which is good enough
                        throw new IncorrectResultSizeDataAccessException(1, 2);
                    }

                    // Work out the DN of the matched entry
                    StringBuffer dn = new StringBuffer(searchResult.getName());

                    if (base.length() > 0) {
                        dn.append(",");
                        dn.append(base);
                    }

                    String nameInNamespace = ctx.getNameInNamespace();

                    if (StringUtils.hasLength(nameInNamespace)) {
                        dn.append(",");
                        dn.append(nameInNamespace);
                    }

                    return mapper.mapAttributes(dn.toString(), searchResult.getAttributes());
                }
            });
    }

    /**
     * Sets the search controls which will be used for search operations by the template.
     *
     * @param searchControls the SearchControls instance which will be cached in the template.
     */
    public void setSearchControls(SearchControls searchControls) {
        this.searchControls = searchControls;
    }

    //~ Inner Classes ==================================================================================================

    private static class LdapExceptionTranslator implements NamingExceptionTranslator {
        public DataAccessException translate(String task, NamingException e) {
            return new LdapDataAccessException(task + ";" + e.getMessage(), e);
        }
    }
}
