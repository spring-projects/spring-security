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

package org.springframework.security.ldap;

import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.ContextExecutor;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.text.MessageFormat;
import java.util.HashSet;
import java.util.Set;
import java.util.Arrays;


/**
 * LDAP equivalent of the Spring JdbcTemplate class.
 * <p>
 * This is mainly intended to simplify Ldap access within Spring Security's LDAP-related services.
 * </p>
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class SpringSecurityLdapTemplate extends org.springframework.ldap.core.LdapTemplate {
    //~ Static fields/initializers =====================================================================================
    private static final Log logger = LogFactory.getLog(SpringSecurityLdapTemplate.class);

    public static final String[] NO_ATTRS = new String[0];

    //~ Instance fields ================================================================================================

    /** Default search controls */
    private SearchControls searchControls = new SearchControls();

    //~ Constructors ===================================================================================================

    public SpringSecurityLdapTemplate(ContextSource contextSource) {
        Assert.notNull(contextSource, "ContextSource cannot be null");
        setContextSource(contextSource);

        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
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

        class LdapCompareCallback implements ContextExecutor {

            public Object executeWithContext(DirContext ctx) throws NamingException {
                SearchControls ctls = new SearchControls();
                ctls.setReturningAttributes(NO_ATTRS);
                ctls.setSearchScope(SearchControls.OBJECT_SCOPE);

                NamingEnumeration results = ctx.search(dn, comparisonFilter, new Object[] {value}, ctls);

                return Boolean.valueOf(results.hasMore());
            }
        }

        Boolean matches = (Boolean) executeReadOnly(new LdapCompareCallback());

        return matches.booleanValue();
    }

    /**
     * Composes an object from the attributes of the given DN.
     *
     * @param dn the directory entry which will be read
     * @param attributesToRetrieve the named attributes which will be retrieved from the directory entry.
     *
     * @return the object created by the mapper
     */
    public DirContextOperations retrieveEntry(final String dn, final String[] attributesToRetrieve) {

        return (DirContextOperations) executeReadOnly(new ContextExecutor() {
                public Object executeWithContext(DirContext ctx) throws NamingException {
                    Attributes attrs = ctx.getAttributes(dn, attributesToRetrieve);

                    // Object object = ctx.lookup(LdapUtils.getRelativeName(dn, ctx));

                    return new DirContextAdapter(attrs, new DistinguishedName(dn));
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

        String formattedFilter = MessageFormat.format(filter, params);

        final HashSet set = new HashSet();

        ContextMapper roleMapper = new ContextMapper() {
            public Object mapFromContext(Object ctx) {
                DirContextAdapter adapter = (DirContextAdapter) ctx;
                String[] values = adapter.getStringAttributes(attributeName);
                if (values == null || values.length == 0) {
                    logger.debug("No attribute value found for '" + attributeName + "'");
                } else {
                    set.addAll(Arrays.asList(values));
                }
                return null;
            }
        };

        SearchControls ctls = new SearchControls();
        ctls.setSearchScope(searchControls.getSearchScope());
        ctls.setReturningAttributes(new String[] {attributeName});
        ctls.setReturningObjFlag(false);

        search(base, formattedFilter, ctls, roleMapper);

        return set;
    }

    /**
     * Performs a search, with the requirement that the search shall return a single directory entry, and uses
     * the supplied mapper to create the object from that entry.
     *
     * @param base
     * @param filter
     * @param params
     *
     * @return the object created by the mapper from the matching entry
     *
     * @throws IncorrectResultSizeDataAccessException if no results are found or the search returns more than one
     *         result.
     */
    public DirContextOperations searchForSingleEntry(final String base, final String filter, final Object[] params) {

        return (DirContextOperations) executeReadOnly(new ContextExecutor() {
                public Object executeWithContext(DirContext ctx)
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

                    return new DirContextAdapter(searchResult.getAttributes(), new DistinguishedName(dn.toString()));
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
}
