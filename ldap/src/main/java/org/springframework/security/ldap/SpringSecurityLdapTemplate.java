/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Extension of Spring LDAP's LdapTemplate class which adds extra functionality required
 * by Spring Security.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Filip Hanik
 * @since 2.0
 */
public class SpringSecurityLdapTemplate extends LdapTemplate {

	private static final Log logger = LogFactory.getLog(SpringSecurityLdapTemplate.class);

	public static final String[] NO_ATTRS = new String[0];

	/**
	 * Every search results where a record is defined by a Map&lt;String,String[]&gt;
	 * contains at least this key - the DN of the record itself.
	 */
	public static final String DN_KEY = "spring.security.ldap.dn";

	private static final boolean RETURN_OBJECT = true;

	/** Default search controls */
	private SearchControls searchControls = new SearchControls();

	public SpringSecurityLdapTemplate(ContextSource contextSource) {
		Assert.notNull(contextSource, "ContextSource cannot be null");
		setContextSource(contextSource);
		this.searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
	}

	/**
	 * Performs an LDAP compare operation of the value of an attribute for a particular
	 * directory entry.
	 * @param dn the entry who's attribute is to be used
	 * @param attributeName the attribute who's value we want to compare
	 * @param value the value to be checked against the directory value
	 * @return true if the supplied value matches that in the directory
	 */
	public boolean compare(String dn, String attributeName, Object value) {
		String comparisonFilter = "(" + attributeName + "={0})";
		return executeReadOnly((ctx) -> {
			SearchControls searchControls = new SearchControls();
			searchControls.setReturningAttributes(NO_ATTRS);
			searchControls.setSearchScope(SearchControls.OBJECT_SCOPE);
			Object[] params = new Object[] { value };
			NamingEnumeration<SearchResult> results = ctx.search(dn, comparisonFilter, params, searchControls);
			boolean match = results.hasMore();
			LdapUtils.closeEnumeration(results);
			return match;
		});
	}

	/**
	 * Composes an object from the attributes of the given DN.
	 * @param dn the directory entry which will be read
	 * @param attributesToRetrieve the named attributes which will be retrieved from the
	 * directory entry.
	 * @return the object created by the mapper
	 */
	public DirContextOperations retrieveEntry(final String dn, final String[] attributesToRetrieve) {
		return executeReadOnly((ctx) -> {
			Attributes attrs = ctx.getAttributes(dn, attributesToRetrieve);
			return new DirContextAdapter(attrs, LdapNameBuilder.newInstance(dn).build(),
					LdapNameBuilder.newInstance(ctx.getNameInNamespace()).build());
		});
	}

	/**
	 * Performs a search using the supplied filter and returns the union of the values of
	 * the named attribute found in all entries matched by the search. Note that one
	 * directory entry may have several values for the attribute. Intended for role
	 * searches and similar scenarios.
	 * @param base the DN to search in
	 * @param filter search filter to use
	 * @param params the parameters to substitute in the search filter
	 * @param attributeName the attribute who's values are to be retrieved.
	 * @return the set of String values for the attribute as a union of the values found
	 * in all the matching entries.
	 */
	public Set<String> searchForSingleAttributeValues(final String base, final String filter, final Object[] params,
			final String attributeName) {
		String[] attributeNames = new String[] { attributeName };
		Set<Map<String, List<String>>> multipleAttributeValues = searchForMultipleAttributeValues(base, filter, params,
				attributeNames);
		Set<String> result = new HashSet<>();
		for (Map<String, List<String>> map : multipleAttributeValues) {
			List<String> values = map.get(attributeName);
			if (values != null) {
				result.addAll(values);
			}
		}
		return result;
	}

	/**
	 * Performs a search using the supplied filter and returns the values of each named
	 * attribute found in all entries matched by the search. Note that one directory entry
	 * may have several values for the attribute. Intended for role searches and similar
	 * scenarios.
	 * @param base the DN to search in
	 * @param filter search filter to use
	 * @param params the parameters to substitute in the search filter
	 * @param attributeNames the attributes' values that are to be retrieved.
	 * @return the set of String values for each attribute found in all the matching
	 * entries. The attribute name is the key for each set of values. In addition each map
	 * contains the DN as a String with the key predefined key {@link #DN_KEY}.
	 */
	public Set<Map<String, List<String>>> searchForMultipleAttributeValues(String base, String filter, Object[] params,
			String[] attributeNames) {
		// Escape the params acording to RFC2254
		Object[] encodedParams = new String[params.length];
		for (int i = 0; i < params.length; i++) {
			encodedParams[i] = LdapEncoder.filterEncode(params[i].toString());
		}
		String formattedFilter = MessageFormat.format(filter, encodedParams);
		logger.trace(LogMessage.format("Using filter: %s", formattedFilter));
		HashSet<Map<String, List<String>>> result = new HashSet<>();
		ContextMapper<?> roleMapper = (ctx) -> {
			DirContextAdapter adapter = (DirContextAdapter) ctx;
			Map<String, List<String>> record = new HashMap<>();
			if (ObjectUtils.isEmpty(attributeNames)) {
				try {
					for (NamingEnumeration<? extends Attribute> enumeration = adapter.getAttributes()
						.getAll(); enumeration.hasMore();) {
						Attribute attr = enumeration.next();
						extractStringAttributeValues(adapter, record, attr.getID());
					}
				}
				catch (NamingException ex) {
					throw org.springframework.ldap.support.LdapUtils.convertLdapException(ex);
				}
			}
			else {
				for (String attributeName : attributeNames) {
					extractStringAttributeValues(adapter, record, attributeName);
				}
			}
			record.put(DN_KEY, Collections.singletonList(getAdapterDN(adapter)));
			result.add(record);
			return null;
		};
		SearchControls ctls = new SearchControls();
		ctls.setSearchScope(this.searchControls.getSearchScope());
		ctls.setReturningAttributes((attributeNames != null && attributeNames.length > 0) ? attributeNames : null);
		search(base, formattedFilter, ctls, roleMapper);
		return result;
	}

	/**
	 * Returns the DN for the context representing this LDAP record. By default this is
	 * using {@link javax.naming.Context#getNameInNamespace()} instead of
	 * {@link org.springframework.ldap.core.DirContextAdapter#getDn()} since the latter
	 * returns a partial DN if a base has been specified.
	 * @param adapter - the Context to extract the DN from
	 * @return - the String representing the full DN
	 */
	private String getAdapterDN(DirContextAdapter adapter) {
		// returns the full DN rather than the sub DN if a base is specified
		return adapter.getNameInNamespace();
	}

	/**
	 * Extracts String values for a specified attribute name and places them in the map
	 * representing the ldap record If a value is not of type String, it will derive it's
	 * value from the {@link Object#toString()}
	 * @param adapter - the adapter that contains the values
	 * @param record - the map holding the attribute names and values
	 * @param attributeName - the name for which to fetch the values from
	 */
	private void extractStringAttributeValues(DirContextAdapter adapter, Map<String, List<String>> record,
			String attributeName) {
		Object[] values = adapter.getObjectAttributes(attributeName);
		if (values == null || values.length == 0) {
			logger.debug(LogMessage.format("Did not find attribute value for %s", attributeName));
			return;
		}
		List<String> stringValues = new ArrayList<>();
		for (Object value : values) {
			if (value != null) {
				if (String.class.isAssignableFrom(value.getClass())) {
					stringValues.add((String) value);
				}
				else {
					stringValues.add(value.toString());
					logger.debug(LogMessage.format("Coerced attribute value for %s of type %s to a String",
							attributeName, value.getClass()));
				}
			}
		}
		record.put(attributeName, stringValues);
	}

	/**
	 * Performs a search, with the requirement that the search shall return a single
	 * directory entry, and uses the supplied mapper to create the object from that entry.
	 * <p>
	 * Ignores <tt>PartialResultException</tt> if thrown, for compatibility with Active
	 * Directory (see {@link LdapTemplate#setIgnorePartialResultException(boolean)}).
	 * @param base the search base, relative to the base context supplied by the context
	 * source.
	 * @param filter the LDAP search filter
	 * @param params parameters to be substituted in the search.
	 * @return a DirContextOperations instance created from the matching entry.
	 * @throws IncorrectResultSizeDataAccessException if no results are found or the
	 * search returns more than one result.
	 */
	public DirContextOperations searchForSingleEntry(String base, String filter, Object[] params) {
		return executeReadOnly((ctx) -> searchForSingleEntryInternal(ctx, this.searchControls, base, filter, params));
	}

	/**
	 * Internal method extracted to avoid code duplication in AD search.
	 */
	public static DirContextOperations searchForSingleEntryInternal(DirContext ctx, SearchControls searchControls,
			String base, String filter, Object[] params) throws NamingException {
		final LdapName ctxBaseDn = LdapNameBuilder.newInstance(ctx.getNameInNamespace()).build();
		final LdapName searchBaseDn = LdapNameBuilder.newInstance(base).build();
		final NamingEnumeration<SearchResult> resultsEnum = ctx.search(searchBaseDn, filter, params,
				buildControls(searchControls));
		logger.trace(LogMessage.format("Searching for entry under DN '%s', base = '%s', filter = '%s'", ctxBaseDn,
				searchBaseDn, filter));
		Set<DirContextOperations> results = new HashSet<>();
		try {
			while (resultsEnum.hasMore()) {
				SearchResult searchResult = resultsEnum.next();
				DirContextAdapter dca = (DirContextAdapter) searchResult.getObject();
				Assert.notNull(dca, "No object returned by search, DirContext is not correctly configured");
				logger.debug(LogMessage.format("Found DN: %s", dca.getDn()));
				results.add(dca);
			}
		}
		catch (PartialResultException ex) {
			LdapUtils.closeEnumeration(resultsEnum);
			logger.trace("Ignoring PartialResultException");
		}
		if (results.size() != 1) {
			throw new IncorrectResultSizeDataAccessException(1, results.size());
		}
		return results.iterator().next();
	}

	/**
	 * We need to make sure the search controls has the return object flag set to true, in
	 * order for the search to return DirContextAdapter instances.
	 * @param originalControls the {@link SearchControls} that might have the return
	 * object flag set to true
	 * @return a {@link SearchControls} that does have the return object flag set to true
	 */
	private static SearchControls buildControls(SearchControls originalControls) {
		return new SearchControls(originalControls.getSearchScope(), originalControls.getCountLimit(),
				originalControls.getTimeLimit(), originalControls.getReturningAttributes(), RETURN_OBJECT,
				originalControls.getDerefLinkFlag());
	}

	/**
	 * Sets the search controls which will be used for search operations by the template.
	 * @param searchControls the SearchControls instance which will be cached in the
	 * template.
	 */
	public void setSearchControls(SearchControls searchControls) {
		this.searchControls = searchControls;
	}

}
