package org.springframework.security.authoritymapping;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


/**
 * <p>
 * This class implements the Attributes2GrantedAuthoritiesMapper and
 * MappableAttributesRetriever interfaces based on the supplied Map.
 * It supports both one-to-one and one-to-many mappings. The granted
 * authorities to map to can be supplied either as a String or as a
 * GrantedAuthority object.
 * </p>
 * @author Ruud Senden
 */
public class MapBasedAttributes2GrantedAuthoritiesMapper implements Attributes2GrantedAuthoritiesMapper, MappableAttributesRetriever, InitializingBean {
	private Map attributes2grantedAuthoritiesMap = null;
	private String stringSeparator = ",";
	private String[] mappableAttributes = null;

	/**
	 * Check whether all properties have been set to correct values, and do some preprocessing.
	 */
	public void afterPropertiesSet() {
		Assert.notEmpty(attributes2grantedAuthoritiesMap,"A non-empty attributes2grantedAuthoritiesMap must be supplied");
		attributes2grantedAuthoritiesMap = preProcessMap(attributes2grantedAuthoritiesMap);
		try {
			mappableAttributes = (String[])attributes2grantedAuthoritiesMap.keySet().toArray(new String[]{});
		} catch ( ArrayStoreException ase ) {
			throw new IllegalArgumentException("attributes2grantedAuthoritiesMap contains non-String objects as keys");
		}
	}

	/**
	 * Preprocess the given map
	 * @param orgMap The map to process
	 * @return the processed Map
	 */
	private Map preProcessMap(Map orgMap) {
		Map result = new HashMap(orgMap.size());
		Iterator it = orgMap.entrySet().iterator();
		while ( it.hasNext() ) {
			Map.Entry entry = (Map.Entry)it.next();
			result.put(entry.getKey(),getGrantedAuthorityCollection(entry.getValue()));
		}
		return result;
	}

	/**
	 * Convert the given value to a collection of Granted Authorities
	 *
	 * @param value
	 *            The value to convert to a GrantedAuthority Collection
	 * @return Collection containing the GrantedAuthority Collection
	 */
	private Collection getGrantedAuthorityCollection(Object value) {
		Collection result = new ArrayList();
		addGrantedAuthorityCollection(result,value);
		return result;
	}

	/**
	 * Convert the given value to a collection of Granted Authorities,
	 * adding the result to the given result collection.
	 *
	 * @param value
	 *            The value to convert to a GrantedAuthority Collection
	 * @return Collection containing the GrantedAuthority Collection
	 */
	private void addGrantedAuthorityCollection(Collection result, Object value) {
		if ( value != null ) {
			if ( value instanceof Collection ) {
				addGrantedAuthorityCollection(result,(Collection)value);
			} else if ( value instanceof Object[] ) {
				addGrantedAuthorityCollection(result,(Object[])value);
			} else if ( value instanceof String ) {
				addGrantedAuthorityCollection(result,(String)value);
			} else if ( value instanceof GrantedAuthority ) {
				result.add(value);
			} else {
				throw new IllegalArgumentException("Invalid object type: "+value.getClass().getName());
			}
		}
	}

	private void addGrantedAuthorityCollection(Collection result, Collection value) {
		Iterator it = value.iterator();
		while ( it.hasNext() ) {
			addGrantedAuthorityCollection(result,it.next());
		}
	}

	private void addGrantedAuthorityCollection(Collection result, Object[] value) {
		for ( int i = 0 ; i < value.length ; i++ ) {
			addGrantedAuthorityCollection(result,value[i]);
		}
	}

	private void addGrantedAuthorityCollection(Collection result, String value) {
		StringTokenizer st = new StringTokenizer(value,stringSeparator,false);
		while ( st.hasMoreTokens() ) {
			String nextToken = st.nextToken();
			if ( StringUtils.hasText(nextToken) ) {
				result.add(new GrantedAuthorityImpl(nextToken));
			}
		}
	}

	/**
	 * Map the given array of attributes to Spring Security GrantedAuthorities.
	 */
	public GrantedAuthority[] getGrantedAuthorities(String[] attributes) {
		List gaList = new ArrayList();
		for (int i = 0; i < attributes.length; i++) {
			Collection c = (Collection)attributes2grantedAuthoritiesMap.get(attributes[i]);
			if ( c != null ) { gaList.addAll(c); }
		}
		GrantedAuthority[] result = new GrantedAuthority[gaList.size()];
		result = (GrantedAuthority[])gaList.toArray(result);
		return result;
	}

	/**
	 * @return Returns the attributes2grantedAuthoritiesMap.
	 */
	public Map getAttributes2grantedAuthoritiesMap() {
		return attributes2grantedAuthoritiesMap;
	}
	/**
	 * @param attributes2grantedAuthoritiesMap The attributes2grantedAuthoritiesMap to set.
	 */
	public void setAttributes2grantedAuthoritiesMap(Map attributes2grantedAuthoritiesMap) {
		this.attributes2grantedAuthoritiesMap = attributes2grantedAuthoritiesMap;
	}

	/**
	 *
	 * @see org.springframework.security.authoritymapping.MappableAttributesRetriever#getMappableAttributes()
	 */
	public String[] getMappableAttributes() {
		return mappableAttributes;
	}
	/**
	 * @return Returns the stringSeparator.
	 */
	public String getStringSeparator() {
		return stringSeparator;
	}
	/**
	 * @param stringSeparator The stringSeparator to set.
	 */
	public void setStringSeparator(String stringSeparator) {
		this.stringSeparator = stringSeparator;
	}
}
