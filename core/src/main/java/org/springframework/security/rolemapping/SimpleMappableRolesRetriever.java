package org.springframework.security.rolemapping;

import org.springframework.util.Assert;

/**
 * This class implements the MappableRolesRetriever interface by just returning
 * a list of mappable roles as previously set using the corresponding setter
 * method.
 */
public class SimpleMappableRolesRetriever implements MappableRolesRetriever {
	private String[] mappableRoles = null;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.rolemapping.MappableRolesRetriever#getMappableRoles()
	 */
	public String[] getMappableRoles() {
		Assert.notNull(mappableRoles, "No mappable roles have been set");
		String[] copy = new String[mappableRoles.length];
		System.arraycopy(mappableRoles, 0, copy, 0, copy.length);
		return copy;
	}

	public void setMappableRoles(String[] aMappableRoles) {
		this.mappableRoles = new String[aMappableRoles.length];
		System.arraycopy(aMappableRoles, 0, mappableRoles, 0, mappableRoles.length);
	}

}
