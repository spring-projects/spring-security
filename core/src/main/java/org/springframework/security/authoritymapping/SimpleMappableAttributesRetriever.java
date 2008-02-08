package org.springframework.security.authoritymapping;

import org.springframework.util.Assert;

/**
 * This class implements the MappableAttributesRetriever interface by just returning
 * a list of mappable roles as previously set using the corresponding setter
 * method.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class SimpleMappableAttributesRetriever implements MappableAttributesRetriever {
    private String[] mappableRoles = null;

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.security.authoritymapping.MappableAttributesRetriever#getMappableAttributes()
     */
    public String[] getMappableAttributes() {
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
