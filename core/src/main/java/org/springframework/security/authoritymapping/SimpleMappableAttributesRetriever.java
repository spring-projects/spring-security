package org.springframework.security.authoritymapping;

import org.springframework.util.Assert;

/**
 * This class implements the MappableAttributesRetriever interface by just returning
 * a list of mappable attributes as previously set using the corresponding setter
 * method.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class SimpleMappableAttributesRetriever implements MappableAttributesRetriever {
    private String[] mappableAttributes = null;

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.security.authoritymapping.MappableAttributesRetriever#getMappableAttributes()
     */
    public String[] getMappableAttributes() {
        Assert.notNull(mappableAttributes, "No mappable roles have been set");
        String[] copy = new String[mappableAttributes.length];
        System.arraycopy(mappableAttributes, 0, copy, 0, copy.length);
        return copy;
    }

    public void setMappableAttributes(String[] aMappableRoles) {
        this.mappableAttributes = new String[aMappableRoles.length];
        System.arraycopy(aMappableRoles, 0, mappableAttributes, 0, mappableAttributes.length);
    }

}
