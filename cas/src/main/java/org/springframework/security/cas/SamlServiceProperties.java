package org.springframework.security.cas;

/**
 * Sets the appropriate parameters for CAS's implementation of SAML (which is not guaranteed to be actually SAML compliant).
 *
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.0
 */
public final class SamlServiceProperties extends ServiceProperties {

    public static final String DEFAULT_SAML_ARTIFACT_PARAMETER = "SAMLart";

    public static final String DEFAULT_SAML_SERVICE_PARAMETER = "TARGET";

    public SamlServiceProperties() {
        super.setArtifactParameter(DEFAULT_SAML_ARTIFACT_PARAMETER);
        super.setServiceParameter(DEFAULT_SAML_SERVICE_PARAMETER);
    }
}
