package org.springframework.security.web.authentication.preauth.websphere;

import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;

/**
 * This AuthenticationDetailsSource implementation, when configured with a MutableGrantedAuthoritiesContainer,
 * will set the pre-authenticated granted authorities based on the WebSphere groups for the current WebSphere
 * user, mapped using the configured Attributes2GrantedAuthoritiesMapper.
 *
 * By default, this class is configured to build instances of the
 * PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails class.
 *
 * @author Ruud Senden
 */
public class WebSpherePreAuthenticatedWebAuthenticationDetailsSource extends WebSpherePreAuthenticatedAuthenticationDetailsSource {
    /**
     * Public constructor which overrides the default AuthenticationDetails
     * class to be used.
     */
    public WebSpherePreAuthenticatedWebAuthenticationDetailsSource() {
        super();
        super.setClazz(PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails.class);
    }
}
