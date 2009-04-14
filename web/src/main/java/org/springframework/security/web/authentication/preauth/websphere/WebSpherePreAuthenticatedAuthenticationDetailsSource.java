package org.springframework.security.web.authentication.preauth.websphere;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationDetailsSourceImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.MutableGrantedAuthoritiesContainer;
import org.springframework.security.core.authoritymapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authoritymapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesAuthenticationDetails;
import org.springframework.util.Assert;

/**
 * This AuthenticationDetailsSource implementation, when configured with a MutableGrantedAuthoritiesContainer,
 * will set the pre-authenticated granted authorities based on the WebSphere groups for the current WebSphere
 * user, mapped using the configured Attributes2GrantedAuthoritiesMapper.
 *
 * By default, this class is configured to build instances of the
 * PreAuthenticatedGrantedAuthoritiesAuthenticationDetails class.
 *
 * @author Ruud Senden
 */
public class WebSpherePreAuthenticatedAuthenticationDetailsSource extends AuthenticationDetailsSourceImpl implements InitializingBean {
    private final Log logger = LogFactory.getLog(getClass());

    private Attributes2GrantedAuthoritiesMapper webSphereGroups2GrantedAuthoritiesMapper = new SimpleAttributes2GrantedAuthoritiesMapper();

    /**
     * Public constructor which overrides the default AuthenticationDetails
     * class to be used.
     */
    public WebSpherePreAuthenticatedAuthenticationDetailsSource() {
        super.setClazz(PreAuthenticatedGrantedAuthoritiesAuthenticationDetails.class);
    }

    /**
     * Check that all required properties have been set.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(webSphereGroups2GrantedAuthoritiesMapper, "WebSphere groups to granted authorities mapper not set");
    }

    /**
     * Build the authentication details object. If the specified authentication
     * details class implements the PreAuthenticatedGrantedAuthoritiesSetter, a
     * list of pre-authenticated Granted Authorities will be set based on the
     * WebSphere groups for the current user.
     *
     * @see org.springframework.security.authentication.AuthenticationDetailsSource#buildDetails(Object)
     */
    public Object buildDetails(Object context) {
        Object result = super.buildDetails(context);
        if (result instanceof MutableGrantedAuthoritiesContainer) {
            ((MutableGrantedAuthoritiesContainer) result)
                    .setGrantedAuthorities(getWebSphereGroupsBasedGrantedAuthorities());
        }
        return result;
    }

    /**
     * Get a list of Granted Authorities based on the current user's WebSphere groups.
     *
     * @return GrantedAuthority[] mapped from the user's WebSphere groups.
     */
    private List<GrantedAuthority> getWebSphereGroupsBasedGrantedAuthorities() {
        List<String> webSphereGroups = Arrays.asList(WASSecurityHelper.getGroupsForCurrentUser());
        List<GrantedAuthority> userGas = webSphereGroups2GrantedAuthoritiesMapper.getGrantedAuthorities(webSphereGroups);
        if (logger.isDebugEnabled()) {
            logger.debug("WebSphere groups: " + webSphereGroups + " mapped to Granted Authorities: " + userGas);
        }
        return userGas;
    }

    /**
     * @param mapper
     *            The Attributes2GrantedAuthoritiesMapper to use
     */
    public void setWebSphereGroups2GrantedAuthoritiesMapper(Attributes2GrantedAuthoritiesMapper mapper) {
        webSphereGroups2GrantedAuthoritiesMapper = mapper;
    }

}
