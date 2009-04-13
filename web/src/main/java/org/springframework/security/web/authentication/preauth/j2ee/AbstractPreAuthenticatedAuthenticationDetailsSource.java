package org.springframework.security.web.authentication.preauth.j2ee;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.authoritymapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.access.authoritymapping.MappableAttributesRetriever;
import org.springframework.security.access.authoritymapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.authentication.AuthenticationDetailsSourceImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.MutableGrantedAuthoritiesContainer;
import org.springframework.util.Assert;

/**
 * Base implementation for classes scenarios where the authentication details object is used
 * to store a list of authorities obtained from the context object (such as an HttpServletRequest)
 * passed to {@link #buildDetails(Object)}.
 * <p>
 *
 *
 * @author Luke Taylor
 * @since 2.0
 */
public abstract class AbstractPreAuthenticatedAuthenticationDetailsSource extends AuthenticationDetailsSourceImpl {
    protected final Log logger = LogFactory.getLog(getClass());
    protected Set<String> j2eeMappableRoles;
    protected Attributes2GrantedAuthoritiesMapper j2eeUserRoles2GrantedAuthoritiesMapper =
        new SimpleAttributes2GrantedAuthoritiesMapper();

    public AbstractPreAuthenticatedAuthenticationDetailsSource() {
    }

    /**
     * Check that all required properties have been set.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(j2eeMappableRoles, "No mappable roles available");
        Assert.notNull(j2eeUserRoles2GrantedAuthoritiesMapper, "Roles to granted authorities mapper not set");
    }

    /**
     * Build the authentication details object. If the specified authentication
     * details class implements {@link MutableGrantedAuthoritiesContainer}, a
     * list of pre-authenticated Granted Authorities will be set based on the
     * roles for the current user.
     *
     * @see org.springframework.security.authentication.AuthenticationDetailsSource#buildDetails(Object)
     */
    public Object buildDetails(Object context) {
        Object result = super.buildDetails(context);

        if (result instanceof MutableGrantedAuthoritiesContainer) {
            Collection<String> j2eeUserRoles = getUserRoles(context, j2eeMappableRoles);
            List<GrantedAuthority> userGas = j2eeUserRoles2GrantedAuthoritiesMapper.getGrantedAuthorities(j2eeUserRoles);

            if (logger.isDebugEnabled()) {
                logger.debug("J2EE roles [" + j2eeUserRoles + "] mapped to Granted Authorities: [" + userGas + "]");
            }

            ((MutableGrantedAuthoritiesContainer) result).setGrantedAuthorities(userGas);
        }
        return result;
    }

    /**
     * Allows the roles of the current user to be determined from the context object
     *
     * @param context the context object (an HttpRequest, PortletRequest etc)
     * @param mappableRoles the possible roles as determined by the MappableAttributesRetriever
     * @return the subset of mappable roles which the current user has.
     */
    protected abstract Collection<String> getUserRoles(Object context, Set<String> mappableRoles);

    /**
     * @param aJ2eeMappableRolesRetriever
     *            The MappableAttributesRetriever to use
     */
    public void setMappableRolesRetriever(MappableAttributesRetriever aJ2eeMappableRolesRetriever) {
        this.j2eeMappableRoles = aJ2eeMappableRolesRetriever.getMappableAttributes();
    }

    /**
     * @param mapper
     *            The Attributes2GrantedAuthoritiesMapper to use
     */
    public void setUserRoles2GrantedAuthoritiesMapper(Attributes2GrantedAuthoritiesMapper mapper) {
        j2eeUserRoles2GrantedAuthoritiesMapper = mapper;
    }
}
