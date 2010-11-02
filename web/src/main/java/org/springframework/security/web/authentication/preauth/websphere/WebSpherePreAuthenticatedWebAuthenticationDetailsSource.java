package org.springframework.security.web.authentication.preauth.websphere;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * This AuthenticationDetailsSource implementation will set the pre-authenticated granted
 * authorities based on the WebSphere groups for the current WebSphere user, mapped using the
 * configured Attributes2GrantedAuthoritiesMapper.
 *
 * @author Ruud Senden
 */
public class WebSpherePreAuthenticatedWebAuthenticationDetailsSource implements
        AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> {
    private final Log logger = LogFactory.getLog(getClass());

    private Attributes2GrantedAuthoritiesMapper webSphereGroups2GrantedAuthoritiesMapper = new SimpleAttributes2GrantedAuthoritiesMapper();

    private final WASUsernameAndGroupsExtractor wasHelper;

    public WebSpherePreAuthenticatedWebAuthenticationDetailsSource() {
        this(new DefaultWASUsernameAndGroupsExtractor());
    }

    public WebSpherePreAuthenticatedWebAuthenticationDetailsSource(WASUsernameAndGroupsExtractor wasHelper) {
        this.wasHelper = wasHelper;
    }

    public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(context, getWebSphereGroupsBasedGrantedAuthorities());
    }

    /**
     * Get a list of Granted Authorities based on the current user's WebSphere groups.
     *
     * @return authorities mapped from the user's WebSphere groups.
     */
    private Collection<? extends GrantedAuthority> getWebSphereGroupsBasedGrantedAuthorities() {
        List<String> webSphereGroups = wasHelper.getGroupsForCurrentUser();
        Collection<? extends GrantedAuthority> userGas = webSphereGroups2GrantedAuthoritiesMapper.getGrantedAuthorities(webSphereGroups);
        if (logger.isDebugEnabled()) {
            logger.debug("WebSphere groups: " + webSphereGroups + " mapped to Granted Authorities: " + userGas);
        }
        return userGas;
    }

    /**
     * @param mapper The Attributes2GrantedAuthoritiesMapper to use for converting the WAS groups to authorities
     */
    public void setWebSphereGroups2GrantedAuthoritiesMapper(Attributes2GrantedAuthoritiesMapper mapper) {
        webSphereGroups2GrantedAuthoritiesMapper = mapper;
    }

}
