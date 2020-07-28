package sample;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;

import java.time.LocalDateTime;
import java.util.Collection;

public class Saml2AccessDecisionVoter extends AuthenticatedVoter {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        System.err.println("Debug: Authorities: " + authentication.toString());
        if ( authentication.getClass().equals(org.springframework.security.saml2.provider.service.authentication.Saml2Authentication.class)) {
            DefaultSaml2AuthenticatedPrincipal mySaml2Principal = (DefaultSaml2AuthenticatedPrincipal) authentication.getPrincipal();

            System.err.println("Debug: Email: (" + mySaml2Principal.getFirstAttribute("emailAddress") + ")");
            System.err.println("Debug: Attributes: " + mySaml2Principal.getAttributes().toString());


            boolean hasAuthority = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(r -> "ROLE_USER".equals(r)
                            && LocalDateTime.now().getMinute() % 2 != 0)
                    .findAny().isPresent();

            System.err.println("DEBUG: Has Authority [Role_User]:" + hasAuthority);
            return hasAuthority ? ACCESS_GRANTED : ACCESS_DENIED;
        } else {
            return ACCESS_DENIED;
        }
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }
}
