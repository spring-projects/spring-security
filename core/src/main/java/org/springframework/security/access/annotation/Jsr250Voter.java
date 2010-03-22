package org.springframework.security.access.annotation;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Voter on JSR-250 configuration attributes.
 *
 * @author Ryan Heaton
 * @since 2.0
 */
public class Jsr250Voter implements AccessDecisionVoter {

    /**
     * The specified config attribute is supported if its an instance of a {@link Jsr250SecurityConfig}.
     *
     * @param configAttribute The config attribute.
     * @return whether the config attribute is supported.
     */
    public boolean supports(ConfigAttribute configAttribute) {
        return configAttribute instanceof Jsr250SecurityConfig;
    }

    /**
     * All classes are supported.
     *
     * @param clazz the class.
     * @return true
     */
    public boolean supports(Class<?> clazz) {
        return true;
    }

    /**
     * Votes according to JSR 250.
     * <p>
     * If no JSR-250 attributes are found, it will abstain, otherwise it will grant or deny access
     * based on the attributes that are found.
     *
     * @param authentication The authentication object.
     * @param object         The access object.
     * @param definition     The configuration definition.
     * @return The vote.
     */
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> definition) {
        boolean jsr250AttributeFound = false;

        for (ConfigAttribute attribute : definition) {
            if (Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE.equals(attribute)) {
                return ACCESS_GRANTED;
            }

            if (Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE.equals(attribute)) {
                return ACCESS_DENIED;
            }

            if (supports(attribute)) {
                jsr250AttributeFound = true;
                // Attempt to find a matching granted authority
                for (GrantedAuthority authority : authentication.getAuthorities()) {
                    if (attribute.getAttribute().equals(authority.getAuthority())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return jsr250AttributeFound ? ACCESS_DENIED : ACCESS_ABSTAIN;
    }
}

