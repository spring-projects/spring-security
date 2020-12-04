package org.springframework.security.ldap.jackson2;

import java.util.List;
import java.util.Map;

import org.springframework.security.jackson2.SecurityJackson2Modules;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * This is a Jackson mixin class helps in serialize/deserialize
 * {@link org.springframework.security.ldap.userdetails.LdapAuthority} class.
 * To use this class you need to register it with {@link com.fasterxml.jackson.databind.ObjectMapper}.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new LdapJackson2Module());
 * </pre>
 *
 * <i>Note: This class will save full class name into a property called @class</i>
 *
 * @see LdapJackson2Module
 * @see SecurityJackson2Modules
 * @since 4.2
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class LdapAuthorityMixin {

    /**
     * Constructor used by Jackson to create object of
     * {@link org.springframework.security.ldap.userdetails.LdapAuthority}.
     * @param role
     * @param dn
     * @param attributes
     */
    @JsonCreator
    LdapAuthorityMixin(
            @JsonProperty("role") String role,
            @JsonProperty("dn") String dn,
            @JsonProperty("attributes") Map<String, List<String>> attributes) {
    }

}
