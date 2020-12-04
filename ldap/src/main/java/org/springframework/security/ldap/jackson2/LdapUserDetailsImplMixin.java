package org.springframework.security.ldap.jackson2;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.jackson2.SimpleGrantedAuthorityMixin;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * This is a Jackson mixin class helps in serialize/deserialize
 * {@link org.springframework.security.ldap.userdetails.LdapUserDetailsImpl} class.
 * To use this class you need to register it with
 * {@link com.fasterxml.jackson.databind.ObjectMapper} and
 * {@link SimpleGrantedAuthorityMixin} because AnonymousAuthenticationToken contains
 * SimpleGrantedAuthority. <pre>
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
abstract class LdapUserDetailsImplMixin {
}
