package org.springframework.security.config.ldap

import java.text.MessageFormat
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer
import org.springframework.security.config.AbstractXmlConfigTests
import org.springframework.security.config.BeanIds
import org.springframework.security.util.FieldUtils
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.context.ApplicationContextException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper

/**
 * @author Luke Taylor
 */
class LdapProviderBeanDefinitionParserTests extends AbstractXmlConfigTests {

    // SEC-1182
    def multipleProvidersAreSupported() {
        xml.'ldap-server'(url: 'ldap://blah:389/dc=blah')
        xml.'authentication-manager'() {
            'ldap-authentication-provider'('group-search-filter': 'member={0}')
            'ldap-authentication-provider'('group-search-filter': 'uniqueMember={0}')
        }

        createAppContext('')

        def providers = appContext.getBean(BeanIds.AUTHENTICATION_MANAGER).providers

        expect:

        providers.size() == 2
        providers[0].authoritiesPopulator.groupSearchFilter == "member={0}"
        providers[1].authoritiesPopulator.groupSearchFilter == "uniqueMember={0}"
    }


    def simpleProviderAuthenticatesCorrectly() {
        xml.'ldap-server'()
        xml.'authentication-manager'{
            'ldap-authentication-provider'('group-search-filter':'member={0}')
        }

        createAppContext('')

        def am = appContext.getBean(BeanIds.AUTHENTICATION_MANAGER)

        when:
        def auth = am.authenticate(new UsernamePasswordAuthenticationToken("ben", "benspassword"))
        def ben =  auth.principal;

        then:
        ben.authorities.size() == 3
    }

    def missingServerEltCausesConfigException() {
        xml.'authentication-manager'{
            'ldap-authentication-provider'()
        }

        when:
        createAppContext('')

        then:
        thrown(ApplicationContextException)
    }

    def supportsPasswordComparisonAuthentication() {
        xml.'ldap-server'()
        xml.'authentication-manager'{
            'ldap-authentication-provider'('user-dn-pattern': 'uid={0},ou=people')
            'password-compare'
        }
        createAppContext('')
        def am = appContext.getBean(BeanIds.AUTHENTICATION_MANAGER)

        when:
        def auth = am.authenticate(new UsernamePasswordAuthenticationToken("ben", "benspassword"))

        then:
        auth != null
        notThrown(AuthenticationException)
    }

    def supportsPasswordComparisonAuthenticationWithHashAttribute() {
        xml.'ldap-server'()
        xml.'authentication-manager'{
            'ldap-authentication-provider'('user-dn-pattern': 'uid={0},ou=people') {
                'password-compare'('password-attribute': 'uid', hash: 'plaintext')
            }
        }
        createAppContext('')
        def am = appContext.getBean(BeanIds.AUTHENTICATION_MANAGER)

        when:
        def auth = am.authenticate(new UsernamePasswordAuthenticationToken("ben", "ben"))

        then:
        auth != null
        notThrown(AuthenticationException)

    }

    def supportsPasswordComparisonAuthenticationWithPasswordEncoder() {
        xml.'ldap-server'()
        xml.'authentication-manager'{
            'ldap-authentication-provider'('user-dn-pattern': 'uid={0},ou=people') {
                'password-compare'('password-attribute': 'uid') {
                    'password-encoder'(hash: 'plaintext')
                }
            }
        }

        createAppContext('')
        def am = appContext.getBean(BeanIds.AUTHENTICATION_MANAGER)

        when:
        def auth = am.authenticate(new UsernamePasswordAuthenticationToken("ben", "ben"))

        then:
        auth != null
        notThrown(AuthenticationException)
    }

    def inetOrgContextMapperIsSupported()  {
        xml.'ldap-server'(url: 'ldap://127.0.0.1:343/dc=springframework,dc=org')
        xml.'authentication-manager'{
            'ldap-authentication-provider'('user-details-class' :'inetOrgPerson')
        }
        createAppContext('')

        expect:
        appContext.getBean(BeanIds.AUTHENTICATION_MANAGER).providers[0].userDetailsContextMapper instanceof InetOrgPersonContextMapper
    }

    def ldapAuthenticationProviderWorksWithPlaceholders() {
        System.setProperty('udp','people')
        System.setProperty('gsf','member')

        xml.'ldap-server'()
        xml.'authentication-manager'{
            'ldap-authentication-provider'('user-dn-pattern':'uid={0},ou=${udp}','group-search-filter':'${gsf}={0}')
        }
        bean(PropertyPlaceholderConfigurer.class.name, PropertyPlaceholderConfigurer.class)

        createAppContext('')
        def provider = this.appContext.getBean(BeanIds.AUTHENTICATION_MANAGER).providers[0]

        expect:
        [new MessageFormat("uid={0},ou=people")] == FieldUtils.getFieldValue(provider,"authenticator.userDnFormat")
        "member={0}" == FieldUtils.getFieldValue(provider, "authoritiesPopulator.groupSearchFilter")
    }
}
