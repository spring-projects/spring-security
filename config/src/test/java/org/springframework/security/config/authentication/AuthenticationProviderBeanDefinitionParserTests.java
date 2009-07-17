package org.springframework.security.config.authentication;

import static org.junit.Assert.*;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.ReflectionSaltSource;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.authentication.AuthenticationProviderBeanDefinitionParser;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.util.FieldUtils;
import org.springframework.context.support.AbstractXmlApplicationContext;

import org.junit.Test;
import org.junit.After;

import java.util.List;

/**
 * Tests for {@link AuthenticationProviderBeanDefinitionParser}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationProviderBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;
    private UsernamePasswordAuthenticationToken bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void worksWithEmbeddedUserService() {
        setContext(" <authentication-provider>" +
                "        <user-service>" +
                "            <user name='bob' password='bobspassword' authorities='ROLE_A' />" +
                "        </user-service>" +
                "    </authentication-provider>");
        getProvider().authenticate(bob);
    }

    @Test
    public void externalUserServiceRefWorks() throws Exception {
        setContext(" <authentication-provider user-service-ref='myUserService' />" +
                "    <user-service id='myUserService'>" +
                "       <user name='bob' password='bobspassword' authorities='ROLE_A' />" +
                "    </user-service>");
        getProvider().authenticate(bob);
    }

    @Test
    public void providerWithMd5PasswordEncoderWorks() throws Exception {
        setContext(" <authentication-provider>" +
                "        <password-encoder hash='md5'/>" +
                "        <user-service>" +
                "            <user name='bob' password='12b141f35d58b8b3a46eea65e6ac179e' authorities='ROLE_A' />" +
                "        </user-service>" +
                "    </authentication-provider>");

        getProvider().authenticate(bob);
    }

    @Test
    public void providerWithShaPasswordEncoderWorks() throws Exception {
        setContext(" <authentication-provider>" +
                "        <password-encoder hash='{sha}'/>" +
                "        <user-service>" +
                "            <user name='bob' password='{SSHA}PpuEwfdj7M1rs0C2W4ssSM2XEN/Y6S5U' authorities='ROLE_A' />" +
                "        </user-service>" +
                "    </authentication-provider>");

        getProvider().authenticate(bob);
    }

    @Test
    public void providerWithSha256PasswordEncoderIsSupported() throws Exception {
        setContext(" <authentication-provider>" +
                "        <password-encoder hash='sha-256'/>" +
                "        <user-service>" +
                "            <user name='bob' password='notused' authorities='ROLE_A' />" +
                "        </user-service>" +
                "    </authentication-provider>");

        ShaPasswordEncoder encoder = (ShaPasswordEncoder) FieldUtils.getFieldValue(getProvider(), "passwordEncoder");
        assertEquals("SHA-256", encoder.getAlgorithm());
    }

    @Test
    public void passwordIsBase64EncodedWhenBase64IsEnabled() throws Exception {
        setContext(" <authentication-provider>" +
                "        <password-encoder hash='md5' base64='true'/>" +
                "        <user-service>" +
                "            <user name='bob' password='ErFB811YuLOkbupl5qwXng==' authorities='ROLE_A' />" +
                "        </user-service>" +
                "    </authentication-provider>");

        getProvider().authenticate(bob);
    }

    @Test
    public void externalUserServicePasswordEncoderAndSaltSourceWork() throws Exception {
        setContext(" <authentication-provider user-service-ref='customUserService'>" +
                "        <password-encoder ref='customPasswordEncoder'>" +
                "            <salt-source ref='saltSource'/>" +
                "        </password-encoder>" +
                "    </authentication-provider>" +

                "    <b:bean id='customPasswordEncoder' " +
                            "class='org.springframework.security.authentication.encoding.Md5PasswordEncoder'/>" +
                "    <b:bean id='saltSource' " +
                "           class='" + ReflectionSaltSource.class.getName() +"'>" +
                "         <b:property name='userPropertyToUse' value='username'/>" +
                "    </b:bean>" +
                "    <b:bean id='customUserService' " +
                "           class='org.springframework.security.core.userdetails.memory.InMemoryDaoImpl'>" +
                "        <b:property name='userMap' value='bob=f117f0862384e9497ff4f470e3522606,ROLE_A'/>" +
                "    </b:bean>");
        getProvider().authenticate(bob);
    }

    private AuthenticationProvider getProvider() {
        List<AuthenticationProvider> providers =
                ((ProviderManager)appContext.getBean(BeanIds.AUTHENTICATION_MANAGER)).getProviders();

        return providers.get(0);
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
