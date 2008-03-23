package org.springframework.security.config;

import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.util.InMemoryXmlApplicationContext;
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
    public void externalUserServiceAndPasswordEncoderWork() throws Exception {
        setContext(" <authentication-provider user-service-ref='customUserService'>" +
                "        <password-encoder ref='customPasswordEncoder'>" +
                "            <salt-source user-property='username'/>" +
                "        </password-encoder>" +
                "    </authentication-provider>" +

                "    <b:bean id='customPasswordEncoder' " +
                            "class='org.springframework.security.providers.encoding.Md5PasswordEncoder'/>" +

                "    <b:bean id='customUserService' " +
                "           class='org.springframework.security.userdetails.memory.InMemoryDaoImpl'>" +
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
