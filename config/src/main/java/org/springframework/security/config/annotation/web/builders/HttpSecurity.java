/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.JeeConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.PortMapperConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.config.annotation.web.configurers.openid.OpenIDLoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RegexRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;

/**
 * A {@link HttpSecurity} is similar to Spring Security's XML <http> element in the namespace
 * configuration. It allows configuring web based security for specific http requests. By default
 * it will be applied to all requests, but can be restricted using {@link #requestMatcher(RequestMatcher)}
 * or other similar methods.
 *
 * <h2>Example Usage</h2>
 *
 * The most basic form based configuration can be seen below. The configuration will require that any URL
 * that is requested will require a User with the role "ROLE_USER". It also defines an in memory authentication
 * scheme with a user that has the username "user", the password "password", and the role "ROLE_USER". For
 * additional examples, refer to the Java Doc of individual methods on {@link HttpSecurity}.
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
 *
 *     &#064;Override
 *     protected void configure(HttpSecurity http) throws Exception {
 *         http
 *             .authorizeUrls()
 *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
 *                 .and()
 *             .formLogin();
 *     }
 *
 *     &#064;Override
 *     protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
 *         auth
 *              .inMemoryAuthentication()
 *                   .withUser(&quot;user&quot;)
 *                        .password(&quot;password&quot;)
 *                        .roles(&quot;USER&quot;);
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 3.2
 * @see EnableWebSecurity
 */
public final class HttpSecurity extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain,HttpSecurity> implements SecurityBuilder<DefaultSecurityFilterChain>, HttpSecurityBuilder<HttpSecurity> {
    private AuthenticationManager authenticationManager;

    private List<Filter> filters =  new ArrayList<Filter>();
    private RequestMatcher requestMatcher = new AnyRequestMatcher();
    private FilterComparator comparitor = new FilterComparator();

    /**
     * Creates a new instance
     * @param objectPostProcessor the {@link ObjectPostProcessor} that should be used
     * @param authenticationBuilder the {@link AuthenticationManagerBuilder} to use for additional updates
     * @param sharedObjects the shared Objects to initialize the {@link HttpSecurity} with
     * @see WebSecurityConfiguration
     */
    public HttpSecurity(ObjectPostProcessor<Object> objectPostProcessor, AuthenticationManagerBuilder authenticationBuilder, Map<Class<Object>,Object> sharedObjects) {
        super(objectPostProcessor);
        Assert.notNull(authenticationBuilder, "authenticationBuilder cannot be null");
        setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
        for(Map.Entry<Class<Object>, Object> entry : sharedObjects.entrySet()) {
            setSharedObject(entry.getKey(), entry.getValue());
        }
    }

    /**
     * Allows configuring OpenID based authentication. Multiple invocations of
     * {@link #openidLogin()} will override previous invocations.
     *
     * <h2>Example Configurations</h2>
     *
     * A basic example accepting the defaults and not using attribute exchange:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .openidLogin()
     *                 .permitAll();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
     *         auth
     *                 .inMemoryAuthentication()
     *                     // the username must match the OpenID of the user you are
     *                     // logging in with
     *                     .withUser(&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
     *                         .password(&quot;password&quot;)
     *                         .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * A more advanced example demonstrating using attribute exchange and
     * providing a custom AuthenticationUserDetailsService that will make any
     * user that authenticates a valid user.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .openidLogin()
     *                 .loginPage(&quot;/login&quot;)
     *                 .permitAll()
     *                 .authenticationUserDetailsService(new AutoProvisioningUserDetailsService())
     *                     .attributeExchange(&quot;https://www.google.com/.*&quot;)
     *                         .attribute(&quot;email&quot;)
     *                             .type(&quot;http://axschema.org/contact/email&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;firstname&quot;)
     *                             .type(&quot;http://axschema.org/namePerson/first&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;lastname&quot;)
     *                             .type(&quot;http://axschema.org/namePerson/last&quot;)
     *                             .required(true)
     *                             .and()
     *                         .and()
     *                     .attributeExchange(&quot;.*yahoo.com.*&quot;)
     *                         .attribute(&quot;email&quot;)
     *                             .type(&quot;http://schema.openid.net/contact/email&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;fullname&quot;)
     *                             .type(&quot;http://axschema.org/namePerson&quot;)
     *                             .required(true)
     *                             .and()
     *                         .and()
     *                     .attributeExchange(&quot;.*myopenid.com.*&quot;)
     *                         .attribute(&quot;email&quot;)
     *                             .type(&quot;http://schema.openid.net/contact/email&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;fullname&quot;)
     *                             .type(&quot;http://schema.openid.net/namePerson&quot;)
     *                             .required(true);
     *     }
     * }
     *
     * public class AutoProvisioningUserDetailsService implements
     *         AuthenticationUserDetailsService&lt;OpenIDAuthenticationToken&gt; {
     *     public UserDetails loadUserDetails(OpenIDAuthenticationToken token) throws UsernameNotFoundException {
     *         return new User(token.getName(), &quot;NOTUSED&quot;, AuthorityUtils.createAuthorityList(&quot;ROLE_USER&quot;));
     *     }
     * }
     * </pre>
     *
     * @return the {@link OpenIDLoginConfigurer} for further customizations.
     *
     * @throws Exception
     * @see OpenIDLoginConfigurer
     */
    public OpenIDLoginConfigurer<HttpSecurity> openidLogin() throws Exception {
        return apply(new OpenIDLoginConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring of Session Management. Multiple invocations of
     * {@link #sessionManagement()} will override previous invocations.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to enforce that only a
     * single instance of a user is authenticated at a time. If a user
     * authenticates with the username "user" without logging out and an attempt
     * to authenticate with "user" is made the first session will be forcibly
     * terminated and sent to the "/login?expired" URL.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class SessionManagementSecurityConfig extends
     *         WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .anyRequest().hasRole(&quot;USER&quot;)
     *                 .and()
     *            .formLogin()
     *                 .permitAll()
     *                 .and()
     *            .sessionManagement()
     *                 .maximumSessions(1)
     *                 .expiredUrl(&quot;/login?expired&quot;);
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth.
     *             inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * When using {@link SessionManagementConfigurer#maximumSessions(int)}, do
     * not forget to configure {@link HttpSessionEventPublisher} for the
     * application to ensure that expired sessions are cleaned up.
     *
     * In a web.xml this can be configured using the following:
     *
     * <pre>
     * &lt;listener&gt;
     *      &ltlistener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
     * &lt/listener>
     * </pre>
     *
     * Alternatively,
     * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
     * could return true.
     *
     * @return the {@link SessionManagementConfigurer} for further
     *         customizations
     * @throws Exception
     */
    public SessionManagementConfigurer<HttpSecurity> sessionManagement() throws Exception {
        return apply(new SessionManagementConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring a {@link PortMapper} that is available from
     * {@link HttpSecurity#getSharedObject(Class)}. Other provided
     * {@link SecurityConfigurer} objects use this configured
     * {@link PortMapper} as a default {@link PortMapper} when redirecting from
     * HTTP to HTTPS or from HTTPS to HTTP (for example when used in combination
     * with {@link #requiresChannel()}. By default Spring Security uses a
     * {@link PortMapperImpl} which maps the HTTP port 8080 to the HTTPS port
     * 8443 and the HTTP port of 80 to the HTTPS port of 443.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will ensure that redirects within Spring
     * Security from HTTP of a port of 9090 will redirect to HTTPS port of 9443
     * and the HTTP port of 80 to the HTTPS port of 443.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .permitAll()
     *                 .and()
     *                 // Example portMapper() configuration
     *                 .portMapper()
     *                     .http(9090).mapsTo(9443)
     *                     .http(80).mapsTo(443);
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return the {@link PortMapperConfigurer} for further customizations
     * @throws Exception
     * @see {@link #requiresChannel()}
     */
    public PortMapperConfigurer<HttpSecurity> portMapper() throws Exception {
        return apply(new PortMapperConfigurer<HttpSecurity>());
    }

    /**
     * Configures container based based pre authentication. In this case,
     * authentication is managed by the Servlet Container.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will use the principal found on the
     * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
     * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             // Example jee() configuration
     *             .jee()
     *                 .mappableRoles(&quot;ROLE_USER&quot;, &quot;ROLE_ADMIN&quot;);
     *     }
     * }
     * </pre>
     *
     * Developers wishing to use pre authentication with the container will need
     * to ensure their web.xml configures the security constraints. For example,
     * the web.xml (there is no equivalent Java based configuration supported by
     * the Servlet specification) might look like:
     *
     * <pre>
     * &lt;login-config&gt;
     *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
     *     &lt;form-login-config&gt;
     *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
     *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
     *     &lt;/form-login-config&gt;
     * &lt;/login-config&gt;
     *
     * &lt;security-role&gt;
     *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     * &lt;/security-role&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
     *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
     *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     * &lt;/security-constraint&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
     *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     *     &lt;auth-constraint&gt;
     *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     *     &lt;/auth-constraint&gt;
     * &lt;/security-constraint&gt;
     * </pre>
     *
     * Last you will need to configure your container to contain the user with the
     * correct roles. This configuration is specific to the Servlet Container, so consult
     * your Servlet Container's documentation.
     *
     * @return the {@link JeeConfigurer} for further customizations
     * @throws Exception
     */
    public JeeConfigurer<HttpSecurity> jee() throws Exception {
        return apply(new JeeConfigurer<HttpSecurity>());
    }

    /**
     * Configures X509 based pre authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will attempt to extract the username from
     * the X509 certificate. Remember that the Servlet Container will need to be
     * configured to request client certificates in order for this to work.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             // Example x509() configuration
     *             .x509();
     *     }
     * }
     * </pre>
     *
     * @return the {@link X509Configurer} for further customizations
     * @throws Exception
     */
    public X509Configurer<HttpSecurity> x509() throws Exception {
        return apply(new X509Configurer<HttpSecurity>());
    }

    /**
     * Allows configuring of Remember Me authentication. Multiple invocations of
     * {@link #rememberMe()} will override previous invocations.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to allow token based remember me
     * authentication. Upon authenticating if the HTTP parameter named "remember-me" exists,
     * then the user will be remembered even after their {@link javax.servlet.http.HttpSession} expires.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .permitAll()
     *                 .and()
     *              // Example Remember Me Configuration
     *             .rememberMe();
     *     }
     * }
     * </pre>
     *
     * @return the {@link RememberMeConfigurer} for further customizations
     * @throws Exception
     */
    public RememberMeConfigurer<HttpSecurity> rememberMe() throws Exception {
        return apply(new RememberMeConfigurer<HttpSecurity>());
    }


    /**
     * Allows restricting access based upon the {@link HttpServletRequest} using
     * {@link RequestMatcher} implementations (i.e. via URL patterns). Invoking
     * {@link #authorizeUrls()} twice will override previous invocations of
     * {@link #authorizeUrls()}.
     *
     * <h2>Example Configurations</h2>
     *
     * The most basic example is to configure all URLs to require the role "ROLE_USER". The
     * configuration below requires authentication to every URL and will grant access to
     * both the user "admin" and "user".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;)
     *                        .and()
     *                   .withUser(&quot;adminr&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;ADMIN&quot;,&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * We can also configure multiple URLs. The configuration below requires authentication to every URL
     * and will grant access to URLs starting with /admin/ to only the "admin" user. All other URLs either
     * user can access.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;)
     *                        .and()
     *                   .withUser(&quot;adminr&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;ADMIN&quot;,&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * Note that the matchers are considered in order. Therefore, the following is invalid because the first
     * matcher matches every request and will never get to the second mapping:
     *
     * <pre>
     * http
     *     .authorizeUrls()
     *         .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *         .antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
     * </pre>
     *
     * @see #requestMatcher(RequestMatcher)
     *
     * @return
     * @throws Exception
     */
    public ExpressionUrlAuthorizationConfigurer<HttpSecurity> authorizeUrls() throws Exception {
        return apply(new ExpressionUrlAuthorizationConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring the Request Cache. For example, a protected page (/protected) may be requested prior
     * to authentication. The application will redirect the user to a login page. After authentication, Spring
     * Security will redirect the user to the originally requested protected page (/protected). This is
     * automatically applied when using {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link RequestCacheConfigurer} for further customizations
     * @throws Exception
     */
    public RequestCacheConfigurer<HttpSecurity> requestCache() throws Exception {
        return apply(new RequestCacheConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring exception handling. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link ExceptionHandlingConfigurer} for further customizations
     * @throws Exception
     */
    public ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling() throws Exception {
        return apply(new ExceptionHandlingConfigurer<HttpSecurity>());
    }

    /**
     * Sets up management of the {@link SecurityContext} on the
     * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is automatically
     * applied when using {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link SecurityContextConfigurer} for further customizations
     * @throws Exception
     */
    public SecurityContextConfigurer<HttpSecurity> securityContext() throws Exception {
        return apply(new SecurityContextConfigurer<HttpSecurity>());
    }

    /**
     * Integrates the {@link HttpServletRequest} methods with the values found
     * on the {@link SecurityContext}. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link ServletApiConfigurer} for further customizations
     * @throws Exception
     */
    public ServletApiConfigurer<HttpSecurity> servletApi() throws Exception {
        return apply(new ServletApiConfigurer<HttpSecurity>());
    }

    /**
     * Provides logout support. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}. The default is that accessing
     * the URL "/logout" will log the user out by invalidating the HTTP Session,
     * cleaning up any {@link #rememberMe()} authentication that was configured,
     * clearing the {@link SecurityContextHolder}, and then redirect to
     * "/login?success".
     *
     * <h2>Example Custom Configuration</h2>
     *
     * The following customization to log out when the URL "/custom-logout" is
     * invoked. Log out will remove the cookie named "remove", not invalidate the
     * HttpSession, clear the SecurityContextHolder, and upon completion redirect
     * to "/logout-success".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             // sample logout customization
     *             .logout()
     *                 .logout()
     *                    .deleteCookies("remove")
     *                    .invalidateHttpSession(false)
     *                    .logoutUrl("/custom-logout")
     *                    .logoutSuccessUrl("/logout-success");
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return
     * @throws Exception
     */
    public LogoutConfigurer<HttpSecurity> logout() throws Exception {
        return apply(new LogoutConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring how an anonymous user is represented. This is automatically applied
     * when used in conjunction with {@link WebSecurityConfigurerAdapter}. By default anonymous
     * users will be represented with an {@link org.springframework.security.authentication.AnonymousAuthenticationToken} and contain the role
     * "ROLE_ANONYMOUS".
     *
     * <h2>Example Configuration</h2
     *
     * The following configuration demonstrates how to specify that anonymous users should contain
     * the role "ROLE_ANON" instead.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnononymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             // sample anonymous customization
     *             .anonymous()
     *                 .authorities("ROLE_ANON");
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * The following demonstrates how to represent anonymous users as null. Note that this can cause
     * {@link NullPointerException} in code that assumes anonymous authentication is enabled.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnononymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             // sample anonymous customization
     *             .anonymous()
     *                 .disabled();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return
     * @throws Exception
     */
    public AnonymousConfigurer<HttpSecurity> anonymous() throws Exception {
        return apply(new AnonymousConfigurer<HttpSecurity>());
    }

    /**
     * Specifies to support form based authentication. If
     * {@link FormLoginConfigurer#loginPage(String)} is not specified a
     * default login page will be generated.
     *
     * <h2>Example Configurations</h2>
     *
     * The most basic configuration defaults to automatically generating a login
     * page at the URL "/login", redirecting to "/login?error" for
     * authentication failure. The details of the login page can be found on
     * {@link FormLoginConfigurer#loginPage(String)}
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * The configuration below demonstrates customizing the defaults.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                    .usernameParameter("j_username") // default is username
     *                    .passwordParameter("j_password") // default is password
     *                    .loginPage("/authentication/login") // default is /login with an HTTP get
     *                    .failureUrl("/authentication/login?failed") // default is /login?error
     *                    .loginProcessingUrl("/authentication/login/process"); // default is /login with an HTTP post
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @see FormLoginConfigurer#loginPage(String)
     *
     * @return
     * @throws Exception
     */
    public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
        return apply(new FormLoginConfigurer<HttpSecurity>());
    }

    /**
     * Configures channel security. In order for this configuration to be useful at least
     * one mapping to a required channel must be provided. Invoking this method multiple times
     * will reset previous invocations of the method.
     *
     * <h2>Example Configuration</h2>
     *
     * The example below demonstrates how to require HTTPs for every request. Only requiring HTTPS
     * for some requests is supported, but not recommended since an application that allows for HTTP
     * introduces many security vulnerabilities. For one such example, read about
     * <a href="http://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             .channelSecurity()
     *                 .anyRequest().requiresSecure();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     *
     * @return the {@link ChannelSecurityConfigurer} for further customizations
     * @throws Exception
     */
    public ChannelSecurityConfigurer<HttpSecurity> requiresChannel() throws Exception {
        return apply(new ChannelSecurityConfigurer<HttpSecurity>());
    }

    /**
     * Configures HTTP Basic authentication. Multiple infocations of
     * {@link #httpBasic()} will override previous invocations.
     *
     * <h2>Example Configuration</h2>
     *
     * The example below demonstrates how to configure HTTP Basic authentication
     * for an application. The default realm is "Spring Security Application",
     * but can be customized using
     * {@link HttpBasicConfigurer#realmName(String)}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return the {@link HttpBasicConfigurer} for further customizations
     * @throws Exception
     */
    public HttpBasicConfigurer<HttpSecurity> httpBasic() throws Exception {
        return apply(new HttpBasicConfigurer<HttpSecurity>());
    }

    @Override
    protected void beforeConfigure() throws Exception {
        this.authenticationManager = getAuthenticationRegistry().build();
    }

    @Override
    protected DefaultSecurityFilterChain performBuild() throws Exception {
        Collections.sort(filters,comparitor);
        return new DefaultSecurityFilterChain(requestMatcher, filters);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)
     */
    @Override
    public HttpSecurity authenticationProvider(AuthenticationProvider authenticationProvider) {
        getAuthenticationRegistry().authenticationProvider(authenticationProvider);
        return this;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#userDetailsService(org.springframework.security.core.userdetails.UserDetailsService)
     */
    @Override
    public HttpSecurity userDetailsService(UserDetailsService userDetailsService) throws Exception {
        getAuthenticationRegistry().userDetailsService(userDetailsService);
        return this;
    }

    private AuthenticationManagerBuilder getAuthenticationRegistry() {
        return getSharedObject(AuthenticationManagerBuilder.class);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#addFilterAfter(javax.servlet.Filter, java.lang.Class)
     */
    @Override
    public HttpSecurity addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
        comparitor.registerAfter(filter.getClass(), afterFilter);
        return addFilter(filter);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#addFilterBefore(javax.servlet.Filter, java.lang.Class)
     */
    @Override
    public HttpSecurity addFilterBefore(Filter filter, Class<? extends Filter> beforeFilter) {
        comparitor.registerBefore(filter.getClass(), beforeFilter);
        return addFilter(filter);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#addFilter(javax.servlet.Filter)
     */
    @Override
    public HttpSecurity addFilter(Filter filter) {
        Class<? extends Filter> filterClass = filter.getClass();
        if(!comparitor.isRegistered(filterClass)) {
            throw new IllegalArgumentException(
                    "The Filter class " + filterClass.getName()
                            + " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
        }
        this.filters.add(filter);
        return this;
    }

    /**
     * Allows specifying which {@link HttpServletRequest} instances this
     * {@link HttpSecurity} will be invoked on.  This method allows for
     * easily invoking the {@link HttpSecurity} for multiple
     * different {@link RequestMatcher} instances. If only a single {@link RequestMatcher}
     * is necessary consider using {@link #antMatcher(String)},
     * {@link #regexMatcher(String)}, or {@link #requestMatcher(RequestMatcher)}.
     *
     * <p>
     * Invoking {@link #requestMatchers()} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * <h3>Example Configurations</h3>
     *
     * The following configuration enables the {@link HttpSecurity} for URLs that
     * begin with "/api/" or "/oauth/".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .requestMatchers()
     *                 .antMatchers("/api/**","/oauth/**")
     *                 .and()
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * The configuration below is the same as the previous configuration.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .requestMatchers()
     *                 .antMatchers("/api/**")
     *                 .antMatchers("/oauth/**")
     *                 .and()
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * The configuration differs from the previous configurations because it invokes
     * {@link #requestMatchers()} twice which resets the {@link RequestMatcherConfigurer}.
     * Therefore the configuration below only matches on URLs that start with "/oauth/**".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .requestMatchers()
     *                 .antMatchers("/api/**")
     *                 .and()
     *             .requestMatchers()
     *                 .antMatchers("/oauth/**")
     *                 .and()
     *             .authorizeUrls()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void registerAuthentication(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return the {@link RequestMatcherConfigurer} for further customizations
     */
    public RequestMatcherConfigurer requestMatchers() {
        return new RequestMatcherConfigurer();
    }

    /**
     * Allows configuring the {@link HttpSecurity} to only be invoked when
     * matching the provided {@link RequestMatcher}. If more advanced configuration is
     * necessary, consider using {@link #requestMatchers()}.
     *
     * <p>
     * Invoking {@link #requestMatcher(RequestMatcher)} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * @param requestMatcher the {@link RequestMatcher} to use (i.e. new AntPathRequestMatcher("/admin/**","GET") )
     * @return the {@link HttpSecurity} for further customizations
     * @see #requestMatchers()
     * @see #antMatcher(String)
     * @see #regexMatcher(String)
     */
    public HttpSecurity requestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    /**
     * Allows configuring the {@link HttpSecurity} to only be invoked when
     * matching the provided ant pattern. If more advanced configuration is
     * necessary, consider using {@link #requestMatchers()} or
     * {@link #requestMatcher(RequestMatcher)}.
     *
     * <p>
     * Invoking {@link #antMatcher(String)} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * @param antPattern the Ant Pattern to match on (i.e. "/admin/**")
     * @return the {@link HttpSecurity} for further customizations
     * @see AntPathRequestMatcher
     */
    public HttpSecurity antMatcher(String antPattern) {
        return requestMatcher(new AntPathRequestMatcher(antPattern));
    }

    /**
     * Allows configuring the {@link HttpSecurity} to only be invoked when
     * matching the provided regex pattern. If more advanced configuration is
     * necessary, consider using {@link #requestMatchers()} or
     * {@link #requestMatcher(RequestMatcher)}.
     *
     * <p>
     * Invoking {@link #regexMatcher(String)} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * @param pattern the Regular Expression to match on (i.e. "/admin/.+")
     * @return the {@link HttpSecurity} for further customizations
     * @see RegexRequestMatcher
     */
    public HttpSecurity regexMatcher(String pattern) {
        return requestMatcher(new RegexRequestMatcher(pattern, null));
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#getAuthenticationManager()
     */
    @Override
    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    /**
     * Allows mapping HTTP requests that this {@link HttpSecurity} will be used for
     *
     * @author Rob Winch
     * @since 3.2
     */
    public final class RequestMatcherConfigurer extends AbstractRequestMatcherConfigurer<HttpSecurity,RequestMatcherConfigurer,DefaultSecurityFilterChain> {

        protected RequestMatcherConfigurer chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            requestMatcher(new OrRequestMatcher(requestMatchers));
            return this;
        }

        /**
         * Return the {@link HttpSecurity} for further customizations
         *
         * @return the {@link HttpSecurity} for further customizations
         */
        public HttpSecurity and() {
            return HttpSecurity.this;
        }

        private RequestMatcherConfigurer(){}
    }

    /**
     * Internal {@link RequestMatcher} instance used by {@link RequestMatcher}
     * that will match if any of the passed in {@link RequestMatcher} instances
     * match.
     *
     * @author Rob Winch
     * @since 3.2
     */
    private static final class OrRequestMatcher implements RequestMatcher {
        private final List<RequestMatcher> requestMatchers;

        private OrRequestMatcher(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            for(RequestMatcher matcher : requestMatchers) {
                if(matcher.matches(request)) {
                    return true;
                }
            }
            return false;
        }
    }
}