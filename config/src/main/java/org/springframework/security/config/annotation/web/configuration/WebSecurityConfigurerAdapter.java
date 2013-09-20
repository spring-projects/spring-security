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
package org.springframework.security.config.annotation.web.configuration;


import javax.servlet.Filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * Provides a convenient base class for creating a {@link WebSecurityConfigurer}
 * instance. The implementation allows customization by overriding methods.
 *
 * @see EnableWebSecurity
 *
 * @author Rob Winch
 */
public abstract class WebSecurityConfigurerAdapter implements SecurityConfigurer<Filter,WebSecurity> {
    private final Log logger = LogFactory.getLog(WebSecurityConfigurerAdapter.class);

    private ApplicationContext context;

    private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();

    private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
        public <T> T postProcess(T object) {
            throw new IllegalStateException(ObjectPostProcessor.class.getName()+ " is a required bean. Ensure you have used @EnableWebSecurity and @Configuration");
        }
    };

    private final AuthenticationManagerBuilder authenticationBuilder = new AuthenticationManagerBuilder(ObjectPostProcessor.QUIESCENT_POSTPROCESSOR);
    private final AuthenticationManagerBuilder parentAuthenticationBuilder = new AuthenticationManagerBuilder(ObjectPostProcessor.QUIESCENT_POSTPROCESSOR) {
        @Override
        public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
            authenticationBuilder.eraseCredentials(eraseCredentials);
            return super.eraseCredentials(eraseCredentials);
        }

    };
    private boolean disableAuthenticationRegistration;
    private boolean authenticationManagerInitialized;
    private AuthenticationManager authenticationManager;
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private HttpSecurity http;
    private boolean disableDefaults;

    /**
     * Creates an instance with the default configuration enabled.
     */
    protected WebSecurityConfigurerAdapter() {
        this(false);
    }

    /**
     * Creates an instance which allows specifying if the default configuration
     * should be enabled. Disabling the default configuration should be
     * considered more advanced usage as it requires more understanding of how
     * the framework is implemented.
     *
     * @param disableDefaults
     *            true if the default configuration should be enabled, else
     *            false
     */
    protected WebSecurityConfigurerAdapter(boolean disableDefaults) {
        this.disableDefaults = disableDefaults;
    }

    /**
     * Used by the default implementation of {@link #authenticationManager()} to attempt to obtain an
     * {@link AuthenticationManager}. If overridden, the {@link AuthenticationManagerBuilder} should be used to specify
     * the {@link AuthenticationManager}. The resulting {@link AuthenticationManager}
     * will be exposed as a Bean as will the last populated {@link UserDetailsService} that is created with the
     * {@link AuthenticationManagerBuilder}. The {@link UserDetailsService} will also automatically be populated on
     * {@link HttpSecurity#getSharedObject(Class)} for use with other {@link SecurityContextConfigurer}
     * (i.e. RememberMeConfigurer )
     *
     * <p>For example, the following configuration could be used to register
     * in memory authentication that exposes an in memory {@link UserDetailsService}:</p>
     *
     * <pre>
     * &#064;Override
     * protected void registerAuthentication(AuthenticationManagerBuilder auth) {
     *     auth
     *         // enable in memory based authentication with a user named "user" and "admin"
     *         .inMemoryAuthentication()
     *             .withUser("user").password("password").roles("USER").and()
     *             .withUser("admin").password("password").roles("USER", "ADMIN");
     * }
     * </pre>
     *
     * @param auth the {@link AuthenticationManagerBuilder} to use
     * @throws Exception
     */
    protected void registerAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        this.disableAuthenticationRegistration = true;
    }

    /**
     * Creates the {@link HttpSecurity} or returns the current instance
     *
     * @return the {@link HttpSecurity}
     * @throws Exception
     */
    protected final HttpSecurity getHttp() throws Exception {
        if(http != null) {
            return http;
        }

        authenticationBuilder.objectPostProcessor(objectPostProcessor);
        parentAuthenticationBuilder.objectPostProcessor(objectPostProcessor);

        DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
        parentAuthenticationBuilder.authenticationEventPublisher(eventPublisher);

        AuthenticationManager authenticationManager = authenticationManager();
        authenticationBuilder.parentAuthenticationManager(authenticationManager);
        http = new HttpSecurity(objectPostProcessor,authenticationBuilder, parentAuthenticationBuilder.getSharedObjects());
        http.setSharedObject(UserDetailsService.class, userDetailsService());
        http.setSharedObject(ApplicationContext.class, context);
        http.setSharedObject(ContentNegotiationStrategy.class, contentNegotiationStrategy);
        http.setSharedObject(AuthenticationTrustResolver.class, trustResolver);
        if(!disableDefaults) {
            http
                .csrf().and()
                .addFilter(new WebAsyncManagerIntegrationFilter())
                .exceptionHandling().and()
                .headers().and()
                .sessionManagement().and()
                .securityContext().and()
                .requestCache().and()
                .anonymous().and()
                .servletApi().and()
                .apply(new DefaultLoginPageConfigurer<HttpSecurity>()).and()
                .logout();
        }
        configure(http);
        return http;
    }

    /**
     * Override this method to expose the {@link AuthenticationManager} from
     * {@link #registerAuthentication(AuthenticationManagerBuilder)} to be exposed as
     * a Bean. For example:
     *
     * <pre>
     * &#064;Bean(name name="myAuthenticationManager")
     * &#064;Override
     * public AuthenticationManager authenticationManagerBean() throws Exception {
     *     return super.authenticationManagerBean();
     * }
     * </pre>
     *
     * @return the {@link AuthenticationManager}
     * @throws Exception
     */
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return new AuthenticationManagerDelegator(authenticationBuilder);
    }

    /**
     * Gets the {@link AuthenticationManager} to use. The default strategy is if
     * {@link #registerAuthentication(AuthenticationManagerBuilder)} method is
     * overridden to use the {@link AuthenticationManagerBuilder} that was passed in.
     * Otherwise, autowire the {@link AuthenticationManager} by type.
     *
     * @return
     * @throws Exception
     */
    protected AuthenticationManager authenticationManager() throws Exception {
        if(!authenticationManagerInitialized) {
            registerAuthentication(parentAuthenticationBuilder);
            if(disableAuthenticationRegistration) {
                try {
                    authenticationManager = context.getBean(AuthenticationManagerBuilder.class).getOrBuild();
                } catch(NoSuchBeanDefinitionException e) {
                    logger.debug("Could not obtain the AuthenticationManagerBuilder. This is ok for now, we will try using an AuthenticationManager directly",e);
                }
                if(authenticationManager == null) {
                    try {
                        authenticationManager = context.getBean(AuthenticationManager.class);
                    } catch(NoSuchBeanDefinitionException e) {
                        logger.debug("The AuthenticationManager was not found. This is ok for now as it may not be required.",e);
                    }
                }
            } else {
                authenticationManager = parentAuthenticationBuilder.build();
            }
            authenticationManagerInitialized = true;
        }
        return authenticationManager;
    }

    /**
     * Override this method to expose a {@link UserDetailsService} created from
     * {@link #registerAuthentication(AuthenticationManagerBuilder)} as a bean. In
     * general only the following override should be done of this method:
     *
     * <pre>
     * &#064;Bean(name = "myUserDetailsService") // any or no name specified is allowed
     * &#064;Override
     * public UserDetailsService userDetailsServiceBean() throws Exception {
     *     return super.userDetailsServiceBean();
     * }
     * </pre>
     *
     * To change the instance returned, developers should change
     * {@link #userDetailsService()} instead
     * @return
     * @throws Exception
     * @see {@link #userDetailsService()}
     */
    public UserDetailsService userDetailsServiceBean() throws Exception {
        return new UserDetailsServiceDelegator(parentAuthenticationBuilder);
    }

    /**
     * Allows modifying and accessing the {@link UserDetailsService} from
     * {@link #userDetailsServiceBean()()} without interacting with the
     * {@link ApplicationContext}. Developers should override this method when
     * changing the instance of {@link #userDetailsServiceBean()}.
     *
     * @return
     */
    protected UserDetailsService userDetailsService() {
        return parentAuthenticationBuilder.getDefaultUserDetailsService();
    }

    public void init(final WebSecurity web) throws Exception {
        final HttpSecurity http = getHttp();
        web
            .addSecurityFilterChainBuilder(http)
            .postBuildAction(new Runnable() {
                public void run() {
                    FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
                    web.securityInterceptor(securityInterceptor);
                }
            });
    }

    /**
     * Override this method to configure {@link WebSecurity}. For
     * example, if you wish to ignore certain requests.
     */
    public void configure(WebSecurity web) throws Exception {
    }

    /**
     * Override this method to configure the {@link HttpSecurity}.
     * Typically subclasses should not invoke this method by calling super
     * as it may override their configuration. The default configuration is:
     *
     * <pre>
     * http
     *     .authorizeRequests()
     *         .anyRequest().authenticated().and()
     *     .formLogin().and()
     *     .httpBasic();
     * </pre>
     *
     * @param http
     *            the {@link HttpSecurity} to modify
     * @throws Exception
     *             if an error occurs
     */
    protected void configure(HttpSecurity http) throws Exception {
        logger.debug("Using default configure(HttpSecurity). If subclassed this will potentially override subclass configure(HttpSecurity).");

        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin().and()
            .httpBasic();
    }

    @Autowired
    public void setApplicationContext(ApplicationContext context) {
        this.context = context;
    }

    @Autowired(required=false)
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    @Autowired(required=false)
    public void setContentNegotationStrategy(ContentNegotiationStrategy contentNegotiationStrategy) {
        this.contentNegotiationStrategy = contentNegotiationStrategy;
    }

    @Autowired(required=false)
    public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }


    /**
     * Delays the use of the {@link UserDetailsService} from the
     * {@link AuthenticationManagerBuilder} to ensure that it has been fully
     * configured.
     *
     * @author Rob Winch
     * @since 3.2
     */
    static final class UserDetailsServiceDelegator implements UserDetailsService {
        private AuthenticationManagerBuilder delegateBuilder;
        private UserDetailsService delegate;
        private final Object delegateMonitor = new Object();

        UserDetailsServiceDelegator(AuthenticationManagerBuilder authentication) {
            this.delegateBuilder = authentication;
        }

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            if(delegate != null) {
                return delegate.loadUserByUsername(username);
            }

            synchronized(delegateMonitor) {
                if (delegate == null) {
                    delegate = this.delegateBuilder.getDefaultUserDetailsService();
                    this.delegateBuilder = null;
                }
            }

            return delegate.loadUserByUsername(username);
        }
    }


    /**
     * Delays the use of the {@link AuthenticationManager} build from the
     * {@link AuthenticationManagerBuilder} to ensure that it has been fully
     * configured.
     *
     * @author Rob Winch
     * @since 3.2
     */
    static final class AuthenticationManagerDelegator implements AuthenticationManager {
        private AuthenticationManagerBuilder delegateBuilder;
        private AuthenticationManager delegate;
        private final Object delegateMonitor = new Object();

        AuthenticationManagerDelegator(AuthenticationManagerBuilder authentication) {
            this.delegateBuilder = authentication;
        }

        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if(delegate != null) {
                return delegate.authenticate(authentication);
            }

            synchronized(delegateMonitor) {
                if (delegate == null) {
                    delegate = this.delegateBuilder.getObject();
                    this.delegateBuilder = null;
                }
            }

            return delegate.authenticate(authentication);
        }
    }
}