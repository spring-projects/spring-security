/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.config.http;


import java.security.Principal
import javax.servlet.Filter
import org.springframework.beans.BeansException
import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.SecurityConfig
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.BeanIds
import org.springframework.security.config.MockUserServiceBeanPostProcessor
import org.springframework.security.config.PostProcessedMockUserDetailsService
import org.springframework.security.config.util.InMemoryXmlApplicationContext
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.openid.OpenIDAuthenticationFilter
import org.springframework.security.util.FieldUtils
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.PortMapperImpl
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.SessionManagementFilter
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler
import org.springframework.security.web.firewall.DefaultHttpFirewall
import org.springframework.security.BeanNameCollectingPostProcessor
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.access.expression.WebExpressionVoter
import org.springframework.security.access.vote.AffirmativeBased
import org.springframework.security.access.PermissionEvaluator
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.authentication.AuthenticationManager


/**
 *
 * @author Rob Winch
 */
class InterceptUrlConfigTests extends AbstractHttpConfigTests {

   def "SEC-2256: intercept-url method is not given priority"() {
       when:
           httpAutoConfig {
               'intercept-url'(pattern: '/anyurl', access: "ROLE_USER")
               'intercept-url'(pattern: '/anyurl', 'method':'GET',access: 'ROLE_ADMIN')
           }
           createAppContext()

           def fids = getFilter(FilterSecurityInterceptor).securityMetadataSource
           def attrs = fids.getAttributes(createFilterinvocation("/anyurl", "GET"))
           def attrsPost = fids.getAttributes(createFilterinvocation("/anyurl", "POST"))

       then:
           attrs.size() == 1
           attrs.contains(new SecurityConfig("ROLE_USER"))
           attrsPost.size() == 1
           attrsPost.contains(new SecurityConfig("ROLE_USER"))
   }
}