= Unit-testing OAuth2 secured `@Component`s
The aim here is offering the ability to configure unit tests security-context with OAuth2 authentication.

Three different authentication implementations are supported: JWT, access-token and OidcId token.

Each of those authentication type can be setup three different ways:
  * request post-processors. Concise and easy to aggregate in functions of your own for most common scenari, but limited to servlets `@Controller`s testing
  * annotations. Familiar for those used to `@WithMockUser` and allow testing any kind of `@Component` (`@Controller`s of course but also services)
  * mutators (implement `WebTestClientConfigurer` and `MockServerConfigurer`). Provide with a flow API for reactive apps
  
== Authorities related processing
Quite a few tricks are applied to merge authorities, roles and scopes:
  * authorities with "SCOPE_" prefix are added to scope claim
  * scopes from scope claim (with either "scope" or "scp" name) are added to authorities after being pre-pended with "SCOPE_"
  * scope claim value can either be a single string with roles separated by spaces or a `Collection` implementation
  * roles are pre-pended with "ROLE_" before being added to authorities

== Request post-processors
MockMvc `.with(...)` method is an extension point for further request processing.
This feature is used here to setup SecurityContext with highly configurable authentications.

=== `JwtRequestPostProcessor`
`org.springframework.security.test.oauth2.request.OAuth2MockMvcRequestPostProcessors.mockJwt()`
returns a post-processor which populates SecurityContext with a `JwtAuthenticationToken` you can tune
setting roles, scopes, authorities, authentication name, etc.

Sample usage:
``` java
@RunWith(SpringRunner.class)
@WebMvcTest(OAuth2ResourceServerController.class)
public class OAuth2ResourceServerControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockBean
    JwtDecoder jwtDecoder;

    @Test
    public void testRequestPostProcessor() throws Exception {
        // No post-processor => no authorization => unauthorized
        mockMvc.perform(get("/message")).andDo(print()).andExpect(status().isUnauthorized());

        //Run with default Authentication: subject is "user" and sole authority is "USER" role
        mockMvc.perform(get("/").with(mockJwt()))
                .andExpect(status().isOk())
                .andExpect(content().string(is("Hello, user!")));

        //Customize Authentication name
        mockMvc.perform(get("/").with(mockJwt().name("ch4mpy")))
                .andExpect(status().isOk())
                .andExpect(content().string(is("Hello, ch4mpy!")));

        //Customize roles, scopes and authorities
        mockMvc.perform(get("/message").with(mockJwt().scope("message:read")))
                .andExpect(status().isOk())
                .andExpect(content().string(is("secret message")));

        //Add custom claims
        mockMvc.perform(get("/message")
                .with(mockJwt()
                        .name("ch4mpy")
                        .authority("SCOPE_message:read")
                        .claim("iat", Instant.parse("2019-03-28T16:36:00Z"))))
                .andExpect(status().isOk())
                .andExpect(content().string(is("secret message")));
    }
}
```
 
 === `AccessTokenRequestPostProcessor`
`org.springframework.security.test.oauth2.request.OAuth2MockMvcRequestPostProcessors.accessToken()`
returns a post-processor which populates SecurityContext with a `OAuth2IntrospectionAuthenticationToken` you can tune
at wish.

Usage is pretty similar to `JwtRequestPostProcessor`.

=== `OidcIdTokenRequestPostProcessor`
Just as `AccessTokenRequestPostProcessor` or `JwtRequestPostProcessor`, call
`org.springframework.security.test.oauth2.request.OAuth2MockMvcRequestPostProcessors.oidcIdToken()` to configure an `OAuth2LoginAuthenticationToken`.

== Annotations
With `@WithMockUser` as model, allow OAuth2 applications components unit testing

=== `@WithMockJwt`
Offers the same SecurityContext configuration options as `JwtRequestPostProcessor`.

Complete sample usage on a service:
``` java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = MessageServiceTest.SecurityConfiguration.class)
public class MessageServiceTest {

    @Autowired
    private MessageService messageService;

    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void greetWitoutMockJwt() {
        messageService.getGreeting();
    }

    @Test
    @WithMockJwt(name = "ch4mpy")
    public void greetWithMockJwt() {
        assertThat(messageService.getGreeting()).isEqualTo("Hello, ch4mpy!");
    }

    @Test(expected = AccessDeniedException.class)
    @WithMockJwt
    public void secretWithoutMessageReadScope() {
        assertThat(messageService.getSecret()).isEqualTo("Secret message");
    }

    @Test
    @WithMockJwt("SCOPE_message:read") // same as:
    // @WithMockJwt(scopes = "message:read")
    // @WithMockJwt(claims = @Attribute(name = "scope", value = "message:read", parser = StringSetParser.class))
    public void secretWithScopeMessageReadAuthority() {
        assertThat(messageService.getSecret()).isEqualTo("Secret message");
    }

    interface MessageService {

        @PreAuthorize("authenticated")
        String getGreeting();

        @PreAuthorize("hasAuthority('SCOPE_message:read')")
        String getSecret();
    }

    @Component
    static final class MessageServiceImpl implements MessageService {

        @Override
        public String getGreeting() {
            return String.format("Hello, %s!", SecurityContextHolder.getContext().getAuthentication().getName());
        }

        @Override
        public String getSecret() {
            return "Secret message";
        }

    }

    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @ComponentScan(basePackageClasses = MessageService.class)
    static class SecurityConfiguration {

        @Bean
        JwtDecoder jwtDecoder() {
            return null;
        }
    }
}
```

=== `@WithMockAccessToken`
Offers the same SecurityContext configuration options as `AccessTokenRequestPostProcessor`.

=== `@WithMockOidcIdToken`
Offers the same SecurityContext configuration options as `OidcIdTokenRequestPostProcessor`.

== Reactive API
Not much more to say here as usage is pretty similar to servlet request post-processors.
Just `import static org.springframework.security.test.oauth2.reactive.server.OAuth2SecurityMockServerConfigurers.*;` and you're all set.
