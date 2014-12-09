package org.springframework.security.test.web.servlet.response;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = SecurityMockMvcResultMatchersTests.Config.class)
@WebAppConfiguration
public class SecurityMockMvcResultMatchersTests {
    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                    .apply(springSecurity())
                    .build();
    }

    // SEC-2719
    @Test
    public void withRolesNotOrderSensitive() throws Exception {
        mockMvc.perform(formLogin())
            .andExpect(authenticated().withRoles("USER","SELLER"))
            .andExpect(authenticated().withRoles("SELLER","USER"));
    }

    @Test(expected = AssertionError.class)
    public void withRolesFailsIfNotAllRoles() throws Exception {
        mockMvc.perform(formLogin())
            .andExpect(authenticated().withRoles("USER"));
    }

    @EnableWebSecurity
    @EnableWebMvc
    static class Config extends WebSecurityConfigurerAdapter {

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").roles("USER","SELLER").password("password");
        }

        @RestController
        static class Controller {
            @RequestMapping("/")
            public String ok() {
                return "ok";
            }
        }
    }
}
