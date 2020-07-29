/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for {@link OAuth2ResourceServerApplication}
 *
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class OAuth2ResourceServerApplicationITests {

	String noScopesToken = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.IyeWtsTonaiWJdoT13B0M7gpqVxAirVGlfqFI4TOmTRcVHICs_ESezS7fa0ODS9XYdwklTtG7hH39yeeMzr2Zo1Ghh-m36fdoqQrV1Do04rUvuTjqbgyNffeZEGB6rquJ-cyAVjp_Oljy10-Bbnw7CeVGwNBSVo9UCB5j49OlNWhLxFpYARFmOlYpXj-s4Q4JiqV6EvjDAYeohAR4QQmND3qoxR-s2I6SLcIho0sSSpUlhrRiqu2uvWefHDcZJdW2WYWnxLHxhzNu3CfnLiqhhaA_YA_iWXR9FYnPDCf_4q3FgSXcgttXzomFKAx5DwnE_dXvsCvpWxslZMU1UIiLA.MHOrrza2GQ9_5PIv.zU4tfhxT6apWBC3stBwQmGlCQBltWVQe4dFIykybWWBFqxo1bf2BZ37twzoEIFXG9jSYEMH4mvBXPWSvn66t-_jnqLnKTJst2plBjhagGCAoLNWXVKeYNp67o-lKOD_JJQFqsRw4oE05VSgRr14MZeaUBFcU3A_kKxMXOu899DKfXBGJvj75H7lDyd8RUXTb-OSWWfUiJc6Y5AUy1zCZCN9yfDsCXt9heTsZANy92Oou9sMFaXkYzyums5OtkBtLFzyuNMEoNioRehTV-FTuL8tDRB1mNhHObwsBfFbR6M1jJK37pHUXGtko-yZ6NGwxyLtwGh4uU2jzE614rQzuzR8aHaHxOkUs1pBTZ8AcRt41snByOe-KU0adthHxedobFiQQBoQ05DgSU7DO6hsK0uVBDF3eG2KjH4L2lZy-WugloLHhdguUoO9F0zUx15-XZO4EVzmhy8xfH2tSXz98eKzz9Dv0DdGnrBL9cK2MM88N1zoq5u4NdlnE12HvuesB7GKdMwZx1-gTw_pzP81TzcctJWl6ETK09Uc.jk0O8qc4Fvip856stDz05Q";
	String messageReadToken = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.CRBAEgvQhpB6pPQhpkTAKpsDai1FDcvkDSRig1R3OI-g18JdTe-qDhzWwP-hV3aCwFwHxQ_g8Z8OIZvhyKpQaPwBb72UeLqqhzSIkm0gEsmmjYg1vEGOrDH5_Fqlm0LnAnXTmsbOIWYIj11ZuenI2lEmMCkVwqth0RlzakdcHRXiuDTEln_trhZpE2j80X-9rS2gZy9Raa9VLir3-F3wC0GKPEL6e3x1OygC03ix9uyXS3vpTsU9zlgoYADZyaLeOF1mCG4mQhvXs7IPmPbwNsElJwKh0xSQCHvNOQShprlvd3cHiUFKYw9fXphY1O-AUYcRzHk4DjoBdkGNQMy_Kw.KtC_z674rYBtDgkN.e8QU50Iq1JHkn-1USSxpjEkbrukb4cobvlQRK40iXGAKVIuOod4bSq5fDpIAPHugqIf-_zGsvr-2OCOdzhtBikL46wU7UdZppxPWtk-X6kl33zH_XObRMaGfe-hLxt3RPxRVn7I1Hp6tGW1Rkxyf_ESq4XlcbbrkhDoIz_G_LKXJhvQ-xahW2e0AUc7RZSucns4XUeq9xX_dd7Ht-o1TmQI9WFoFc1l7oh9GtQ6GZMsghnZ1VrbIS2L7jSYiSsD2JqSv1LLtOGj_FBA0ufhqM3LloGiwflEwAryMD10oNb73WonKEycEj1rBsTIKW7SHkI-VkrQA4-8N-aLWgHwDnzyPZmyNyKpqUMvhjIE_0w6oqU4HpN7J5nfBEIAtpPZ_pDkwAdxCQ7JV3zfiUnF7ZQ3q1PnSId315si02ZN9-wRSrMHcHnboQN1Hs4xCAfGyClVyLpCzfa_fAehjt6v1DjgjbzwSjr_LdNmWTvXYBhNO8Jq9Vb7axksrdwksD3pYNMY8cRZxP-LO0V5Sv1_kT_Hf2yLo2iTwB8n8szzGrJ4QQLb5Znu7Sv-M2x52cnIDMiorP3LNpFk.G85FuMSm-8bGumFAStiFQA";

	@Autowired
	MockMvc mvc;

	@Test
	public void performWhenValidBearerTokenThenAllows()
		throws Exception {

		this.mvc.perform(get("/").with(bearerToken(this.noScopesToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Hello, subject!")));
	}

	@Test
	public void performWhenValidBearerTokenThenScopedRequestsAlsoWork()
			throws Exception {

		this.mvc.perform(get("/message").with(bearerToken(this.messageReadToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("secret message")));
	}

	@Test
	public void performWhenInsufficientlyScopedBearerTokenThenDeniesScopedMethodAccess()
			throws Exception {

		this.mvc.perform(get("/message").with(bearerToken(this.noScopesToken)))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Bearer error=\"insufficient_scope\"")));
	}

	private static class BearerTokenRequestPostProcessor implements RequestPostProcessor {
		private String token;

		BearerTokenRequestPostProcessor(String token) {
			this.token = token;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			request.addHeader("Authorization", "Bearer " + this.token);
			return request;
		}
	}

	private static BearerTokenRequestPostProcessor bearerToken(String token) {
		return new BearerTokenRequestPostProcessor(token);
	}
}
