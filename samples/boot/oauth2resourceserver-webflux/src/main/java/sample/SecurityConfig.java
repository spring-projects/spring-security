/*
 * Copyright 2002-2018 the original author or authors.
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

package sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * @author Rob Winch
 * @since 5.1
 */
@EnableWebFluxSecurity
public class SecurityConfig {
	private static final String JWK_SET_URI_PROP = "sample.jwk-set-uri";

	@Bean
	@ConditionalOnProperty(SecurityConfig.JWK_SET_URI_PROP)
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, @Value("${sample.jwk-set-uri}") String jwkSetUri) throws Exception {
		http
			.authorizeExchange()
				.anyExchange().authenticated()
				.and()
			.oauth2()
				.resourceServer()
					.jwt()
						.jwkSetUri(jwkSetUri);
		return http.build();
	}

	@Bean
	@ConditionalOnProperty(matchIfMissing = true, name = SecurityConfig.JWK_SET_URI_PROP)
	SecurityWebFilterChain springSecurityFilterChainWithJwkSetUri(ServerHttpSecurity http) throws Exception {
		http
			.authorizeExchange()
				.anyExchange().authenticated()
				.and()
			.oauth2()
				.resourceServer()
					.jwt()
						.publicKey(publicKey());
		return http.build();
	}

	private RSAPublicKey publicKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		String modulus = "21301844740604653578042500449274548398885553541276518010855123403873267398204269788903348794459771698460057967144865511347818036788093430902099139850950702438493841101242291810362822203615900335437741117578551216365305797763072813300890517195382010982402736091906390325356368590938709762826676219814134995844721978269999358693499223506089799649124650473473086179730568497569430199548044603025675755473148289824338392487941265829853008714754732175256733090080910187256164496297277607612684421019218165083081805792835073696987599616469568512360535527950859101589894643349122454163864596223876828010734083744763850611111";
		String exponent = "65537";

		RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) factory.generatePublic(spec);
	}
}
