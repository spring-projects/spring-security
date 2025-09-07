/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.crypto.password4j;

import com.password4j.Argon2Function;
import com.password4j.BcryptFunction;
import com.password4j.CompressedPBKDF2Function;
import com.password4j.ScryptFunction;
import com.password4j.types.Argon2;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link Password4jPasswordEncoder}.
 *
 * @author Mehrdad Bozorgmehr
 */
class Password4jPasswordEncoderTests {

    private static final String PASSWORD = "password";
    private static final String WRONG_PASSWORD = "wrongpassword";
    private static final String UNICODE_PASSWORD = "пароль123🔐";
    private static final String LONG_PASSWORD = "a".repeat(1000);

    // Constructor Tests
    @Test
    void constructorWithNullAlgorithmShouldThrowException() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new Password4jPasswordEncoder(null))
                .withMessage("algorithm cannot be null");
    }

    @Test
    void constructorWithNullHashingFunctionShouldThrowException() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new Password4jPasswordEncoder(null, Password4jPasswordEncoder.Password4jAlgorithm.BCRYPT))
                .withMessage("hashingFunction cannot be null");
    }

    @Test
    void constructorWithNullAlgorithmAndValidHashingFunctionShouldThrowException() {
        BcryptFunction function = BcryptFunction.getInstance(10);
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new Password4jPasswordEncoder(function, null))
                .withMessage("algorithm cannot be null");
    }

    @Test
    void defaultConstructorShouldUseBCrypt() {
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder();
        assertThat(encoder.getAlgorithm()).isEqualTo(Password4jPasswordEncoder.Password4jAlgorithm.BCRYPT);
        assertThat(encoder.getHashingFunction()).isInstanceOf(BcryptFunction.class);
    }

    // BCrypt Tests
    @Test
    void bcryptEncoderShouldEncodeAndVerifyPasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.bcrypt(10);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded)
                .isNotNull()
                .isNotEqualTo(PASSWORD)
                .startsWith("$2b$10$");// Password4j uses $2b$ format

        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
        assertThat(encoder.matches(null, encoded)).isFalse();
        assertThat(encoder.matches(PASSWORD, null)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {4, 6, 8, 10, 12, 14})
    void bcryptWithDifferentRoundsShouldWork(int rounds) {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.bcrypt(rounds);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded).startsWith("$2b$" + String.format("%02d", rounds) + "$");
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    @Test
    void bcryptShouldProduceDifferentHashesForSamePassword() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.bcrypt(10);

        String hash1 = encoder.encode(PASSWORD);
        String hash2 = encoder.encode(PASSWORD);

        assertThat(hash1).isNotEqualTo(hash2);
        assertThat(encoder.matches(PASSWORD, hash1)).isTrue();
        assertThat(encoder.matches(PASSWORD, hash2)).isTrue();
    }

    // SCrypt Tests
    @Test
    void scryptEncoderShouldEncodeAndVerifyPasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.scrypt(16384, 8, 1, 32);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded).isNotNull().isNotEqualTo(PASSWORD);

        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
    }

    @Test
    void scryptWithDifferentParametersShouldWork() {
        Password4jPasswordEncoder encoder1 = Password4jPasswordEncoder.scrypt(8192, 8, 1, 32);
        Password4jPasswordEncoder encoder2 = Password4jPasswordEncoder.scrypt(16384, 16, 2, 64);

        String hash1 = encoder1.encode(PASSWORD);
        String hash2 = encoder2.encode(PASSWORD);

        assertThat(encoder1.matches(PASSWORD, hash1)).isTrue();
        assertThat(encoder2.matches(PASSWORD, hash2)).isTrue();
        assertThat(hash1).isNotEqualTo(hash2);
    }

    // Argon2 Tests
    @Test
    void argon2EncoderShouldEncodeAndVerifyPasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.argon2(
                65536, 3, 4, 32, Argon2.ID);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded)
                .isNotNull()
                .isNotEqualTo(PASSWORD)
                .startsWith("$argon2id$");

        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
    }

    @ParameterizedTest
    @EnumSource(Argon2.class)
    void argon2WithDifferentTypesShouldWork(Argon2 type) {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.argon2(
                65536, 3, 4, 32, type);

        String encoded = encoder.encode(PASSWORD);
        String expectedPrefix = switch (type) {
            case D -> "$argon2d$";
            case I -> "$argon2i$";
            case ID -> "$argon2id$";
        };

        assertThat(encoded).startsWith(expectedPrefix);
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    // PBKDF2 Tests
    @Test
    void pbkdf2EncoderShouldEncodeAndVerifyPasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.pbkdf2(100000, 32);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded)
                .isNotNull()
                .isNotEqualTo(PASSWORD);

        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
    }

    @Test
    void compressedPbkdf2EncoderShouldEncodeAndVerifyPasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.compressedPbkdf2(100000, 32);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded)
                .isNotNull()
                .isNotEqualTo(PASSWORD);

        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
    }

    @ParameterizedTest
    @CsvSource({
            "50000, 16",
            "100000, 32",
            "200000, 64",
            "500000, 32"
    })
    void pbkdf2WithDifferentParametersShouldWork(int iterations, int keyLength) {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.pbkdf2(iterations, keyLength);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    // Factory Method Tests
    @Test
    void defaultsForSpringSecurityShouldUseBCrypt() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        assertThat(encoder.getAlgorithm()).isEqualTo(Password4jPasswordEncoder.Password4jAlgorithm.BCRYPT);
        assertThat(encoder.getHashingFunction()).isInstanceOf(BcryptFunction.class);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded).startsWith("$2b$10$"); // Password4j uses $2b$ format
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    // Null and Empty Input Tests
    @Test
    void encodeNullPasswordShouldReturnNull() {
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder();
        assertThat(encoder.encode(null)).isNull();
    }

    @Test
    void encodeEmptyPasswordShouldWork() {
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder();
        String encoded = encoder.encode("");
        assertThat(encoded).isNotNull();
        // AbstractValidatingPasswordEncoder returns false for empty raw passwords
        assertThat(encoder.matches("", encoded)).isFalse();
    }

    @Test
    void matchesWithNullOrEmptyParametersShouldReturnFalse() {
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder();
        String validHash = encoder.encode(PASSWORD);

        assertThat(encoder.matches(null, validHash)).isFalse();
        assertThat(encoder.matches("", validHash)).isFalse();
        assertThat(encoder.matches(PASSWORD, null)).isFalse();
        assertThat(encoder.matches(PASSWORD, "")).isFalse();
        assertThat(encoder.matches(null, null)).isFalse();
        assertThat(encoder.matches("", "")).isFalse();
    }

    // Password Variety Tests
    @ParameterizedTest
    @ValueSource(strings = {"password", "123456", "P@ssw0rd!", "a very long password with spaces and symbols !@#$%"})
    void shouldHandleVariousPasswordFormats(String password) {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        String encoded = encoder.encode(password);
        assertThat(encoded).isNotNull();
        assertThat(encoder.matches(password, encoded)).isTrue();
        assertThat(encoder.matches(password + "x", encoded)).isFalse();
    }

    @Test
    void shouldHandleUnicodePasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        String encoded = encoder.encode(UNICODE_PASSWORD);
        assertThat(encoded).isNotNull();
        assertThat(encoder.matches(UNICODE_PASSWORD, encoded)).isTrue();
        assertThat(encoder.matches("password", encoded)).isFalse();
    }

    @Test
    void shouldHandleLongPasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        String encoded = encoder.encode(LONG_PASSWORD);
        assertThat(encoded).isNotNull();
        assertThat(encoder.matches(LONG_PASSWORD, encoded)).isTrue();
    }

    // Upgrade Encoding Tests
    @Test
    void upgradeEncodingShouldReturnFalse() {
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder();
        String encoded = encoder.encode(PASSWORD);

        // For now, upgradeEncoding should return false
        assertThat(encoder.upgradeEncoding(encoded)).isFalse();
        assertThat(encoder.upgradeEncoding(null)).isFalse();
        assertThat(encoder.upgradeEncoding("")).isFalse();
    }

    @ParameterizedTest
    @EnumSource(Password4jPasswordEncoder.Password4jAlgorithm.class)
    void upgradeEncodingShouldReturnFalseForAllAlgorithms(Password4jPasswordEncoder.Password4jAlgorithm algorithm) {
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(algorithm);
        String encoded = encoder.encode(PASSWORD);

        assertThat(encoder.upgradeEncoding(encoded)).isFalse();
    }

    // Custom Hashing Function Tests
    @Test
    void shouldWorkWithCustomHashingFunction() {
        BcryptFunction customFunction = BcryptFunction.getInstance(12);
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(customFunction, Password4jPasswordEncoder.Password4jAlgorithm.BCRYPT);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded).startsWith("$2b$12$"); // Password4j uses $2b$ format
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    @Test
    void shouldWorkWithCustomScryptFunction() {
        ScryptFunction customFunction = ScryptFunction.getInstance(32768, 16, 2, 64);
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(customFunction, Password4jPasswordEncoder.Password4jAlgorithm.SCRYPT);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    @Test
    void shouldWorkWithCustomArgon2Function() {
        Argon2Function customFunction = Argon2Function.getInstance(131072, 4, 8, 64, Argon2.ID);
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(customFunction, Password4jPasswordEncoder.Password4jAlgorithm.ARGON2);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded).startsWith("$argon2id$");
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    // Algorithm Coverage Tests
    @Test
    void shouldCreateEncoderForEachAlgorithm() {
        // Test all algorithm types can be instantiated
        for (Password4jPasswordEncoder.Password4jAlgorithm algorithm : Password4jPasswordEncoder.Password4jAlgorithm.values()) {
            Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(algorithm);
            assertThat(encoder.getAlgorithm()).isEqualTo(algorithm);

            String encoded = encoder.encode(PASSWORD);
            assertThat(encoded).isNotNull();
            assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        }
    }

    @ParameterizedTest
    @EnumSource(Password4jPasswordEncoder.Password4jAlgorithm.class)
    void allAlgorithmsShouldProduceValidHashes(Password4jPasswordEncoder.Password4jAlgorithm algorithm) {
        Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(algorithm);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoded)
                .isNotNull()
                .isNotEmpty()
                .isNotEqualTo(PASSWORD);

        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
    }

    // Security Properties Tests
    @RepeatedTest(10)
    void samePasswordShouldProduceDifferentHashes() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        String hash1 = encoder.encode(PASSWORD);
        String hash2 = encoder.encode(PASSWORD);

        // Hashes should be different (due to salt)
        assertThat(hash1).isNotEqualTo(hash2);

        // But both should verify correctly
        assertThat(encoder.matches(PASSWORD, hash1)).isTrue();
        assertThat(encoder.matches(PASSWORD, hash2)).isTrue();
    }

    @Test
    void hashLengthShouldBeConsistent() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        String hash1 = encoder.encode("short");
        String hash2 = encoder.encode("this is a much longer password with many characters");

        // BCrypt hashes should have consistent length
        assertThat(hash1).hasSize(60); // BCrypt produces 60-character hashes
        assertThat(hash2).hasSize(60);
    }

    @Test
    void similarPasswordsShouldProduceCompletelyDifferentHashes() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        String hash1 = encoder.encode("password");
        String hash2 = encoder.encode("password1");
        String hash3 = encoder.encode("Password");

        assertThat(hash1)
                .isNotEqualTo(hash2)
                .isNotEqualTo(hash3);
        assertThat(hash2).isNotEqualTo(hash3);

        // Cross-verification should fail
        assertThat(encoder.matches("password", hash2)).isFalse();
        assertThat(encoder.matches("password1", hash1)).isFalse();
    }


    // Additional Security and Robustness Tests
    @Test
    void shouldHandleVeryLongPasswords() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();
        String veryLongPassword = "a".repeat(10000); // 10KB password

        String encoded = encoder.encode(veryLongPassword);
        assertThat(encoded).isNotNull();
        assertThat(encoder.matches(veryLongPassword, encoded)).isTrue();
        // Fix: BCrypt truncates passwords longer than 72 bytes, so we need to test with a meaningful difference
        // Test with a shorter difference that's within the 72-byte limit
        String slightlyDifferentPassword = "b" + veryLongPassword.substring(1); // Change first character
        assertThat(encoder.matches(slightlyDifferentPassword, encoded)).isFalse();
    }

    @Test
    void shouldHandlePasswordsWithNullBytes() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();
        String passwordWithNull = "password\u0000test";

        String encoded = encoder.encode(passwordWithNull);
        assertThat(encoded).isNotNull();
        assertThat(encoder.matches(passwordWithNull, encoded)).isTrue();
        assertThat(encoder.matches("passwordtest", encoded)).isFalse();
    }

    @Test
    void shouldProduceStrongRandomness() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();
        java.util.Set<String> hashes = new java.util.HashSet<>();

        // Generate many hashes of the same password
        for (int i = 0; i < 100; i++) {
            String hash = encoder.encode(PASSWORD);
            assertThat(hashes.add(hash)).isTrue(); // Each hash should be unique
        }

        assertThat(hashes).hasSize(100);
    }

    @Test
    void shouldResistTimingAttacks() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();
        String validHash = encoder.encode(PASSWORD);

        // Measure time for correct password
        long startTime = System.nanoTime();
        boolean result1 = encoder.matches(PASSWORD, validHash);
        long correctTime = System.nanoTime() - startTime;

        // Measure time for wrong password of same length
        startTime = System.nanoTime();
        boolean result2 = encoder.matches("passwore", validHash); // Same length, different content
        long wrongTime = System.nanoTime() - startTime;

        assertThat(result1).isTrue();
        assertThat(result2).isFalse();

        // Times should be relatively close (within 10x factor for timing attack resistance)
        double ratio = Math.max(correctTime, wrongTime) / (double) Math.min(correctTime, wrongTime);
        assertThat(ratio).isLessThan(10.0);
    }


    @Test
    void scryptShouldHandleEdgeCaseParameters() {
        // Test with minimum viable parameters
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.scrypt(2, 1, 1, 16);

        String encoded = encoder.encode(PASSWORD);
        assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
    }

    @Test
    void argon2ShouldWorkWithDifferentMemorySizes() {
        // Test with various memory configurations
        int[] memorySizes = {1024, 4096, 16384, 65536};

        for (int memory : memorySizes) {
            Password4jPasswordEncoder encoder = Password4jPasswordEncoder.argon2(memory, 2, 1, 32, Argon2.ID);
            String encoded = encoder.encode(PASSWORD);
            assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
        }
    }

    @Test
    void pbkdf2ShouldWorkWithDifferentHashAlgorithms() {
        // Test that the implementation handles different internal configurations
        Password4jPasswordEncoder encoder1 = Password4jPasswordEncoder.pbkdf2(50000, 16);
        Password4jPasswordEncoder encoder2 = Password4jPasswordEncoder.pbkdf2(100000, 32);
        Password4jPasswordEncoder encoder3 = Password4jPasswordEncoder.pbkdf2(200000, 64);

        String hash1 = encoder1.encode(PASSWORD);
        String hash2 = encoder2.encode(PASSWORD);
        String hash3 = encoder3.encode(PASSWORD);

        assertThat(encoder1.matches(PASSWORD, hash1)).isTrue();
        assertThat(encoder2.matches(PASSWORD, hash2)).isTrue();
        assertThat(encoder3.matches(PASSWORD, hash3)).isTrue();

        // Hashes should be different due to different parameters
        assertThat(hash1).isNotEqualTo(hash2);
        assertThat(hash2).isNotEqualTo(hash3);
    }

    // Cross-Algorithm Verification Tests
    @Test
    void differentAlgorithmsShouldNotCrossVerify() {
        Password4jPasswordEncoder bcryptEncoder = Password4jPasswordEncoder.bcrypt(10);
        Password4jPasswordEncoder scryptEncoder = Password4jPasswordEncoder.scrypt(16384, 8, 1, 32);
        Password4jPasswordEncoder argon2Encoder = Password4jPasswordEncoder.argon2(65536, 3, 4, 32, Argon2.ID);

        String bcryptHash = bcryptEncoder.encode(PASSWORD);
        String scryptHash = scryptEncoder.encode(PASSWORD);
        String argon2Hash = argon2Encoder.encode(PASSWORD);

        // Each encoder should only verify its own hashes
        assertThat(bcryptEncoder.matches(PASSWORD, bcryptHash)).isTrue();
        assertThat(bcryptEncoder.matches(PASSWORD, scryptHash)).isFalse();
        assertThat(bcryptEncoder.matches(PASSWORD, argon2Hash)).isFalse();

        assertThat(scryptEncoder.matches(PASSWORD, scryptHash)).isTrue();
        assertThat(scryptEncoder.matches(PASSWORD, bcryptHash)).isFalse();
        assertThat(scryptEncoder.matches(PASSWORD, argon2Hash)).isFalse();

        assertThat(argon2Encoder.matches(PASSWORD, argon2Hash)).isTrue();
        assertThat(argon2Encoder.matches(PASSWORD, bcryptHash)).isFalse();
        assertThat(argon2Encoder.matches(PASSWORD, scryptHash)).isFalse();
    }


    @Test
    void encodingShouldCompleteInReasonableTime() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        long startTime = System.currentTimeMillis();
        String encoded = encoder.encode(PASSWORD);
        long duration = System.currentTimeMillis() - startTime;

        assertThat(encoded).isNotNull();
        assertThat(duration).isLessThan(5000); // Should complete within 5 seconds
    }

    // Compatibility and Integration Tests
    @Test
    void shouldBeCompatibleWithSpringSecurityConventions() {
        Password4jPasswordEncoder encoder = Password4jPasswordEncoder.defaultsForSpringSecurity();

        // Test common Spring Security patterns
        assertThat(encoder.encode(null)).isNull();
        assertThat(encoder.matches(null, "hash")).isFalse();
        assertThat(encoder.matches("password", null)).isFalse();
        assertThat(encoder.upgradeEncoding("anyhash")).isFalse();

        // Test that it follows AbstractValidatingPasswordEncoder contract
        assertThat(encoder.matches("", "")).isFalse();
        assertThat(encoder.upgradeEncoding("")).isFalse();
    }

    @Test
    void factoryMethodsShouldCreateCorrectInstances() {
        // Verify all factory methods create properly configured instances
        Password4jPasswordEncoder bcrypt = Password4jPasswordEncoder.bcrypt(12);
        assertThat(bcrypt.getAlgorithm()).isEqualTo(Password4jPasswordEncoder.Password4jAlgorithm.BCRYPT);
        assertThat(bcrypt.getHashingFunction()).isInstanceOf(BcryptFunction.class);

        Password4jPasswordEncoder scrypt = Password4jPasswordEncoder.scrypt(32768, 8, 1, 32);
        assertThat(scrypt.getAlgorithm()).isEqualTo(Password4jPasswordEncoder.Password4jAlgorithm.SCRYPT);
        assertThat(scrypt.getHashingFunction()).isInstanceOf(ScryptFunction.class);

        Password4jPasswordEncoder argon2 = Password4jPasswordEncoder.argon2(65536, 3, 4, 32, Argon2.ID);
        assertThat(argon2.getAlgorithm()).isEqualTo(Password4jPasswordEncoder.Password4jAlgorithm.ARGON2);
        assertThat(argon2.getHashingFunction()).isInstanceOf(Argon2Function.class);

        Password4jPasswordEncoder pbkdf2 = Password4jPasswordEncoder.pbkdf2(100000, 32);
        assertThat(pbkdf2.getAlgorithm()).isEqualTo(Password4jPasswordEncoder.Password4jAlgorithm.PBKDF2);
        assertThat(pbkdf2.getHashingFunction()).isInstanceOf(CompressedPBKDF2Function.class);

        Password4jPasswordEncoder compressedPbkdf2 = Password4jPasswordEncoder.compressedPbkdf2(100000, 32);
        assertThat(compressedPbkdf2.getAlgorithm()).isEqualTo(Password4jPasswordEncoder.Password4jAlgorithm.COMPRESSED_PBKDF2);
        assertThat(compressedPbkdf2.getHashingFunction()).isInstanceOf(CompressedPBKDF2Function.class);
    }
}
