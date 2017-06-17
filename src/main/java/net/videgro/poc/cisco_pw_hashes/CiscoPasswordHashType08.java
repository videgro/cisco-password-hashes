package net.videgro.poc.cisco_pw_hashes;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lambdaworks.crypto.PBKDF;

/**
 * Calculate a Cisco Type 8 password hash
 */
public class CiscoPasswordHashType08 extends CiscoPasswordHash {
    private static final Logger LOGGER = LoggerFactory.getLogger(CiscoPasswordHashType08.class);

    private static final String PBKDF2_ALGORITHM = "HmacSHA256";

    /**
     * Iteration count
     */
    private static final int C = 20000;

    public String generateHash(final String password, final String salt) {
        String result = null;
        byte[] derived = null;
        try {
            final Mac mac = Mac.getInstance(PBKDF2_ALGORITHM);
            mac.init(new SecretKeySpec(password.getBytes(CiscoPasswordHash.UTF8), PBKDF2_ALGORITHM));

            derived = new byte[CiscoPasswordHash.LEN];

            PBKDF.pbkdf2(mac, salt.getBytes(CiscoPasswordHash.UTF8), C, derived, CiscoPasswordHash.LEN);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            LOGGER.error("generateHash", e);
        }

        if (derived != null) {
            result = String.format("$8$%s$%s", salt, base64_wpa(derived));
        }

        LOGGER.trace("Generated Cisco Type 8 password hash for password: {}, with salt: {}, hash: {}", password, salt, result);
        return result;
    }
}
