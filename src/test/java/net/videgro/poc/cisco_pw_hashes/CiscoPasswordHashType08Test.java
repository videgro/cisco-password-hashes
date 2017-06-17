package net.videgro.poc.cisco_pw_hashes;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

public class CiscoPasswordHashType08Test {
    private CiscoPasswordHashType08 ciscoPasswordHashType08;

    @Before
    public void setup() {
        ciscoPasswordHashType08 = new CiscoPasswordHashType08();
    }

    @Test
    public void testGenerateHash1() {
        final String password = "cisco";
        final String salt = "dsYGNam3K1SIJO";

        final String hash = ciscoPasswordHashType08.generateHash(password, salt);
        assertEquals("$8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs", hash);
    }

    @Test
    public void testGenerateHash2() {
        final String password = "hashcat";
        final String salt = "TnGX/fE4KGHOVU";

        final String hash = ciscoPasswordHashType08.generateHash(password, salt);
        assertEquals("$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk", hash);
    }
    
    @Test
    public void testGenerateHash3() {
        final String password = "videgro";
        final String salt = "salt";

        final String hash = ciscoPasswordHashType08.generateHash(password, salt);
        assertEquals("$8$salt$NBq6Kank5gX/nWGmQtbPzwXJeevKLw2suiWRmImSoiQ", hash);
    }
}
