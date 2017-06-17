package net.videgro.poc.cisco_pw_hashes;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

public class CiscoPasswordHashType09Test {
    private CiscoPasswordHashType09 ciscoPasswordHashType09;

    @Before
    public void setup() {
        ciscoPasswordHashType09 = new CiscoPasswordHashType09();
    }

    @Test
    public void testGenerateHash1() {
        final String password = "cisco";
        final String salt = "nhEmQVczB7dqsO";

        final String hash = ciscoPasswordHashType09.generateHash(password, salt);
        assertEquals("$9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM", hash);
    }

    @Test
    public void testGenerateHash2() {
        final String password = "hashcat";
        final String salt = "2MJBozw/9R3UsU";

        final String hash = ciscoPasswordHashType09.generateHash(password, salt);
        assertEquals("$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6", hash);
    }

    @Test
    public void testGenerateHash3() {
        final String password = "123456";
        final String salt = "cvWdfQlRRDKq/U";

        final String hash = ciscoPasswordHashType09.generateHash(password, salt);
        assertEquals("$9$cvWdfQlRRDKq/U$VFTPha5VHTCbSgSUAo.nPoh50ZiXOw1zmljEjXkaq1g", hash);
    }

    @Test
    public void testGenerateHash4() {
        final String password = "JtR";
        final String salt = "X9fA8mypebLFVj";

        final String hash = ciscoPasswordHashType09.generateHash(password, salt);
        assertEquals("$9$X9fA8mypebLFVj$Klp6X9hxNhkns0kwUIinvLRSIgWOvCwDhVTZqjsycyU", hash);
    }
    
    @Test
    public void testGenerateHash5() {
        final String password = "videgro";
        final String salt = "salt";

        final String hash = ciscoPasswordHashType09.generateHash(password, salt);
        assertEquals("$9$salt$mwoksv.VaKEzdcytBnQMWWnpDLjfbMSJb6Rp9r8nAWY", hash);
    }
}
