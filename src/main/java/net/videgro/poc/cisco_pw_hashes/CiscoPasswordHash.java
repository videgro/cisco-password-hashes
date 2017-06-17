package net.videgro.poc.cisco_pw_hashes;

/**
 * References: 
 * 
 * - https://github.com/magnumripper/JohnTheRipper/issues/711
 * 
 * - https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/pass_gen.pl
 *   (Perl methods: base64_wpa and crypt_to64_wpa)
 * 
 * - https://github.com/wg/scrypt
 *   (com.lambdaworks:scrypt)
 */
public abstract class CiscoPasswordHash {
    private static final String ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    protected static final String UTF8 = "UTF-8";

    /**
     * Length
     */
    protected static final int LEN = 32;

    protected static String base64_wpa(final byte[] in) {
        final StringBuilder result = new StringBuilder();

        final int len = in.length;
        final int mod = len % 3;
        final int cnt = (len - mod) / 3;

        for (int i = 0; i < cnt; i++) {
            final int c = Byte.toUnsignedInt(in[i * 3]);
            final int b = Byte.toUnsignedInt(in[i * 3 + 1]);
            final int a = Byte.toUnsignedInt(in[i * 3 + 2]);
            final int l = ((c << 16) | (b << 8) | a);
            result.append(crypt_to64_wpa(l, 4));
        }
        if (mod == 2) {
            final int c = Byte.toUnsignedInt(in[len - 2]);
            final int b = Byte.toUnsignedInt(in[len - 1]);
            final int l = ((c << 16) | (b << 8));
            result.append(crypt_to64_wpa(l, 3));
        }
        if (mod == 1) {
            final int c = Byte.toUnsignedInt(in[len - 1]);
            final int l = ((c << 16));
            result.append(crypt_to64_wpa(l, 2));
        }
        return result.toString();
    }

    private static String crypt_to64_wpa(final int vIn, final int nIn) {
        int v = vIn;
        int n = nIn;

        final StringBuilder result = new StringBuilder();

        while (--n >= 0) {
            result.append(ITOA64.charAt((v & 0xFC0000) >> 18));
            v <<= 6;
        }
        return result.toString();
    }

    public abstract String generateHash(final String password, final String salt);
}
