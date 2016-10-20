package org.bouncycastle.jcajce.provider.digest;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
// BEGIN ANDROID-ADDED
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
// END ANDROID-ADDED
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE;
import org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

public class SHA1
{
    private SHA1()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new SHA1Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new SHA1Digest((SHA1Digest)digest);

            return d;
        }
    }

    /**
     * SHA1 HMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new SHA1Digest()));
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACSHA1", 160, new CipherKeyGenerator());
        }
    }

    /**
     * SHA1 HMac
     */
    public static class SHA1Mac
        extends BaseMac
    {
        public SHA1Mac()
        {
            super(new HMac(new SHA1Digest()));
        }
    }

    // BEGIN ANDROID-ADDED
    public static class SHA224Mac
            extends BaseMac
    {
        public SHA224Mac()
        {
            super(new HMac(new SHA224Digest()));
        }
    }

    public static class SHA256Mac
            extends BaseMac
    {
        public SHA256Mac()
        {
            super(new HMac(new SHA256Digest()));
        }
    }

    public static class SHA384Mac
            extends BaseMac
    {
        public SHA384Mac()
        {
            super(new HMac(new SHA384Digest()));
        }
    }

    public static class SHA512Mac
            extends BaseMac
    {
        public SHA512Mac()
        {
            super(new HMac(new SHA512Digest()));
        }
    }
    // END ANDROID-ADDED

    /**
     * PBEWithHmacSHA
     */
    public static class PBEWithMacKeyFactory
        extends PBESecretKeyFactory
    {
        public PBEWithMacKeyFactory()
        {
            super("PBEwithHmacSHA", null, false, PKCS12, SHA1, 160, 0);
        }
    }

    // BEGIN ANDROID-CHANGED
    // Was: public static class BasePBKDF2WithHmacSHA1
    private static class BasePBKDF2WithHmacSHA_Variant
    // END ANDROID-CHANGED
        extends BaseSecretKeyFactory
    {
        private int scheme;
        // BEGIN ANDROID-ADDED
        private int digest;
        private int keySizeInBits;
        private int ivSizeInBits;
        // END ANDROID-ADDED

        // BEGIN ANDROID-CHANGED
        // Was: public BasePBKDF2WithHmacSHA1(String name, int scheme)
        private BasePBKDF2WithHmacSHA_Variant(
                String name, int scheme, int digest, int keySizeInBits, int ivSizeInBits)
        // END ANDROID-CHANGED
        {
            super(name, PKCSObjectIdentifiers.id_PBKDF2);

            this.scheme = scheme;
            // BEGIN ANDROID-ADDED
            this.digest = digest;
            this.keySizeInBits = keySizeInBits;
            this.ivSizeInBits = ivSizeInBits;
            // END ANDROID-ADDED
        }

        // BEGIN android-added
        private BasePBKDF2WithHmacSHA_Variant(String name, int scheme, int digest) {
            this(name, scheme, digest, 0, 0);
        }
        // END android-added

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PBEKeySpec)
            {
                PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;

                // BEGIN ANDROID-ADDED
                // Allow to specify a key using only the password. The key will be generated later
                // when other parameters are known.
                if (pbeSpec.getSalt() == null
                        && pbeSpec.getIterationCount() == 0
                        && pbeSpec.getKeyLength() == 0
                        && pbeSpec.getPassword().length > 0
                        && keySizeInBits != 0) {
                    return new BCPBEKey(
                            this.algName, this.algOid, scheme, digest, keySizeInBits, ivSizeInBits,
                            pbeSpec,
                            // cipherParameters, to be generated when the PBE parameters are known.
                            null);
                }
                // END ANDROID-ADDED

                if (pbeSpec.getSalt() == null)
                {
                    throw new InvalidKeySpecException("missing required salt");
                }

                if (pbeSpec.getIterationCount() <= 0)
                {
                    throw new InvalidKeySpecException("positive iteration count required: "
                        + pbeSpec.getIterationCount());
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                if (pbeSpec.getPassword().length == 0)
                {
                    throw new IllegalArgumentException("password empty");
                }

                // BEGIN android-removed
                // int digest = SHA1;
                // END android-removed
                int keySize = pbeSpec.getKeyLength();
                int ivSize = -1;    // JDK 1,2 and earlier does not understand simplified version.
                CipherParameters param = PBE.Util.makePBEMacParameters(pbeSpec, scheme, digest, keySize);

                return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, param);
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    // BEGIN android-added
    public static class BasePBKDF2WithHmacSHA1 extends BasePBKDF2WithHmacSHA_Variant {
        public BasePBKDF2WithHmacSHA1(String name, int scheme)
        {
            super(name, scheme, SHA1);
        }
    }
    // END android-added

    public static class PBKDF2WithHmacSHA1UTF8
        extends BasePBKDF2WithHmacSHA1
    {
        public PBKDF2WithHmacSHA1UTF8()
        {
            super("PBKDF2WithHmacSHA1", PKCS5S2_UTF8);
        }
    }

    public static class PBKDF2WithHmacSHA18BIT
        extends BasePBKDF2WithHmacSHA1
    {
        public PBKDF2WithHmacSHA18BIT()
        {
            super("PBKDF2WithHmacSHA1And8bit", PKCS5S2);
        }
    }

    // BEGIN ANDROID-ADDED
    public static class BasePBKDF2WithHmacSHA224 extends BasePBKDF2WithHmacSHA_Variant {
        public BasePBKDF2WithHmacSHA224(String name, int scheme)
        {
            super(name, scheme, SHA224);
        }
    }

    public static class PBKDF2WithHmacSHA224UTF8
            extends BasePBKDF2WithHmacSHA224
    {
        public PBKDF2WithHmacSHA224UTF8()
        {
            super("PBKDF2WithHmacSHA224", PKCS5S2_UTF8);
        }
    }

    public static class BasePBKDF2WithHmacSHA256 extends BasePBKDF2WithHmacSHA_Variant {
        public BasePBKDF2WithHmacSHA256(String name, int scheme)
        {
            super(name, scheme, SHA256);
        }
    }

    public static class PBKDF2WithHmacSHA256UTF8
            extends BasePBKDF2WithHmacSHA256
    {
        public PBKDF2WithHmacSHA256UTF8()
        {
            super("PBKDF2WithHmacSHA256", PKCS5S2_UTF8);
        }
    }


    public static class BasePBKDF2WithHmacSHA384 extends BasePBKDF2WithHmacSHA_Variant {
        public BasePBKDF2WithHmacSHA384(String name, int scheme)
        {
            super(name, scheme, SHA384);
        }
    }

    public static class PBKDF2WithHmacSHA384UTF8
            extends BasePBKDF2WithHmacSHA384
    {
        public PBKDF2WithHmacSHA384UTF8()
        {
            super("PBKDF2WithHmacSHA384", PKCS5S2_UTF8);
        }
    }

    public static class BasePBKDF2WithHmacSHA512 extends BasePBKDF2WithHmacSHA_Variant {
        public BasePBKDF2WithHmacSHA512(String name, int scheme)
        {
            super(name, scheme, SHA512);
        }
    }

    public static class PBKDF2WithHmacSHA512UTF8
            extends BasePBKDF2WithHmacSHA512
    {
        public PBKDF2WithHmacSHA512UTF8()
        {
            super("PBKDF2WithHmacSHA512", PKCS5S2_UTF8);
        }
    }

    public static class PBEWithHmacSHA1AndAES_128
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA1AndAES_128() {
            super("PBEWithHmacSHA1AndAES_128", PKCS5S2_UTF8, SHA1, 128, 128);
        }
    }

    public static class PBEWithHmacSHA224AndAES_128
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA224AndAES_128() {
            super("PBEWithHmacSHA224AndAES_128", PKCS5S2_UTF8, SHA224, 128, 128);
        }
    }

    public static class PBEWithHmacSHA256AndAES_128
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA256AndAES_128() {
            super("PBEWithHmacSHA256AndAES_128", PKCS5S2_UTF8, SHA256, 128, 128);
        }
    }

    public static class PBEWithHmacSHA384AndAES_128
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA384AndAES_128() {
            super("PBEWithHmacSHA384AndAES_128", PKCS5S2_UTF8, SHA384, 128, 128);
        }
    }

    public static class PBEWithHmacSHA512AndAES_128
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA512AndAES_128() {
            super("PBEWithHmacSHA512AndAES_128", PKCS5S2_UTF8, SHA512, 128, 128);
        }
    }


    public static class PBEWithHmacSHA1AndAES_256
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA1AndAES_256() {
            super("PBEWithHmacSHA1AndAES_256", PKCS5S2_UTF8, SHA1, 256, 128);
        }
    }

    public static class PBEWithHmacSHA224AndAES_256
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA224AndAES_256() {
            super("PBEWithHmacSHA224AndAES_256", PKCS5S2_UTF8, SHA224, 256, 128);
        }
    }

    public static class PBEWithHmacSHA256AndAES_256
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA256AndAES_256() {
            super("PBEWithHmacSHA256AndAES_256", PKCS5S2_UTF8, SHA256, 256, 128);
        }
    }

    public static class PBEWithHmacSHA384AndAES_256
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA384AndAES_256() {
            super("PBEWithHmacSHA384AndAES_256", PKCS5S2_UTF8, SHA384, 256, 128);
        }
    }

    public static class PBEWithHmacSHA512AndAES_256
            extends BasePBKDF2WithHmacSHA_Variant {
        public PBEWithHmacSHA512AndAES_256() {
            super("PBEWithHmacSHA512AndAES_256", PKCS5S2_UTF8, SHA512, 256, 128);
        }
    }
    // END ANDROID-ADDED


    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA1.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.SHA-1", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest.SHA1", "SHA-1");
            provider.addAlgorithm("Alg.Alias.MessageDigest.SHA", "SHA-1");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + OIWObjectIdentifiers.idSHA1, "SHA-1");

            addHMACAlgorithm(provider, "SHA1", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
            addHMACAlias(provider, "SHA1", PKCSObjectIdentifiers.id_hmacWithSHA1);
            addHMACAlias(provider, "SHA1", IANAObjectIdentifiers.hmacSHA1);

            provider.addAlgorithm("Mac.PBEWITHHMACSHA", PREFIX + "$SHA1Mac");
            provider.addAlgorithm("Mac.PBEWITHHMACSHA1", PREFIX + "$SHA1Mac");
            // BEGIN android-added
            provider.addAlgorithm("Mac.PBEWITHHMACSHA224", PREFIX + "$SHA224Mac");
            provider.addAlgorithm("Mac.PBEWITHHMACSHA256", PREFIX + "$SHA256Mac");
            provider.addAlgorithm("Mac.PBEWITHHMACSHA384", PREFIX + "$SHA384Mac");
            provider.addAlgorithm("Mac.PBEWITHHMACSHA512", PREFIX + "$SHA512Mac");
            // END android-added
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHHMACSHA", "PBEWITHHMACSHA1");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + OIWObjectIdentifiers.idSHA1, "PBEWITHHMACSHA1");
            provider.addAlgorithm("Alg.Alias.Mac." + OIWObjectIdentifiers.idSHA1, "PBEWITHHMACSHA");

            provider.addAlgorithm("SecretKeyFactory.PBEWITHHMACSHA1", PREFIX + "$PBEWithMacKeyFactory");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WithHmacSHA1", PREFIX + "$PBKDF2WithHmacSHA1UTF8");
            // BEGIN android-added
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WithHmacSHA224", PREFIX + "$PBKDF2WithHmacSHA224UTF8");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WithHmacSHA256", PREFIX + "$PBKDF2WithHmacSHA256UTF8");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WithHmacSHA384", PREFIX + "$PBKDF2WithHmacSHA384UTF8");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WithHmacSHA512", PREFIX + "$PBKDF2WithHmacSHA512UTF8");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA1AndAES_128", PREFIX + "$PBEWithHmacSHA1AndAES_128");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA224AndAES_128", PREFIX + "$PBEWithHmacSHA224AndAES_128");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA256AndAES_128", PREFIX + "$PBEWithHmacSHA256AndAES_128");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA384AndAES_128", PREFIX + "$PBEWithHmacSHA384AndAES_128");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA512AndAES_128", PREFIX + "$PBEWithHmacSHA512AndAES_128");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA1AndAES_256", PREFIX + "$PBEWithHmacSHA1AndAES_256");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA224AndAES_256", PREFIX + "$PBEWithHmacSHA224AndAES_256");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA256AndAES_256", PREFIX + "$PBEWithHmacSHA256AndAES_256");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA384AndAES_256", PREFIX + "$PBEWithHmacSHA384AndAES_256");
            provider.addAlgorithm("SecretKeyFactory.PBEWithHmacSHA512AndAES_256", PREFIX + "$PBEWithHmacSHA512AndAES_256");
            // END android-added
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2WithHmacSHA1AndUTF8", "PBKDF2WithHmacSHA1");
            provider.addAlgorithm("SecretKeyFactory.PBKDF2WithHmacSHA1And8BIT", PREFIX + "$PBKDF2WithHmacSHA18BIT");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2withASCII", "PBKDF2WithHmacSHA1And8BIT");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBKDF2with8BIT", "PBKDF2WithHmacSHA1And8BIT");
        }
    }
}
