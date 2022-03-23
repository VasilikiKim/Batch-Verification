
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.util.encoders.Hex;

public class GenerateKey {
    // public static void main(String [] arg) throws NoSuchAlgorithmException ,
// NoSuchProviderException , InvalidAlgorithmParameterException {
// Define the parameters of sextuple T = (p,a,b,G,n,h) of curve Secp256k1
   /** p ：from  Fp
    * n : a prime close to p
    * a,b : coefficients from the elliptic curve
    * G ： generator
    * h: a Cofactor, must be positive
    */

   /** initiate these parameters */
    public static BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16);
    public static BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16);
    public static BigInteger a = new BigInteger(
            "0000000000000000000000000000000000000000000000000000000000000000",
            16);
    public static BigInteger b = new BigInteger(
            "0000000000000000000000000000000000000000000000000000000000000007",
            16);
    /**
     * Creat Elliptic Curve based on ECField Fp,a, b
     */
    public static EllipticCurve curve = new EllipticCurve(new ECFieldFp(p),// p
            a, // a
            b);// b
    public static ECPoint G = ECPointUtil.decodePoint(
            curve ,
            Hex.decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
            ;// G
    /**
     * Create elliptic curve parameters based on specified values
     */
    static ECParameterSpec ecSpec = new ECParameterSpec(curve , G, // G
            N, // n
            1); // h
    /**
     * This method generates a secure random ECDSA public/private key pair.
     */
    public BigInteger [] KeyGeneration ()
            throws InvalidAlgorithmParameterException ,
            NoSuchAlgorithmException , NoSuchProviderException {
    // generate the key pair randomly
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SunEC");
        g.initialize(ecSpec , new SecureRandom ());
        KeyPair pair = g.generateKeyPair ();
    // get the private key
        PrivateKey priKey = pair.getPrivate ();
        BigInteger s = ((ECPrivateKey) priKey).getS ();
    // get the public key
        PublicKey pubKey = pair.getPublic ();
        ECPoint w = ((ECPublicKey) pubKey).getW ();
        BigInteger [] keypair = { s, w.getAffineX (), w.getAffineY () };
        BigInteger px = w.getAffineX ();
        BigInteger py = w.getAffineY ();
    // if the length of x and y in public key is not 32 bytes , regenerate
    // the key pair
        if (px.toByteArray ().length != 32 || py.toByteArray ().length != 32) {
            return KeyGeneration ();
        }
        return keypair;
    }
}
