
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
public class PointMultiplication {
    public static BigInteger zero = BigInteger.ZERO;
    public static BigInteger two = new BigInteger("2");
    /**
     * This method performs points addition operation given two points p1 and
     * p2.
    */
    public ECPoint AddPoint(ECPoint p1 , ECPoint p2) {
        ECPoint p3 = new ECPoint(zero , zero);
        // p3 is an Infinity point;
        if (p2.getAffineY ().equals(zero)
                || p1.getAffineY ().equals(zero)
                || (p2.getAffineX ().equals(p1.getAffineX ()) && p2.
                getAffineY ()
                .equals(p1.getAffineY ().negate ())))
            p3 = ECPoint.POINT_INFINITY;
        // if two points are equal -- DoublePoint method
        else if ((p1.getAffineX ().equals(p2.getAffineX ()))
                && (p1.getAffineY ().equals(p2.getAffineY ())))
            p3 = DoublePoint(p1);
        // if one of point is an infinity point
        else if (p1.equals(ECPoint.POINT_INFINITY))
            p3 = p2;
        else if (p2.equals(ECPoint.POINT_INFINITY))
            p3 = p1;
        // if points are not equal
        // calculate the slope s = (p2y -p1y)/(p2x -p1x) mod p
        BigInteger s1 = p2.getAffineY ().subtract(p1.getAffineY ()); // s1=yp2 -yp1
        BigInteger s2 = p2.getAffineX ().subtract(p1.getAffineX ()); // s2=xp2 -xp1
        BigInteger s = s1.multiply(s2.modInverse(ECDSA.key.p)).mod(
                ECDSA.key.p);// slope = (s1/s2) mod p
        // calculate p3x =( slope ^2-p1x -p2x) mod p
        BigInteger p3x1 = s.pow (2);// p3x1 = s^2
        BigInteger p3x = p3x1.subtract(p1.getAffineX ())
                .subtract(p2.getAffineX ()).mod(ECDSA.key.p);// p3x =(p3x1 -p1x -p2x)mod p
        // calculate p3y = (slope(p1x -p3x) -p1y) mod p
        BigInteger p3y1 = p1.getAffineX ().subtract(p3x); // p3y1 = p1x -p3x
        BigInteger p3y = s.multiply(p3y1).subtract(p1.getAffineY ())
                .mod(ECDSA.key.p);// p3y = (slope*p3y1 -p1y) mod p
        p3 = new ECPoint(p3x , p3y);
        return p3;
    }
    /**
     * This method performs points doubling operation given one point p.
     */
    public ECPoint DoublePoint(ECPoint P) {
        ECPoint p3 = new ECPoint(zero , zero);
    // calculate the slope = (3*P x^2 +a)/2* Py mod p
        BigInteger s1 = P.getAffineX ().pow (2).multiply(new BigInteger("3"))
                .add(ECDSA.key.a); // s1 = 3* Px ^2 +a
        BigInteger s2 = P.getAffineY ().multiply(new BigInteger("2"));// s2 =2*Py
        BigInteger s = s1.multiply(s2.modInverse(ECDSA.key.p)); // s = (s1/s2)mod p
        // calculate p3x = (slope ^2 - 2* Px) mod p
        BigInteger p3x1 = s.pow (2);// p3x1 = s^2
        BigInteger p3x2 = P.getAffineX ().multiply(new BigInteger("2"));//p3x2 = 2* Px
        BigInteger p3x = p3x1.subtract(p3x2).mod(ECDSA.key.p);// p3x =( p3x1 -p3x2) mod p
        // calculate p3y = (slope(Px -P3X)-Py) mod p
        BigInteger p3y1 = P.getAffineX ().subtract(p3x);// p3y1 = Px -p3x
        BigInteger p3y = s.multiply(p3y1).subtract(P.getAffineY ())
                .mod(ECDSA.key.p);// p3y = (s*p2y1 -Py) mod p
        p3 = new ECPoint(p3x , p3y);
        return p3;

    }
    /**
     * This method performs scalar multiplication operation given one point p
     * and an integer.
     */
    public ECPoint ScalarMulti(BigInteger kin , ECPoint G) {
        String K = kin.toString (2);
        ECPoint q = new ECPoint(zero , zero);
        q = ECPoint.POINT_INFINITY;
        if (K.substring (0, 1).equals("1")) {
            q = G;
        }
        for (int i = 1; i < K.length (); i++) {
            q = DoublePoint(q);
            if (K.substring(i, i + 1).equals("1")) {
                q = AddPoint(q, G);
            }
        }
        return q;
    }

}




