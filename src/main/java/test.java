import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;

public class test {
    private static ECDSA ecdsa = new ECDSA();
    private static PointMultiplication PM = new PointMultiplication();

    public static void main(String[] args) throws NoSuchAlgorithmException {
        BigInteger k1 = ecdsa.SelectK();
        BigInteger k2 = ecdsa.SelectK();
        /*ECPoint G1 = PM.AddPoint(ecdsa.G, ecdsa.G);
        ECPoint G2 = PM.DoublePoint(ecdsa.G);
        System.out.println(G1.getAffineX().toString());
        System.out.println(G2.getAffineX().toString());*/
        ECPoint G1 = PM.ScalarMulti(k1, ecdsa.G);
        ECPoint G2 = PM.ScalarMulti(k2, ecdsa.G);
        BigInteger x1 = G1.getAffineX();
        BigInteger y1 = G1.getAffineY();
        BigInteger x2 = G2.getAffineX();
        BigInteger y2 = G2.getAffineY();
        ECPoint G3 = PM.AddPoint(G1,G2);
        BigInteger x3 = G3.getAffineX();
        BigInteger y3 = G3.getAffineY();
        BigInteger A = x1.subtract(x2).pow(2).multiply(x3.pow(2));
        BigInteger tempB = x1.add(x2).multiply((x1.multiply(x2).add(ecdsa.key.a)));
        BigInteger B = tempB.add(ecdsa.key.b.multiply(new BigInteger("2"))).multiply(x3).multiply(new BigInteger("2"));
        BigInteger C1 = x1.multiply(x2).subtract(ecdsa.key.a).pow(2);
        BigInteger C2 = x1.add(x2).multiply(ecdsa.key.b).multiply(new BigInteger("4"));
        BigInteger result = A.subtract(B).add(C1).subtract(C2).mod(((ecdsa.key).p));
        System.out.println(result.toString());

    }
}