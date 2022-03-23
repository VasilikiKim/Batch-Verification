
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
//import sun.security.ec.ECPrivateKeyImpl;
//import sun.security.ec.ECPublicKeyImpl;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.*;
import java.util.*;

public class ECDSA {
    // get the value of sextuple T = (p,a,b,G,n,h) in curve secp256k1
    public static GenerateKey key = new GenerateKey ();
    public BigInteger N = key.N;
    public static BigInteger p = key.p;
    public BigInteger zero = BigInteger.ZERO;
    public BigInteger one = BigInteger.ONE;
    public EllipticCurve curve = key.curve;
    public ECPoint G = key.G;
    static NumberFormat formatter = new DecimalFormat("#0.00");
    PointMultiplication PM =new PointMultiplication ();
    static TonelliShanks TS = new TonelliShanks();
    //TonelliShanks.Solution s = TS.getTS(zero, one);
    public static int count = 0;


    public static int[][] one_DisjuctMatrix = {{1,0,0,1,0,1},{1,1,0,0,1,0},{0,1,1,1,0,0},{0,0,1,0,1,1}};
    /**
     * This method generates a secure random number k in [1,n -1].
     */
    public BigInteger SelectK () throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom ();
        BigInteger K = new BigInteger (256 , sr);
        K = K.mod(N.subtract(one));
        while (K.equals(zero) || !(K.gcd(p).compareTo(one) == 0)) {
            K = new BigInteger (256 , sr);
            K = K.mod(N.subtract(one));
        }
        return K;
    }
    /*
     * This method signs a message m given the private key.
     */
    public BigInteger [] Sign(byte [] m, BigInteger privatekey)
            throws NoSuchAlgorithmException {
        Long startTime = System.currentTimeMillis ();
        BigInteger K = SelectK ();
        BigInteger dm = SHA1(m);
        // calculate the public key curve point Q.
        ECPoint Q = PM.ScalarMulti(K, G);
        // calculate R = x_q mod N
        BigInteger R = Q.getAffineX ().mod(N);


        BigInteger X = Q.getAffineX();
        BigInteger Y = Q.getAffineY();

        BigInteger temp0 = X.pow(3).add(new BigInteger("7")).mod(p);

        BigInteger temp1 = Y.pow(2).mod(p);

        BigInteger temp2 = (p.subtract(Y)).pow(2).mod(p);
        BigInteger temp = getSqrt(temp0);

        BigInteger temp3 = temp.pow(2).mod(p);
        BigInteger temp4 = p.subtract(temp).pow(2).mod(p);


        // calculate S = k^-1 (dm + R* privateKey ) mod N
        BigInteger Kin = K.modInverse(N);
        BigInteger mm = dm.add(privatekey.multiply(R));
        BigInteger S = (Kin.multiply(mm)).mod(N);
        // if R or S equal to zero , resign the message
        if (R.equals(zero) || S.equals(zero)) {
            K = SelectK ();
            Q = PM.ScalarMulti(K, G);
            R = Q.getAffineX ().mod(N);
            Kin = K.modInverse(N);
            mm = dm.add(privatekey.multiply(R));
            S = (Kin.multiply(mm)).mod(N);
        }
        BigInteger [] Signature = { R, S };
        Long endTime = System.currentTimeMillis ();
        Long totalTime = endTime - startTime;
        //System.out.println("Runing Time of singning in ECDSA:"
        //       +totalTime *1000 + "us");
        return Signature;
    }
    /**
     * This method calculates the hash value by using SHA -1 algorithm .
     */
    public BigInteger SHA1(byte [] m) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte [] result = mDigest.digest(m);
        return new BigInteger(result);
    }
    /**
     * This method verifies a signature on message m given the public key.
     */
    public void batchVerif(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException{
        Long startTime = System.currentTimeMillis();
        BigInteger sumU = new BigInteger("0");
        ECPoint temp = new ECPoint(zero,zero);
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            if (signature [0]. compareTo(N) == 1 || signature [0]. compareTo(one) ==
                    -1
                    || signature [1]. compareTo(N) == 1
                    || signature [1]. compareTo(one) == -1) {
                System.out.println("SIGNATURE WAS NOT IN VALID RANGE");
            }
            BigInteger w = signature[1].modInverse(N);//模乘逆元
            BigInteger h = SHA1(m);
            BigInteger u = (h.multiply(w)).mod(N);
            BigInteger v = (signature [0]. multiply(w)).mod(N);
            sumU = sumU.add(u);
            //ECPoint p1 = PM.ScalarMulti(u, G);// G = P
            ECPoint Q = pks.get(i);
            ECPoint p2 = PM.ScalarMulti(v, Q);
            if(i == 0) temp = p2;
            else{
                temp = PM.AddPoint(temp, p2);
            }
        }
        ECPoint p1 = PM.ScalarMulti(sumU, G);
        ECPoint pt = PM.AddPoint(p1, temp);
        BigInteger R = pt.getAffineX().mod(N);
        System.out.println("R:"+R);
        ArrayList<BigInteger> roots = new ArrayList<BigInteger>();
        BigInteger begin1 = new BigInteger("0");
        BigInteger begin2 = new BigInteger("0");
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            BigInteger b = new BigInteger("7");

            BigInteger yPow = signature[0].pow(3).add(b);
            TonelliShanks.Solution solution = TS.getSoultion(yPow, key.p);
            roots.add(solution.root1);
            roots.add(solution.root2);
            if(i == 0){
                begin1 = solution.root1;
                begin2 = solution.root2;
            }


        }
        if(dfs(roots, signatures, new ECPoint(signatures.get(0)[0], begin1), 1, R) || dfs(roots, signatures, new ECPoint(signatures.get(0)[0], begin2), 1, R) ){
            System.out.println("Valid signature");
            Long endTime = System.currentTimeMillis ();
            Long totalTime = endTime - startTime;
            System.out.println("Runing Time of verification:"
                    + formatter.format(totalTime) + "ms");
        }
        else {
            System.out.println("InValid signature");
            Long endTime = System.currentTimeMillis ();
            Long totalTime = endTime - startTime;
            System.out.println("Runing Time of verification:"
                    + formatter.format(totalTime) + "ms");
        }
        System.out.println("the number of valid signatures:"+count);
    }
    //递归遍历所有根
    private boolean dfs(ArrayList<BigInteger> roots, ArrayList<BigInteger[]> signatures, ECPoint sumP, int height, BigInteger R){
        PointMultiplication PM =new PointMultiplication ();
        if(height == signatures.size()){
            ECDSA.count++;
            System.out.println("sump:"+sumP.getAffineX());
            return sumP.getAffineX().equals(R);
        }
        ECPoint cur1 = new ECPoint(signatures.get(height)[0], roots.get(height*2));
        ECPoint cur2 = new ECPoint(signatures.get(height)[0], roots.get(height*2+1));
        ECPoint sumP1 = PM.AddPoint(sumP, cur1);
        ECPoint sumP2 = PM.AddPoint(sumP, cur2);
        return dfs(roots, signatures, sumP1, height+1, R) || dfs(roots, signatures, sumP2, height+1, R);

    }

    //BigInteger开方 https://blog.csdn.net/mgl934973491/article/details/70337969/
    public BigInteger getSqrt(BigInteger num) {
        String s = num.toString();
        int mlen = s.length();    //被开方数的长度
        int len;    //开方后的长度
        BigInteger beSqrtNum = new BigInteger(s);//被开方数
        BigInteger sqrtOfNum;    //存储开方后的数
        BigInteger sqrtOfNumMul;    //开方数的平方
        String sString;//存储sArray转化后的字符串
        if (mlen % 2 == 0) len = mlen / 2;
        else len = mlen / 2 + 1;
        char[] sArray = new char[len];
        Arrays.fill(sArray, '0');//开方数初始化为0
        for (int pos = 0; pos < len; pos++) {
            //从最高开始遍历数组，
            //每一位都转化为开方数平方后刚好不大于被开方数的程度
            for (char ch = '1'; ch <= '9'; ch++) {
                sArray[pos] = ch;
                sString = String.valueOf(sArray);
                sqrtOfNum = new BigInteger(sString);
                sqrtOfNumMul = sqrtOfNum.multiply(sqrtOfNum);
                if (sqrtOfNumMul.compareTo(beSqrtNum) == 1) {
                    sArray[pos] -= 1;
                    break;
                }
            }
        }
        return new BigInteger(String.valueOf(sArray));
    }
    public void verify(byte [] m, BigInteger [] signature ,
                       ECPoint publickey) throws NoSuchAlgorithmException {
        Long startTime = System.currentTimeMillis ();
        // if R and S is not in [1,n -1] , signature invalid.
        if (signature [0]. compareTo(N) == 1 || signature [0]. compareTo(one) ==
                -1
                || signature [1]. compareTo(N) == 1
                || signature [1]. compareTo(one) == -1) {
            System.out.println("SIGNATURE WAS NOT IN VALID RANGE");
        }
        // calculate w = S^-1 mod N
        BigInteger w = signature [1]. modInverse(N);
        BigInteger h = SHA1(m);
        // calculate u1= hw mod N and u2=Rw mod N
        BigInteger u1 = (h.multiply(w)).mod(N);
        BigInteger u2 = (signature [0]. multiply(w)).mod(N);
        // calculate the curve point (x1 ,x2)=u1*G+u2* publicKey
        ECPoint p1 = PM.ScalarMulti(u1 , G);
        ECPoint p2 = PM.ScalarMulti(u2 , publickey);
        ECPoint pt = PM.AddPoint(p1 , p2);
        // calculate V = x1 mod N
        BigInteger V = pt.getAffineX ().mod(N);
        // if R=V, signature valid , otherwise invalid
        if (V.equals(signature [0]))
            System.out.println("Valid signature");
        else
            System.out.println("Invalid signature");
        Long endTime = System.currentTimeMillis ();
        Long totalTime = endTime - startTime;
        System.out.println("Runing Time of verification:"
                + formatter.format(totalTime) + "ms");
    }
    /**
     * This method generates a signature , verifies it and calculate the running
     * time of the whole process.
     */
/*    public static void main(String [] arg) throws NoSuchAlgorithmException ,
            InvalidAlgorithmParameterException , NoSuchProviderException {
        ECDSA ecdsa = new ECDSA ();
        //Format format = new Format();
        String message = "ECDSA TEST";
        byte [] m = message.getBytes ();
        BigInteger [] keypair = key.KeyGeneration ();
        BigInteger privatekey = keypair [0];
        ECPoint publickey = new ECPoint(keypair [1], keypair [2]);
        System.out.println("private key is: " + privatekey.toString (16));
        //System.out.println("The private key is: "
        //        + format.format(privatekey.toByteArray ()));
        System.out.println("The private key is: "
                + privatekey.toByteArray ());
        System.out.println("x of public key is: "
                + publickey.getAffineX ().toString ());
        System.out.println("y of public key is: "
                + publickey.getAffineY ().toString ());
        BigInteger [] signature = ecdsa.Sign(m, privatekey);
        System.out.println("the value of R is:" + signature [0]);
        System.out.println("the value of S is:" + signature [1]);
        ecdsa.verify(m, signature , publickey);
    }*/
    public HashSet<BigInteger> recursionSummationPolynomialV1(BigInteger[] rs) {
        HashSet<BigInteger> Xi = new HashSet<BigInteger>();
        BigInteger[] parameters = new BigInteger[2];
        System.out.println("--------------recursion starts---------- ");
        if (rs.length > 3) {

            BigInteger[] rs1 = new BigInteger[rs.length / 2 + 1];
            System.arraycopy(rs, 0, rs1, 0, rs1.length - 1);
            BigInteger[] rs2;
            if(rs.length % 2 == 1){
                rs2 = new BigInteger[rs.length / 2 + 2];
            }
            else{
                rs2 = new BigInteger[rs.length / 2 + 1];
            }
            // rs2 = new BigInteger[rs.length / 2 + 1];
            System.arraycopy(rs, rs.length / 2, rs2, 0, rs2.length-1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length - 1] = X;

            System.out.println("-----------samllrs1-------");
            for (BigInteger i : rs1) {
                System.out.println(i.toString());
            }


            HashSet<BigInteger> tempX = new HashSet<BigInteger>();

            tempX = recursionSummationPolynomialV1(rs1);

            for (BigInteger possibleValue : tempX) {
                rs2[rs2.length - 1] = possibleValue;

                System.out.println("-----------samllrs2-------");
                for (BigInteger i : rs2) {
                    System.out.println(i.toString());
                }
                System.out.println("-----------recursionSummationPolynomial(rs2)-------");
                Xi.addAll(recursionSummationPolynomialV1(rs2));
            }

        } else if (rs.length == 3) {
            int count = 0;
            for (BigInteger i : rs) {
                if (i.compareTo(zero) != 0) {
                    System.out.println("count:"+count);
                    parameters[count] = i;
                    count++;
                }
            }
            System.out.println("p0:"+parameters[0]);
            System.out.println("p1:"+parameters[1]);
            Xi.addAll(computeXfromPoly3V1(parameters[0], parameters[1]));
        }
        return Xi;
    }


    public List<BigInteger> recursionSummationPolynomialV2(BigInteger[] rs) {
        List<BigInteger> Xi = new ArrayList<>();
        BigInteger[] parameters = new BigInteger[2];
        //System.out.println("--------------recursion starts---------- ");
        if (rs.length > 3) {

            BigInteger[] rs1 = new BigInteger[rs.length / 2 + 1];
            System.arraycopy(rs, 0, rs1, 0, rs1.length - 1);
            BigInteger[] rs2;
            if(rs.length % 2 == 1){
                rs2 = new BigInteger[rs.length / 2 + 2];
            }
            else{
                rs2 = new BigInteger[rs.length / 2 + 1];
            }
            // rs2 = new BigInteger[rs.length / 2 + 1];
           System.arraycopy(rs, rs.length / 2, rs2, 0, rs2.length-1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length - 1] = X;

           /* System.out.println("-----------samllrs1-------");
            for (BigInteger i : rs1) {
                System.out.println(i.toString());
            }
            */

            List<BigInteger> tempX = new ArrayList<>();

            tempX = recursionSummationPolynomialV2(rs1);

            for (BigInteger possibleValue : tempX) {
                rs2[rs2.length - 1] = possibleValue;

               /* System.out.println("-----------samllrs2-------");
                for (BigInteger i : rs2) {
                    System.out.println(i.toString());
                }
                System.out.println("-----------recursionSummationPolynomial(rs2)-------");
                */
                Xi.addAll(recursionSummationPolynomialV2(rs2));
            }

        } else if (rs.length == 3) {
            int count = 0;
            for (BigInteger i : rs) {
                if (i.compareTo(zero) != 0) {
                    //System.out.println("count:"+count);
                    parameters[count] = i;
                    count++;
                }
            }
            System.out.println("p0:"+parameters[0]);
            System.out.println("p1:"+parameters[1]);
            Xi.addAll(computeXfromPoly3V2(parameters[0], parameters[1]));
        }
        return Xi;
    }

    public  HashSet<BigInteger> computeXfromPoly3V1(BigInteger x1, BigInteger x2) {
        System.out.println("----------------------computeXfromPoly3----------------------");
        BigInteger A = x1.subtract(x2).pow(2);
        BigInteger tempB = x1.add(x2).multiply((x1.multiply(x2).add(key.a)));
        BigInteger B = tempB.add(key.b.multiply(new BigInteger("2"))).multiply(new BigInteger("2")).negate();
        BigInteger C1 = x1.multiply(x2).subtract(key.a).pow(2);
        BigInteger C2 = x1.add(x2).multiply(key.b).multiply(new BigInteger("4"));
        BigInteger C = C1.subtract(C2);
        HashSet<BigInteger> X = new HashSet<BigInteger>();
        BigInteger right = B.pow(2).multiply(A.pow(2).multiply(new BigInteger("4")).modInverse(key.p)).subtract(C.multiply(A.modInverse(key.p))).mod(key.p);
        TonelliShanks.Solution solution = TS.getSoultion(right, key.p);
        BigInteger b2a = B.multiply(A.multiply(new BigInteger("2")).modInverse(key.p));
        System.out.println("r1:" + solution.root1.subtract(b2a).mod(key.p).toString());
        System.out.println("r2:" + solution.root2.subtract(b2a).mod(key.p).toString());
        X.add(solution.root1.subtract(b2a).mod(key.p));
        X.add(solution.root2.subtract(b2a).mod(key.p));

        return X;
    }


    public List<BigInteger> computeXfromPoly3V2(BigInteger x1, BigInteger x2) {
       // System.out.println("----------------------computeXfromPoly3----------------------");
        BigInteger A = x1.subtract(x2).pow(2);
        BigInteger tempB = x1.add(x2).multiply((x1.multiply(x2).add(key.a)));
        BigInteger B = tempB.add(key.b.multiply(new BigInteger("2"))).multiply(new BigInteger("2")).negate();
        BigInteger C1 = x1.multiply(x2).subtract(key.a).pow(2);
        BigInteger C2 = x1.add(x2).multiply(key.b).multiply(new BigInteger("4"));
        BigInteger C = C1.subtract(C2);
        List<BigInteger> X = new ArrayList<>();
        BigInteger right = B.pow(2).multiply(A.pow(2).multiply(new BigInteger("4")).modInverse(key.p)).subtract(C.multiply(A.modInverse(key.p))).mod(key.p);
        TonelliShanks.Solution solution = TS.getSoultion(right, key.p);
        BigInteger b2a = B.multiply(A.multiply(new BigInteger("2")).modInverse(key.p));
       // System.out.println("r1:" + solution.root1.subtract(b2a).mod(key.p).toString());
        // System.out.println("r2:" + solution.root2.subtract(b2a).mod(key.p).toString());
        X.add(solution.root1.subtract(b2a).mod(key.p));
        X.add(solution.root2.subtract(b2a).mod(key.p));

        return X;
    }



    public boolean summationPoly3V1(BigInteger[] rs) {
        System.out.println("-----------compute f3-----------");
        BigInteger A = rs[0].subtract(rs[1]).pow(2).multiply(rs[2].pow(2));
        BigInteger tempB = rs[0].add(rs[1]).multiply((rs[0].multiply(rs[1]).add(key.a)));
        BigInteger B = tempB.add(key.b.multiply(new BigInteger("2"))).multiply(rs[2]).multiply(new BigInteger("2"));
        BigInteger C1 = rs[0].multiply(rs[1]).subtract(key.a).pow(2);
        BigInteger C2 = rs[0].add(rs[1]).multiply(key.b).multiply(new BigInteger("4"));
        BigInteger result = A.subtract(B).add(C1).subtract(C2).mod((key.p));
        //System.out.println(result.toString());
        if (result.compareTo(zero) == 0) {
            System.out.println("yes");
            return true;
        } else {
            System.out.println("false");
            return false;
        }


    }

    public BigInteger summationPoly3V2(BigInteger[] rs) {
       // System.out.println("-----------compute f3-----------");
        BigInteger A = rs[0].subtract(rs[1]).pow(2).multiply(rs[2].pow(2));
        BigInteger tempB = rs[0].add(rs[1]).multiply((rs[0].multiply(rs[1]).add(key.a)));
        BigInteger B = tempB.add(key.b.multiply(new BigInteger("2"))).multiply(rs[2]).multiply(new BigInteger("2"));
        BigInteger C1 = rs[0].multiply(rs[1]).subtract(key.a).pow(2);
        BigInteger C2 = rs[0].add(rs[1]).multiply(key.b).multiply(new BigInteger("4"));
        BigInteger result = A.subtract(B).add(C1).subtract(C2).mod((key.p));
        System.out.println(result.toString());
        return result;


    }

    public BigInteger getLeadingCoff(BigInteger[] rs){
        int count = 0;
        if (rs.length == 2){
            return BigInteger.ONE;
        }
        else if (rs.length == 3){
            BigInteger[] temprs1 = new BigInteger[rs.length-1];
            for(BigInteger i: rs){
                if(i.compareTo(zero)!=0){
                    temprs1[count] = i;
                    count++;
                }
            }
            return temprs1[0].subtract(temprs1[1]).pow(2);
        }
        else if (rs.length == 4){
            BigInteger[] temprs2 = new BigInteger[rs.length-1];
            for(BigInteger i: rs){
                if(i.compareTo(zero)!=0){
                    temprs2[count] = i;
                    count++;
                }
            }
            return summationPoly3V2(temprs2).pow(2);
        }
        else{
            BigInteger[] temprs3 = new BigInteger[rs.length-1];
            for(BigInteger i: rs){
                if(i.compareTo(zero)!=0){
                    temprs3[count] = i;
                    count++;
                }
            }
            return summationPolynomialV2(temprs3).pow(2);
        }
    }


    public boolean summationPolynomialV1(BigInteger[] rs) {
        if (rs.length == 3) {
            return summationPoly3V1(rs);
        } else if (rs.length > 3) {
            System.out.println(rs.length);
            BigInteger[] rs1 = new BigInteger[rs.length / 2 + 1];
            BigInteger[] rs2;
            if(rs.length % 2 == 1){
                rs2 = new BigInteger[rs.length / 2 + 2];
            }
            else{
                rs2 = new BigInteger[rs.length / 2 + 1];
            }
            System.arraycopy(rs, 0, rs1, 0, rs1.length - 1);
            System.arraycopy(rs, rs.length / 2, rs2, 0, rs2.length - 1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length - 1] = X;
            rs2[rs2.length - 1] = X;
            HashSet<BigInteger> resX1 = new HashSet<BigInteger>();
            HashSet<BigInteger> resX2 = new HashSet<BigInteger>();
            System.out.println("-----------rs1-------");
            for (BigInteger i : rs1) {
                System.out.println(i.toString());
            }
            System.out.println("-----------rs2-------");
            for (BigInteger i : rs2) {
                System.out.println(i.toString());
            }
            resX1 = recursionSummationPolynomialV1(rs1);
            resX2 = recursionSummationPolynomialV1(rs2);
            System.out.println("-----------resX1-------");
            for (BigInteger j : resX1) {
                System.out.println(j.toString());
            }
            System.out.println("-----------resX2-------");
            for (BigInteger j : resX2) {
                System.out.println(j.toString());
            }

            for (BigInteger index : resX1) {
                if (resX2.contains(index)) {
                    return true;
                }
            }

        }
        return false;
    }


    public BigInteger summationPolynomialV2(BigInteger[] rs) {
        BigInteger Mul = new BigInteger("1");
        BigInteger Two = new BigInteger("2");
        if (rs.length == 3) {
            return summationPoly3V2(rs);
        }
        else if (rs.length > 3) {
            System.out.println(rs.length);
            BigInteger[] rs1 = new BigInteger[rs.length / 2 + 1];
            BigInteger[] rs2;
            if (rs.length % 2 == 1) {
                rs2 = new BigInteger[rs.length / 2 + 2];
            }
            else {
                rs2 = new BigInteger[rs.length / 2 + 1];
            }
            System.arraycopy(rs, 0, rs1, 0, rs1.length - 1);
            System.arraycopy(rs, rs.length / 2, rs2, 0, rs2.length - 1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length - 1] = X;
            rs2[rs2.length - 1] = X;
            List<BigInteger> resX1 = new ArrayList<>();
            List<BigInteger> resX2 = new ArrayList<>();

          /*  System.out.println("-----------rs1-------");
            for (BigInteger i : rs1) {
                System.out.println(i.toString());
            }
            System.out.println("-----------rs2-------");
            for (BigInteger i : rs2) {
                System.out.println(i.toString());
            }
           */

            resX1 = recursionSummationPolynomialV2(rs1);
            resX2 = recursionSummationPolynomialV2(rs2);
            BigInteger a0 = getLeadingCoff(rs1);
            BigInteger b0 = getLeadingCoff(rs2);
            a0 = a0.pow((int)Math.pow(2,rs2.length-2));
            b0 = b0.pow((int)Math.pow(2,rs1.length-2));
            /*
            System.out.println("-----------resX1-------");
            for (BigInteger j : resX1) {
                System.out.println(j.toString());
            }
            System.out.println("-----------resX2-------");
            for (BigInteger j : resX2) {
                System.out.println(j.toString());
            }
            */
            for (BigInteger x : resX1) {
                for (BigInteger y : resX2) {
                    Mul = Mul.multiply(x.subtract(y));
                }
            }
            Mul = Mul.multiply(a0).multiply(b0);
            System.out.println("Res:"+Mul.toString());
        }
        return Mul;

    }


    public BigInteger getR(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException {
        BigInteger sumU = new BigInteger("0");
        ECPoint temp = new ECPoint(zero,zero);
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            if (signature [0]. compareTo(N) == 1 || signature [0]. compareTo(one) ==
                    -1
                    || signature [1]. compareTo(N) == 1
                    || signature [1]. compareTo(one) == -1) {
                System.out.println("SIGNATURE WAS NOT IN VALID RANGE");
            }
            BigInteger w = signature[1].modInverse(N);//模乘逆元
            BigInteger h = SHA1(m);
            BigInteger u = (h.multiply(w)).mod(N);
            BigInteger v = (signature [0]. multiply(w)).mod(N);
            sumU = sumU.add(u);
            //ECPoint p1 = PM.ScalarMulti(u, G);// G = P
            ECPoint Q = pks.get(i);
            ECPoint p2 = PM.ScalarMulti(v, Q);
            if(i == 0) temp = p2;
            else{
                temp = PM.AddPoint(temp, p2);
            }
        }
        ECPoint p1 = PM.ScalarMulti(sumU, G);
        ECPoint pt = PM.AddPoint(p1, temp);
        BigInteger R = pt.getAffineX().mod(N);
        return R;
    }

    public boolean sumBatchVerif(byte[] ms, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException {
        ECDSA ecdsa = new ECDSA();
        BigInteger[] rs = new BigInteger[pks.size()];
        for(int i = 0; i < rs.length; i++){
            if(i == rs.length-1){
                rs[i] = ecdsa.getR(ms, signatures, pks);
                break;
            }
            rs[i] = signatures.get(i)[0];
        }
        return ecdsa.summationPolynomialV1(rs);

    }


    public Map<BigInteger[], ECPoint> columnMatchIdentification(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException {
        ECDSA ecdsa = new ECDSA();
        String message = "test";
        byte[] ms = message.getBytes();
        Map<BigInteger[], ECPoint> validSignatuers = new HashMap<BigInteger[], ECPoint>();
        Map<BigInteger[], ECPoint> invalidSignatuers = new HashMap<BigInteger[], ECPoint>();
        int t = 0;
        if(pks.size() > 7) t = 7;
        else if(pks.size() <= 7) t = 3;
        boolean[][] matrix = new boolean[t][pks.size()];
        double probility = 0.3;
        for(int i = 0; i < t; i++){
            ArrayList<BigInteger[]> tempSignatures = new ArrayList<>();
            ArrayList<ECPoint> tempPks = new ArrayList<>();
            for(int j = 0; j < pks.size(); j++){
                if(Math.random() < probility){
                    matrix[i][j] = true;
                    tempSignatures.add(signatures.get(j));
                    tempPks.add(pks.get(j));
                }
            }
            if(ecdsa.sumBatchVerif(ms, tempSignatures, tempPks)){
                for(int k = 0; k < tempPks.size(); k++){
                    validSignatuers.put(tempSignatures.get(i), tempPks.get(i));
                }
            }
        }
        for(int i = 0; i < pks.size(); i++){
            if(!validSignatuers.containsKey(signatures.get(i))){
                invalidSignatuers.put(signatures.get(i),pks.get(i));
            }
        }
        return invalidSignatuers;
    }



    public Map<BigInteger[], ECPoint> d_CoverFreeIdentification(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException {
        ECDSA ecdsa = new ECDSA();
        String message = "test";
        byte[] ms = message.getBytes();
        Map<BigInteger[], ECPoint> validSignatuers = new HashMap<BigInteger[], ECPoint>();
        Map<BigInteger[], ECPoint> invalidSignatuers = new HashMap<BigInteger[], ECPoint>();
        //signature.size = 6
        for(int i = 0; i < one_DisjuctMatrix.length; i++){
            ArrayList<BigInteger[]> tempSignatures = new ArrayList<>();
            ArrayList<ECPoint> tempPks = new ArrayList<>();
            for(int j = 0; j < one_DisjuctMatrix[0].length; j++){
                if(one_DisjuctMatrix[i][j] == 1){
                    tempSignatures.add(signatures.get(j));
                    tempPks.add(pks.get(j));
                }
            }
            if(ecdsa.sumBatchVerif(ms, tempSignatures, tempPks)){
                for(int k = 0; k < tempPks.size(); k++){
                    validSignatuers.put(tempSignatures.get(i), tempPks.get(i));
                }
            }
        }
        for(int i = 0; i < pks.size(); i++){
            if(!validSignatuers.containsKey(signatures.get(i))){
                invalidSignatuers.put(signatures.get(i),pks.get(i));
            }
        }
        return invalidSignatuers;
    }


    public static void main(String[] arg) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECDSA ecdsa = new ECDSA();
        String message = "naive test";
        byte[] ms = message.getBytes();
 /*     BigInteger[] keyPair = key.KeyGeneration();
        BigInteger privateKey = keyPair[0];
        ECPoint publickey = new ECPoint(keyPair[1], keyPair[2]);
        BigInteger[] signature = ecdsa.Sign(ms, privateKey);
        ecdsa.verify(ms, signature , publickey);*/
        BigInteger[] rs = new BigInteger[9];
        ArrayList<BigInteger[]> signatures = new ArrayList<BigInteger[]>();
        ArrayList<ECPoint> pks = new ArrayList<ECPoint>();
        for(int i = 0 ; i < rs.length-1; i++){
            BigInteger[] keyPair = key.KeyGeneration();
            BigInteger privatekey = keyPair[0];
            ECPoint publickey = new ECPoint(keyPair[1], keyPair[2]);
            BigInteger[] signature = ecdsa.Sign(ms,privatekey);
            pks.add(publickey);
            signatures.add(signature);
            rs[i] = signature[0];
           // System.out.println(signature[0]);
        }
        Long startTime1 = System.currentTimeMillis ();
        System.out.println("startTime1:"+startTime1);
        rs[rs.length-1]= ecdsa.getR(ms,signatures,pks);
        ecdsa.summationPolynomialV2(rs);
        Long endTime1 = System.currentTimeMillis ();
        System.out.println("endTime1:"+endTime1);
        Long totalTime1 = endTime1 - startTime1;
        System.out.println("time consumption of summation :"+totalTime1);
       /* Long startTime1 = System.currentTimeMillis ();
        System.out.println("startTime1:"+startTime1);
        ecdsa.batchVerif(ms, signatures, pks);
        Long endTime1 = System.currentTimeMillis ();
        System.out.println("endTime1:"+endTime1);
        Long totalTime1 = endTime1 - startTime1;
        System.out.println("time consumption of naive batch:"+totalTime1);*/







    }





}
