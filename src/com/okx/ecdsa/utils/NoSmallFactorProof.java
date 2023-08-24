package com.okx.ecdsa.utils;
// import com.okx.ecdsa.utils.NumericUtil;
import java.math.BigInteger;
// import com.okx.ecdsa.utils.HashUtil;




public class NoSmallFactorProof {
    NumericUtil numericUtil = new NumericUtil();
    Pedersen pedersen = new Pedersen();

    public int l;
    public int epsilon;

    public BigInteger P;
    public BigInteger Q;
    public BigInteger A;
    public BigInteger B;
    public BigInteger T;
    public BigInteger rou;

    public BigInteger z1;
    public BigInteger z2;
    public BigInteger w1;
    public BigInteger w2;
    public BigInteger v;

    public void init(int l, int epsilon, int security){
        this.l = l;
        this.epsilon = epsilon;
        this.pedersen.setup(security);
    }

    public void prove(BigInteger N, BigInteger p, BigInteger q){
        BigInteger N_Sqrt = N.sqrt();

        // sample vars
        BigInteger alpha = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l+epsilon).multiply(N_Sqrt));
        BigInteger beta = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l+epsilon).multiply(N_Sqrt));

        BigInteger miu = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l).multiply(pedersen.n));
        BigInteger niu = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l).multiply(pedersen.n));

        this.rou = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l).multiply(N).multiply(pedersen.n));
        BigInteger r = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l+epsilon).multiply(N).multiply(pedersen.n));

        BigInteger x = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l+epsilon).multiply(pedersen.n));
        BigInteger y = numericUtil.getRandomWithinRange(BigInteger.TWO.pow(l+epsilon).multiply(pedersen.n));
        
        // calculate P, Q, A, B, T
        this.P = pedersen.commit(p, miu);
        this.Q = pedersen.commit(q, niu);

        this.A = pedersen.commit(alpha, x);
        this.B = pedersen.commit(beta, y);

        this.T = Q.modPow(alpha, pedersen.n).multiply(pedersen.s.modPow(r,pedersen.n)).mod(pedersen.n);
        
        // TODO: to be replaced by FS scheme
        // BigInteger e = numericUtil.getRandomNumber(255);
        String oracle = N.toString(16) + this.P.toString(16) + this.Q.toString(16) + this.A.toString(16) + this.B.toString(16) + this.T.toString(16);
        BigInteger e =new BigInteger(HashUtil.getSHA( oracle, "SHA-256"), 16);
        BigInteger rou_tidle = this.rou.subtract(niu.multiply(p));

        this.z1 = alpha.add(e.multiply(p));
        this.z2 = beta.add(e.multiply(q));
        this.w1 = x.add(e.multiply(miu));
        this.w2 = y.add(e.multiply(niu));
        this.v = r.add(e.multiply(rou_tidle));
        
        return;
    }

    public boolean verify(BigInteger N){
        BigInteger N_Sqrt = N.sqrt();
        String oracle = N.toString(16) + this.P.toString(16) + this.Q.toString(16) + this.A.toString(16) + this.B.toString(16) + this.T.toString(16);
        BigInteger e =new BigInteger(HashUtil.getSHA( oracle, "SHA-256"), 16);

        BigInteger R = pedersen.commit(N, this.rou);
        // check commit(z1, w1) = A * P^e
        BigInteger left0 = pedersen.commit(this.z1, this.w1);
        BigInteger right0 = this.A.multiply(this.P.modPow(e, pedersen.n)).mod(pedersen.n);
        if (left0.compareTo(right0) != 0) {
            System.out.println("check commit(z1, w1) = A * P^e failed");
            return false;
        }

        // check commit(z2, w2) = B * Q^e
        BigInteger left1 = pedersen.commit(this.z2, this.w2);
        BigInteger right1 = this.B.multiply(this.Q.modPow(e, pedersen.n)).mod(pedersen.n);
        if (left1.compareTo(right1) != 0) {
            System.out.println("check commit(z2, w2) = B * Q^e failed");
            return false;
        }

        // check Q^z1 * s^v = T * R^e
        BigInteger left2 = this.Q.modPow(this.z1, pedersen.n).multiply(pedersen.s.modPow(this.v, pedersen.n)).mod(pedersen.n);
        BigInteger right2 = this.T.multiply(R.modPow(e, pedersen.n)).mod(pedersen.n);
        if (left2.compareTo(right2) != 0) {
            System.out.println("check Q^z1 * s^v = T * R^e failed");
            return false;
        }

        // check z1, z2 <= rangeLimit
        BigInteger rangeLimit = BigInteger.TWO.pow(l+epsilon).multiply(N_Sqrt);
        
        if (this.z1.compareTo(rangeLimit) == 1 || this.z2.compareTo(rangeLimit) == 1) {
            System.out.println("check z1, z2 <= rangeLimit failed");
            return false;
        }
        return true;

    }
}
