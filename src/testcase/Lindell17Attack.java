package testcase;

import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.utils.Pedersen;
import com.okx.ecdsa.Point;

import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.math.BigInteger;
import java.security.KeyPair;

// This attack was disclosed by fireblocks on Augest 2023: 
// https://www.fireblocks.com/blog/lindell17-abort-vulnerability-technical-report
// https://eprint.iacr.org/2023/1234.pdf
// This fix solution is based on https://eprint.iacr.org/2020/492.pdf, chapter 4.2
public class Lindell17Attack {
         public static void main(String[] args) throws HomomorphicException{
        // k = k1 * k2, x = x1 + x2
        System.out.println("==========================  invalid zk proof aff-g  ===============================");
        lindell_test_zk_invalid();
        
        System.out.println("==========================  valid zk proof aff-g  ===============================");
        lindell_test_zk_valid();

    }

    private static void lindell_test_zk_invalid() throws HomomorphicException{
        // order of secp256k1 curve
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        
        Pedersen pedersen = new Pedersen();
        pedersen.setup(1024);

        // ============================ 1. key generation ===============================
        BigInteger key1 = pedersen.getRandomNumber(256);
        BigInteger key2 = pedersen.getRandomNumber(256);

        System.out.println("key1:"+key1.toString(2));


        BigInteger k1 = pedersen.getRandomNumber(256);
        BigInteger k2 = pedersen.getRandomNumber(256);
        
        // 2. Calculate P1，P2 and R1，R2, P = P1 + P2, R = k1 * k2 * G
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.add(P2, P1);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiplyWithPoint(k2, R1);
        BigInteger r = R.getX().mod(n);

        // 3. P1 send ckey = enc(key1) to P2
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		KeyPair paillier = pa.generateKeyPair();		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) paillier.getPrivate();

        BigInteger N = pk.getN();
        BigInteger NN = N.multiply(N);

        BigInteger ckey = PaillierCipher.encrypt(key1, pk);

        // ============================ 2. sign ===============================
        BigInteger m = new BigInteger(message,16);

        // y = ro * n + k2^(-1) * (m + r * x2) mod n
        BigInteger ro = pedersen.getRandomNumber(256);
        BigInteger y = ro.multiply(n).add(k2.modInverse(n).multiply(m.add(r.multiply(key2))).mod(n));

        // c1 = (1 + N)^y * rou^N mod N^2 = enc(y, pk)
        BigInteger rou = pedersen.getRandomNumber(256);
        BigInteger c1 = (BigInteger.ONE.add(N)).modPow(y, NN).multiply(rou.modPow(N, NN)).mod(NN);

        // make sure _r is odd
        BigInteger _r = r;
        if (r.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {_r = r.add(n);}

        // d = 2 * k2^(-1) mod n, if d is even, d = d + n
        // k2_inv = (2^(-1) mod N) * d
        // x = k2_inv * _r
        BigInteger d = BigInteger.TWO.multiply(k2.modInverse(n));
        if (d.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0){
            d = d.add(n);
        }  
        BigInteger x =  BigInteger.TWO.modInverse(N).multiply(d).multiply(_r).mod(N);
        System.out.println("x.length:"+x.toString(2).length());

        // x = k2^(-1) * _r
        // BigInteger x = k2.modInverse(N).multiply(_r).mod(N);
        Point X = acore.fastMultiply(x);

        // c3 = mul(ckey，x)
        BigInteger c2 = PaillierCipher.multiply(ckey, x, pk); 

        // c3 = add(c1, c2）
        BigInteger c = PaillierCipher.add(c1, c2, pk);

        // 5. s= k1^(−1)*s_
        BigInteger s_ = PaillierCipher.decrypt(c, sk);

        // String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);

        // ============================ 3. signature verification ===============================
        // 6. signature verification 
        boolean ok = acore.verifyWithResult(message, r.toString(16), s, P);

        // ============================ 4. next round attack ===============================
        k1 = pedersen.getRandomNumber(256);
        k2 = pedersen.getRandomNumber(256);

        R1 = acore.fastMultiply(k1);
        R2 = acore.fastMultiply(k2);
        R = acore.fastMultiplyWithPoint(k2, R1);
        r = R.getX().mod(n);

        message = "4243ab5ca30bb34fe154a0bd49fc4b9b40359d88771ebbbdefd2356a805af66b";
        m = new BigInteger(message,16);

        ro = pedersen.getRandomNumber(256);
        y = ro.multiply(n).add(k2.modInverse(n).multiply(m.add(r.multiply(key2))).mod(n));

        // yita0 = yb * r * (k2^(-1) mod n)
        // yita1 = yb * r * (k2^(-1) mod n)*4
        // yita1 = yita1 + n  if yita1 is even
        // yita1 = yita1 *(4^(-1) mod N)) mod N

        // yita = yita0 - yita1
        BigInteger yb = ok? BigInteger.ZERO : BigInteger.ONE;
        System.out.println("yb:"+yb);
        BigInteger yita0 = yb.multiply(r).multiply(k2.modInverse(n));
        BigInteger yita1 = yb.multiply(r).multiply(k2.modInverse(n)).multiply(BigInteger.valueOf(4));
        if (yb.compareTo(BigInteger.ZERO) == 1 && yita1.mod(BigInteger.valueOf(4)).compareTo(BigInteger.ZERO) == 0){
            yita1 = yita1.add(n);
        }
        // if (ok && yita1.mod(BigInteger.valueOf(4)).compareTo(BigInteger.ZERO) == 0){
        //     yita1 = yita1.add(n);
        // }
        yita1 = yita1.multiply(BigInteger.valueOf(4).modInverse(N)).mod(N);
        BigInteger yita = yita0.subtract(yita1).mod(n);
        // System.out.println("yita.lenth:"+yita.bitLength());

        // c1 = (1 + N)^y * rou^N mod N^2 = enc(y, pk)
        rou = pedersen.getRandomNumber(256);
        c1 = (BigInteger.ONE.add(N)).modPow(y.add(yita), NN).multiply(rou.modPow(N, NN)).mod(NN);

        // make sure _r is odd
        _r = r;
        if (r.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {_r = r.add(n);}

        // d = 4 * k2^(-1) mod n, if d is even, d = d + n
        // k2_inv = (2^(-1) mod N) * d
        // x = k2_inv * _r
        d = BigInteger.valueOf(4).multiply(k2.modInverse(n)).multiply(_r);
        if (d.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0){
            d = d.add(n);
        }  
        x =  BigInteger.valueOf(4).modInverse(N).multiply(d).mod(N);
        System.out.println("x.length:"+x.toString(2).length());

        // x = k2^(-1) * _r
        // BigInteger x = k2.modInverse(N).multiply(_r).mod(N);
        X = acore.fastMultiply(x);

        // c2 = mul(ckey，x)
        c2 = PaillierCipher.multiply(ckey, x, pk); 

        // c3 = add(c1, c2）
        c = PaillierCipher.add(c1, c2, pk);

        // 5. s= k1^(−1)*s_
        s_ = PaillierCipher.decrypt(c, sk);

        // String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        s = k1.modInverse(n).multiply(s_).mod(n).toString(16);

        // 6. signature verification 
        ok = acore.verifyWithResult(message, r.toString(16), s, P);





        

        // ============================ 4. generate zk proof ===============================
        // x = k2^(-1) * _r, maximum length of x is 2 * 256 = 512 bits
        // y = ro * n + k2^(-1) * (m + r * x2) mod n, maximum length of y is 3 * 256 = 768 bits
        int l = 2 * 256;
        int l1 = 3 * 256;
        int epsilon = 3 * 256;

        // Prover commit
        BigInteger alpha = pedersen.getRandomNumber(l + epsilon);
        BigInteger beta = pedersen.getRandomNumber(l1 + epsilon);

        BigInteger rp = pedersen.getRandomNumber(N.toString(2).length());
        BigInteger gama = pedersen.getRandomNumber(l + epsilon + pedersen.n.toString(2).length());
        BigInteger mp = pedersen.getRandomNumber(l + pedersen.n.toString(2).length());
        BigInteger delta = pedersen.getRandomNumber(l + epsilon + pedersen.n.toString(2).length());
        BigInteger u = pedersen.getRandomNumber(l + pedersen.n.toString(2).length());

        // A = ckey^alpha * (1 + N)^beta * rp^N mod N^2
        BigInteger A = ckey.modPow(alpha, NN).multiply((BigInteger.ONE.add(N)).modPow(beta, NN).multiply(rp.modPow(N, NN))).mod(NN);

        // Bx = alpha * G
        // Point Bx = acore.fastMultiply(alpha);

        // E = s^alpha * t^gama
        BigInteger E = pedersen.commit(alpha, gama);

        // S = s^x * t^mp
        BigInteger S = pedersen.commit(x, mp);

        // F = s^beta * t^delta
        BigInteger F = pedersen.commit(beta, delta);

        // T = s^y * t^u
        BigInteger T = pedersen.commit(y, u);

        // Verifier challenge，could be transfered to NIZK by FS-transform
        BigInteger e = pedersen.getRandomNumber(255);

        // Prover reply challenge
        // z1 = alpha + e * x
        // z2 = beta + e * y
        // z3 = gama + e * mp
        // z4 = delta + e * u
        // w = rp * rou^e mod N
        BigInteger z1 = alpha.add(e.multiply(x));
        BigInteger z2 = beta.add(e.multiply(y));
        BigInteger z3 = gama.add(e.multiply(mp));
        BigInteger z4 = delta.add(e.multiply(u));
        BigInteger w = rp.multiply(rou.modPow(e, N)).mod(N);

        // ============================ 3. validate zk proof ===============================
        // Verifier verify
        // A * c^e = ckey^z1 * (1 + N)^z2 * w^N mod N^2
        BigInteger left = A.multiply(c.modPow(e, NN)).mod(NN);
        BigInteger right = ckey.modPow(z1, NN).multiply((BigInteger.ONE.add(N)).modPow(z2, NN).multiply(w.modPow(N, NN))).mod(NN);
        System.out.println("check A:"+left.equals(right));

        //z1 * G = Bx + e * X
        // Point left1 = acore.fastMultiply(z1);
        // Point right1 = acore.add(Bx, acore.fastMultiplyWithPoint(e, X));
        // System.out.println("check Bx:"+left1.equals(right1));

        // s^z1 * t^z3 = E * S^e
        BigInteger left2 = pedersen.commit(z1, z3);
        BigInteger right2 = E.multiply(S.modPow(e, pedersen.n)).mod(pedersen.n);
        System.out.println("check E:"+left2.equals(right2));

        // s^z2 * t^z4 = F * T^e
        BigInteger left3 = pedersen.commit(z2, z4);
        BigInteger right3 = F.multiply(T.modPow(e, pedersen.n)).mod(pedersen.n);
        System.out.println("check F:"+left3.equals(right3));

        int z1length = z1.toString(2).length();
        int z2length = z2.toString(2).length();
        System.out.println("z1length:"+z1length);
        System.out.println("z2length:"+z2length);
        System.out.println("valid zk proof :" + (z1length <= l + epsilon && z2length <= l1 + epsilon));

    }

    private static void lindell_test_zk_valid() throws HomomorphicException{
        // order of secp256k1 curve
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        
        Pedersen pedersen = new Pedersen();
        pedersen.setup(1024);

        // ============================ 1. key generation ===============================
        BigInteger key1 = pedersen.getRandomNumber(256);
        BigInteger key2 = pedersen.getRandomNumber(256);
        BigInteger k1 = pedersen.getRandomNumber(256);
        BigInteger k2 = pedersen.getRandomNumber(256);
        
        // 2. Calculate P1，P2 and R1，R2, P = P1 + P2, R = k1 * k2 * G
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.add(P2, P1);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiplyWithPoint(k2, R1);
        BigInteger r = R.getX().mod(n);

        // 3. P1 send ckey = enc(key1) to P2
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		KeyPair paillier = pa.generateKeyPair();		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) paillier.getPrivate();

        BigInteger N = pk.getN();
        BigInteger NN = N.multiply(N);

        BigInteger ckey = PaillierCipher.encrypt(key1, pk);

        // ============================ 2. sign ===============================
        BigInteger m = new BigInteger(message,16);

        // y = ro * n + k2^(-1) * (m + r * x2) mod n
        BigInteger ro = pedersen.getRandomNumber(256);
        BigInteger y = ro.multiply(n).add(k2.modInverse(n).multiply(m.add(r.multiply(key2))).mod(n));

        // c1 = (1 + N)^y * rou^N mod N^2 = enc(y, pk)
        BigInteger rou = pedersen.getRandomNumber(256);
        BigInteger c1 = (BigInteger.ONE.add(N)).modPow(y, NN).multiply(rou.modPow(N, NN)).mod(NN);

        // x = k2^(-1) * r
        BigInteger x = k2.modInverse(n).multiply(r).mod(n);
        Point X = acore.fastMultiply(x);

        // c3 = mul(ckey，x)
        BigInteger c2 = PaillierCipher.multiply(ckey, x, pk); 

        // c3 = add(c1, c2）
        BigInteger c = PaillierCipher.add(c1, c2, pk);

        // 5. s= k1^(−1)*s_
        BigInteger s_ = PaillierCipher.decrypt(c, sk);

        // String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);

        // ============================ 3. signature verification ===============================
        // 6. signature verification 
        acore.verify(message, r.toString(16), s, P);

        // ============================ 4. generate zk proof ===============================
        // x = k2^(-1) * _r, maximum length of x is 2 * 256 = 512 bits
        // y = ro * n + k2^(-1) * (m + r * x2) mod n, maximum length of y is 3 * 256 = 768 bits
        int l = 2 * 256;
        int l1 = 3 * 256;
        int epsilon = 3 * 256;

        // Prover commit
        BigInteger alpha = pedersen.getRandomNumber(l + epsilon);
        BigInteger beta = pedersen.getRandomNumber(l1 + epsilon);

        BigInteger rp = pedersen.getRandomNumber(N.toString(2).length());
        BigInteger gama = pedersen.getRandomNumber(l + epsilon + pedersen.n.toString(2).length());
        BigInteger mp = pedersen.getRandomNumber(l + pedersen.n.toString(2).length());
        BigInteger delta = pedersen.getRandomNumber(l + epsilon + pedersen.n.toString(2).length());
        BigInteger u = pedersen.getRandomNumber(l + pedersen.n.toString(2).length());

        // A = ckey^alpha * (1 + N)^beta * rp^N mod N^2
        BigInteger A = ckey.modPow(alpha, NN).multiply((BigInteger.ONE.add(N)).modPow(beta, NN).multiply(rp.modPow(N, NN))).mod(NN);

        // Bx = alpha * G
        // Point Bx = acore.fastMultiply(alpha);

        // E = s^alpha * t^gama
        BigInteger E = pedersen.commit(alpha, gama);

        // S = s^x * t^mp
        BigInteger S = pedersen.commit(x, mp);

        // F = s^beta * t^delta
        BigInteger F = pedersen.commit(beta, delta);

        // T = s^y * t^u
        BigInteger T = pedersen.commit(y, u);

        // Verifier challenge，could be transfered to NIZK by FS-transform
        BigInteger e = pedersen.getRandomNumber(255);

        // Prover reply challenge
        // z1 = alpha + e * x
        // z2 = beta + e * y
        // z3 = gama + e * mp
        // z4 = delta + e * u
        // w = rp * rou^e mod N
        BigInteger z1 = alpha.add(e.multiply(x));
        BigInteger z2 = beta.add(e.multiply(y));
        BigInteger z3 = gama.add(e.multiply(mp));
        BigInteger z4 = delta.add(e.multiply(u));
        BigInteger w = rp.multiply(rou.modPow(e, N)).mod(N);

        // ============================ 3. validate zk proof ===============================
        // Verifier verify
        // A * c^e = ckey^z1 * (1 + N)^z2 * w^N mod N^2
        BigInteger left = A.multiply(c.modPow(e, NN)).mod(NN);
        BigInteger right = ckey.modPow(z1, NN).multiply((BigInteger.ONE.add(N)).modPow(z2, NN).multiply(w.modPow(N, NN))).mod(NN);
        System.out.println("check A:"+left.equals(right));

        //z1 * G = Bx + e * X
        // Point left1 = acore.fastMultiply(z1);
        // Point right1 = acore.add(Bx, acore.fastMultiplyWithPoint(e, X));
        // System.out.println("check Bx:"+left1.equals(right1));

        // s^z1 * t^z3 = E * S^e
        BigInteger left2 = pedersen.commit(z1, z3);
        BigInteger right2 = E.multiply(S.modPow(e, pedersen.n)).mod(pedersen.n);
        System.out.println("check E:"+left2.equals(right2));

        // s^z2 * t^z4 = F * T^e
        BigInteger left3 = pedersen.commit(z2, z4);
        BigInteger right3 = F.multiply(T.modPow(e, pedersen.n)).mod(pedersen.n);
        System.out.println("check F:"+left3.equals(right3));

        int z1length = z1.toString(2).length();
        int z2length = z2.toString(2).length();
        System.out.println("z1length:"+z1length);
        System.out.println("z2length:"+z2length);
        System.out.println("valid zk proof :" + (z1length <= l + epsilon && z2length <= l1 + epsilon));

    }

}
