package testcase;


import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.ED25519core;
import com.okx.ecdsa.utils.Pedersen;
import com.okx.ecdsa.Curve25519core;
import com.okx.ecdsa.Point;
import com.okx.ecdsa.utils.Base58;
import com.okx.ecdsa.utils.HEX;
import com.okx.ecdsa.utils.HashUtil;

import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.math.BigInteger;
import java.security.KeyPair;


public class Lindell17Attack {
         public static void main(String[] args) throws HomomorphicException{
        // k = k1 * k2, x = x1 + x2
        // System.out.println("==========================  k2=2, x1 lsb is odd  ===============================");
        // lindell_test0();

        // lindell_test1();

        // https://eprint.iacr.org/2020/492.pdf, 4.2
        System.out.println("==========================  invalid zk proof aff-g  ===============================");
        lindell_test_zk_invalid();
        
        System.out.println("==========================  valid zk proof aff-g  ===============================");
        lindell_test_zk_valid();



    }

    private static void lindell_test0() throws HomomorphicException{
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        BigInteger TWO = new BigInteger("2",16);
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        BigInteger key1 = new BigInteger("334", 16);
        BigInteger key2 = new BigInteger("555", 16);
        BigInteger k1 = new BigInteger("8", 16); 
        BigInteger k2 = new BigInteger("2", 16); 
        
        // 2. A和B各自计算的 P1，P2 和 R1，R2
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.add(P2, P1);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiplyWithPoint(k2, R1);
        BigInteger r = R.getX().mod(n);


        // 3. P1 将其私钥 key1 进行同态加密，得到 c1，将 c1 给 P2
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		KeyPair paillier = pa.generateKeyPair();		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) paillier.getPrivate();

        BigInteger N = pk.getN();
        System.out.println("N:"+N);
        // System.out.println("print paillier keys");
        // System.out.println(pk);
        // System.out.println(sk);

        BigInteger ckey = PaillierCipher.encrypt(key1, pk);
        // System.out.println("ckey"+ckey);
		// BigInteger key1_ = PaillierCipher.decrypt(ckey, sk);
        // System.out.println("key1_" + key1_);


        // 4. P2 使用 ckey 计算 s'=(z+r⋅ckey⋅key2)/k2
        BigInteger h = new BigInteger(message,16);

        //c1 =encrypt(ro*n + k2^(-1)*m), ro是P2生成的一个随机数，用于混淆
        BigInteger ro = new BigInteger("7",16);
        BigInteger c1 = PaillierCipher.encrypt((ro.multiply(n)).add(k2.modInverse(n).multiply(h).mod(n)), pk);

        // BigInteger _r = r;
        // if (r.mod(TWO)==BigInteger.ZERO){
        //     _r = r.add(n);
        //     System.out.println("r 为偶数");
        // } else {
        //     System.out.println("r 为奇数");
        // }
        // System.out.println("_r:"+_r);

        // v1 = k2^(-1)*r*key2
        BigInteger v1 = k2.modInverse(n).multiply(r).multiply(key2).mod(n);
        BigInteger c2 = PaillierCipher.encrypt(v1, pk);

        // v2 = k2^(-1)*r
        BigInteger v2 = k2.modInverse(n).multiply(r).mod(n);

        // c3 = 标量乘（ckey，v2)
        BigInteger c3 = PaillierCipher.multiply(ckey, v2, pk); 

        // c3 = 同态加 （c1, c2）
        BigInteger c4 = PaillierCipher.add(c1, c2, pk);
        c4 = PaillierCipher.add(c3, c4, pk);



        // 5. P1 同态解密c3得到s_, s= k1^(−1)*s_
        BigInteger s_ = PaillierCipher.decrypt(c4, sk);
        String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        System.out.println("r:"+r);
        System.out.println("s:"+s);

        // 6. 验证签名 
        acore.verify(message, r.toString(16), s, P);

    }

    private static void lindell_test1() throws HomomorphicException{
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        BigInteger TWO = new BigInteger("2",16);
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        BigInteger key1 = new BigInteger("336", 16);
        BigInteger key2 = new BigInteger("555", 16);
        BigInteger k1 = new BigInteger("8", 16); 
        BigInteger k2 = new BigInteger("2", 16); 
        
        // 2. A和B各自计算的 P1，P2 和 R1，R2
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.add(P2, P1);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiplyWithPoint(k2, R1);
        BigInteger r = R.getX().mod(n);


        // 3. P1 将其私钥 key1 进行同态加密，得到 c1，将 c1 给 P2
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		KeyPair paillier = pa.generateKeyPair();		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) paillier.getPrivate();

        BigInteger N = pk.getN();
        System.out.println("N:"+N);

        // (N-n)/2
        BigInteger delta = N.subtract(n).divide(TWO);
        System.out.println("delta:"+delta);
        // System.out.println("print paillier keys");
        // System.out.println(pk);
        // System.out.println(sk);

        BigInteger ckey = PaillierCipher.encrypt(key1, pk);
        // System.out.println("ckey"+ckey);
		// BigInteger key1_ = PaillierCipher.decrypt(ckey, sk);
        // System.out.println("key1_" + key1_);


        // 4. P2 使用 ckey 计算 s'=(z+r⋅ckey⋅key2)/k2
        BigInteger h = new BigInteger(message,16);

        //c1 =encrypt(ro*n + k2^(-1)*m), ro是P2生成的一个随机数，用于混淆
        BigInteger ro = new BigInteger("7",16);
        BigInteger c1 = PaillierCipher.encrypt((ro.multiply(n)).add(k2.modInverse(n).multiply(h).mod(n)), pk);

        BigInteger _r = r;
        if (r.mod(TWO)==BigInteger.ZERO){
            _r = r.add(n);
            System.out.println("r 为偶数");
        } else {
            System.out.println("r 为奇数");
        }
        System.out.println("_r:"+_r);

        // v1 = k2^(-1)*r*key2
        BigInteger v1 = k2.modInverse(n).multiply(r).multiply(key2).mod(n);
        BigInteger c2 = PaillierCipher.encrypt(v1, pk);

        // v2 = k2^(-1)*_r
        BigInteger v2 = k2.modInverse(N).multiply(_r).mod(N);

        // c3 = 标量乘（ckey，v2)
        BigInteger c3 = PaillierCipher.multiply(ckey, v2, pk); 

        // c3 = 同态加 （c1, c2）
        BigInteger c4 = PaillierCipher.add(c1, c2, pk);
        c4 = PaillierCipher.add(c3, c4, pk);



        // 5. P1 同态解密c3得到s_, s= k1^(−1)*s_
        BigInteger s_ = PaillierCipher.decrypt(c4, sk);

        // String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        System.out.println("r:"+r);
        System.out.println("s:"+s);

        // 6. 验证签名 
        acore.verify(message, r.toString(16), s, P);

    }


    private static void lindell_test_zk_invalid() throws HomomorphicException{
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        
        Pedersen pedersen = new Pedersen();
        pedersen.setup(1024);

        // ============================ 1. key generation ===============================
        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        // BigInteger key1 = new BigInteger("3333338", 16);
        // BigInteger key2 = new BigInteger("5533335", 16);
        // BigInteger k1 = new BigInteger("18", 16); 
        // BigInteger k2 = new BigInteger("999", 16); 
        BigInteger key1 = pedersen.getRandomNumber(256);
        BigInteger key2 = pedersen.getRandomNumber(256);
        BigInteger k1 = pedersen.getRandomNumber(256);
        BigInteger k2 = pedersen.getRandomNumber(256);
        
        // 2. A和B各自计算的 P1，P2 和 R1，R2
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.add(P2, P1);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiplyWithPoint(k2, R1);
        BigInteger r = R.getX().mod(n);


        // 3. P1 将其私钥 key1 进行同态加密，得到 c1，将 c1 给 P2
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		KeyPair paillier = pa.generateKeyPair();		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) paillier.getPrivate();

        BigInteger N = pk.getN();
        BigInteger NN = N.multiply(N);


        BigInteger ckey = PaillierCipher.encrypt(key1, pk);

        // ============================ 2. sign ===============================
        // 4. P2 使用 ckey 计算 s'=(z+r⋅ckey⋅key2)/k2
        BigInteger m = new BigInteger(message,16);

        // y = ro*n + k2^(-1)*(m + r*x2), ro是P2生成的一个随机数，用于混淆
        BigInteger ro = pedersen.getRandomNumber(256);
        BigInteger y = ro.multiply(n).add(k2.modInverse(n).multiply(m.add(r.multiply(key2))).mod(n));

        // c1 = (1 + N)^y * rou^N mod N^2 = enc(y, pk)
        BigInteger rou = pedersen.getRandomNumber(256);
        BigInteger c1 = (BigInteger.ONE.add(N)).modPow(y, NN).multiply(rou.modPow(N, NN)).mod(NN);

        // make sure _r is odd
        BigInteger _r = r;
        if (r.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0){
            _r = r.add(n);
        } else {
        }

        // d = 2 * k2^(-1) mod n, if d is even, d = d + n
        // k2_inv = (2^(-1) mod N)* d
        // x = k2_inv * _r
        BigInteger d = BigInteger.TWO.multiply(k2.modInverse(n));
        if (d.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0){
            d = d.add(n);
        }  
        BigInteger x =  BigInteger.TWO.modInverse(N).multiply(d).multiply(_r).mod(N);

        // x = k2^(-1)*_r
        // BigInteger x = k2.modInverse(N).multiply(_r).mod(N);
        Point X = acore.fastMultiply(x);

        // c3 = 标量乘（ckey，x)
        BigInteger c2 = PaillierCipher.multiply(ckey, x, pk); 

        // c3 = 同态加 （c1, c2）
        BigInteger c = PaillierCipher.add(c1, c2, pk);

        // 5. P1 同态解密c3得到s_, s= k1^(−1)*s_
        BigInteger s_ = PaillierCipher.decrypt(c, sk);

        // String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);


        // ============================ 3. signature verification ===============================
        // 6. 验证签名 
        acore.verify(message, r.toString(16), s, P);

        // ============================ 4. generate zk proof ===============================
        int l = 768;
        int epsilon = 256;
        int l1 = 512;

        // Prover commit
        BigInteger alpha = pedersen.getRandomNumber(l + epsilon);
        BigInteger beta = pedersen.getRandomNumber(l1 + epsilon);

        BigInteger rp = pedersen.getRandomNumber(2048);
        BigInteger gama = pedersen.getRandomNumber(2048);
        BigInteger mp = pedersen.getRandomNumber(2048);
        BigInteger delta = pedersen.getRandomNumber(2048);
        BigInteger u = pedersen.getRandomNumber(2048);

        // A = ckey^alpha * (1 + N)^beta * rp^N mod N^2
        BigInteger A = ckey.modPow(alpha, NN).multiply((BigInteger.ONE.add(N)).modPow(beta, NN).multiply(rp.modPow(N, NN))).mod(NN);

        // Bx = alpha * G
        Point Bx = acore.fastMultiply(alpha);

        // E = s^alpha * t^gama
        BigInteger E = pedersen.commit(alpha, gama);

        // S = s^x * t^mp
        BigInteger S = pedersen.commit(x, mp);

        // F = s^beta * t^delta
        BigInteger F = pedersen.commit(beta, delta);

        // T = s^y * t^u
        BigInteger T = pedersen.commit(y, u);


        // Verifier challenge
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
        Point left1 = acore.fastMultiply(z1);
        Point right1 = acore.add(Bx, acore.fastMultiplyWithPoint(e, X));
        System.out.println("check Bx:"+left1.equals(right1));

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
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        
        Pedersen pedersen = new Pedersen();
        pedersen.setup(1024);

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        BigInteger key1 = new BigInteger("3333338", 16);
        BigInteger key2 = new BigInteger("5533335", 16);
        BigInteger k1 = new BigInteger("18", 16); 
        BigInteger k2 = new BigInteger("2", 16); 
        
        // 2. A和B各自计算的 P1，P2 和 R1，R2
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.add(P2, P1);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiplyWithPoint(k2, R1);
        BigInteger r = R.getX().mod(n);


        // 3. P1 将其私钥 key1 进行同态加密，得到 c1，将 c1 给 P2
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		KeyPair paillier = pa.generateKeyPair();		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) paillier.getPrivate();

        BigInteger N = pk.getN();
        BigInteger NN = N.multiply(N);


        BigInteger ckey = PaillierCipher.encrypt(key1, pk);

        // 4. P2 使用 ckey 计算 s'=(z+r⋅ckey⋅key2)/k2
        BigInteger m = new BigInteger(message,16);

        // y = ro*n + k2^(-1)*(m + r*x2), ro是P2生成的一个随机数，用于混淆
        BigInteger ro = new BigInteger("7",16);
        BigInteger y = ro.multiply(n).add(k2.modInverse(n).multiply(m.add(r.multiply(key2))).mod(n));

        // c1 = (1 + N)^y * rou^N mod N^2 = enc(y, pk)
        BigInteger rou = new BigInteger("17",16);
        BigInteger c1 = (BigInteger.ONE.add(N)).modPow(y, NN).multiply(rou.modPow(N, NN)).mod(NN);

        // x = k2^(-1)*_r
        BigInteger x = k2.modInverse(n).multiply(r).mod(n);
        Point X = acore.fastMultiply(x);

        // c3 = 标量乘（ckey，x)
        BigInteger c2 = PaillierCipher.multiply(ckey, x, pk); 

        // c3 = 同态加 （c1, c2）
        BigInteger c = PaillierCipher.add(c1, c2, pk);

        // 5. P1 同态解密c3得到s_, s= k1^(−1)*s_
        BigInteger s_ = PaillierCipher.decrypt(c, sk);

        // String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);

        // 6. 验证签名 
        acore.verify(message, r.toString(16), s, P);


        int l = 768;
        int epsilon = 256;
        int l1 = 512;

        // Prover commit
        BigInteger alpha = pedersen.getRandomNumber(l + epsilon);
        BigInteger beta = pedersen.getRandomNumber(l1 + epsilon);

        BigInteger rp = pedersen.getRandomNumber(2048);
        BigInteger gama = pedersen.getRandomNumber(2048);
        BigInteger mp = pedersen.getRandomNumber(2048);
        BigInteger delta = pedersen.getRandomNumber(2048);
        BigInteger u = pedersen.getRandomNumber(2048);

        // A = ckey^alpha * (1 + N)^beta * rp^N mod N^2
        BigInteger A = ckey.modPow(alpha, NN).multiply((BigInteger.ONE.add(N)).modPow(beta, NN).multiply(rp.modPow(N, NN))).mod(NN);

        // Bx = alpha * G
        Point Bx = acore.fastMultiply(alpha);

        // E = s^alpha * t^gama
        BigInteger E = pedersen.commit(alpha, gama);

        // S = s^x * t^mp
        BigInteger S = pedersen.commit(x, mp);

        // F = s^beta * t^delta
        BigInteger F = pedersen.commit(beta, delta);

        // T = s^y * t^u
        BigInteger T = pedersen.commit(y, u);


        // Verifier challenge
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

        // Verifier verify
        // A * c^e = ckey^z1 * (1 + N)^z2 * w^N mod N^2
        BigInteger left = A.multiply(c.modPow(e, NN)).mod(NN);
        BigInteger right = ckey.modPow(z1, NN).multiply((BigInteger.ONE.add(N)).modPow(z2, NN).multiply(w.modPow(N, NN))).mod(NN);
        System.out.println("check A:"+left.equals(right));

        //z1 * G = Bx + e * X
        Point left1 = acore.fastMultiply(z1);
        Point right1 = acore.add(Bx, acore.fastMultiplyWithPoint(e, X));
        System.out.println("check Bx:"+left1.equals(right1));

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
