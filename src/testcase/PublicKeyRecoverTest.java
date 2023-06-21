package testcase;


import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.ED25519core;
import com.okx.ecdsa.Curve25519core;
import com.okx.ecdsa.Point;
import com.okx.ecdsa.utils.Base58;
import com.okx.ecdsa.utils.HEX;
import com.okx.ecdsa.utils.HashUtil;
import com.okx.ecdsa.utils.PrivateKeyUtil;

import java.math.BigInteger;
import java.security.KeyPair;


public class PublicKeyRecoverTest {
    static BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
    static BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
    static ECDSAcore acore = new ECDSAcore();
    static PrivateKeyUtil util = new PrivateKeyUtil();

    static int chainId = 1;



    public static void main(String[] args) {
    
        System.out.println("==========================  ECDSA: Public Key Recover  ====================================");
        // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
        // https://crypto.stackexchange.com/questions/60218/recovery-public-key-from-secp256k1-signature-and-message
        // https://learnblockchain.cn/index.php/article/1038
        // https://github.com/Tschaul/recover-pub-key/blob/fda94f0f04adfea982babeb5973be59aadf1327b/node_modules/ecdsa/lib/ecdsa.js
        // https://www.cnblogs.com/HachikoT/p/15991277.html#恢复recover

        publicKeyRecovery();

        // publicKeyRecoveryWithCompactEncodedSignature();

    }


    // =================================================================

    public static void publicKeyRecovery() {
        String message = "54c5fcd6fb03500520cd85796b8ce7febe2732c21e67ffbeb10e7f38f3307dd";
        String privateKey = "23a77118133287637ebdcd9e87a1613e443df789558867f5ba91faf7a024205";
        Point PublicKey = acore.fastMultiply(new BigInteger(privateKey,16));
        System.out.println("PublicKey: " + PublicKey);

        Point Key1 = acore.recoverR(PublicKey.getX().toString(16), 28, 1);
        Point Key2 = acore.recoverR(PublicKey.getX().toString(16), 27, 1);
        System.out.println("Key1: " + Key1);
        System.out.println("Key2: " + Key2);

        // PublicKey: 
        // x:60de32cdaf78bdab488d87f7720d5f3898f16d1461203621731f80fa85c35ff 
        // y:1e4e2b0b4520de0428ed588e54150f11d424f41c2482bb968c37dbab5e68a29
        // Key1: x:60de32cdaf78bdab488d87f7720d5f3898f16d1461203621731f80fa85c35ff 
        // y:61b1d4f4badf230bd712a771abeaf0ee2bdb0be3db7d446973c82454a1975d8
        // Key2: x:60de32cdaf78bdab488d87f7720d5f3898f16d1461203621731f80fa85c35ff 
        // y:61b1d4f4badf230bd712a771abeaf0ee2bdb0be3db7d446973c82454a1975d8


        // // 1. 生成以太坊签名 r,s,v
        // BigInteger random_k = new BigInteger("171963177ac61f96094e2506a1a11d5329f992a18a1d62174560a03a78767313",16);
        // Point R0 = acore.fastMultiply(random_k);
        // BigInteger r0 = R0.getX();
        // BigInteger r = r0.mod(n);
        // BigInteger s = random_k.modInverse(n).multiply(new BigInteger(message,16).add(r.multiply(new BigInteger(privateKey,16)))).mod(n);
        // int v = acore.calculateV(R0, chainId);

        // acore.verify(message, r.toString(16), s.toString(16), PublicKey);

        // System.out.println("R0: " + R0);
        // System.out.println("r: " + r.toString(16));
        // System.out.println("s: " + s.toString(16));
        // System.out.println("v: " + v);

        // // 2. 根据 message, r, s, v 恢复public key
        // Point Q = acore.recoverPubkey(message, r, s, v, chainId);
        // String RecoveredAccount = util.getEthereumAddressWithPublicKey(Q);

        // System.out.println("根据 message, r, s, v 恢复账户地址: ");
        // System.out.println("Recovered Public Key Point: " + Q);
        // System.out.println("Recovered Account: " + RecoveredAccount);

        // // 3. 在只有 message, r, s 的情况下，恢复出两个可能的公钥
        // Point Q1 = acore.recoverPubkey(message, r, s, 27, chainId);
        // Point Q2 = acore.recoverPubkey(message, r, s, 28, chainId);
        // String PotentialAccount1 = util.getEthereumAddressWithPublicKey(Q1);
        // String PotentialAccount2 = util.getEthereumAddressWithPublicKey(Q2);

        // System.out.println("根据 message, r, s  恢复两个可能的账户地址: ");
        // System.out.println("PotentialAccount1: " + PotentialAccount1);
        // System.out.println("PotentialAccount2: " + PotentialAccount2);

    }

    
    public static void publicKeyRecoveryWithCompactEncodedSignature() {

        String message = "397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f";
        String r = "173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882";
        String s = "4b6d75385aed025aa222f28a0adc6d58db78ff17e51c3f59e259b131cd5a1cc";
        
        Point P1 = acore.recoverPubkey(message, r, s, 27, 1);
        Point P2 = acore.recoverPubkey(message, r, s, 28, 1);
        // Point P = acore.recoverPubkeyCompactEncoded(message, r, vs, 1);
        // String RecoveredAccount = util.getEthereumAddressWithPublicKey(P);
        // System.out.println("Recovered Account with compact encoded signature: " + RecoveredAccount);
        System.out.println("P1: " + P1);
        System.out.println("P2: " + P2);

        // acore.verify(message,r.toString(16),vs.toString(16),P1);
        // acore.verify(message,r.toString(16),vs.toString(16),P2);

        // String RecoveredAccount1 = util.getEthereumAddressWithPublicKey(P1);
        // String RecoveredAccount2 = util.getEthereumAddressWithPublicKey(P2);
        // System.out.println("Recovered Account with compact encoded signature: " + RecoveredAccount1);
        // System.out.println("Recovered Account with compact encoded signature: " + RecoveredAccount2);






    }
    





}
