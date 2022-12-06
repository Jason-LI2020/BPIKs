package testcase;


import com.vhklabs.ecdsa.ECDSAcore;
import com.vhklabs.ecdsa.ED25519core;
import com.vhklabs.ecdsa.Curve25519core;
import com.vhklabs.ecdsa.Point;
import com.vhklabs.ecdsa.utils.Base58;
import com.vhklabs.ecdsa.utils.HEX;
import com.vhklabs.ecdsa.utils.HashUtil;
import com.vhklabs.ecdsa.utils.PrivateKeyUtil;

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

        // publicKeyRecovery();

        publicKeyRecoveryWithCompactEncodedSignature();

    }


    // =================================================================

    // public static void publicKeyRecovery() {
    //     String message = "df623c51d5cdf16f35695e55f1a4f20a31dcb45107fe5d368e612c02ce1af041";
    //     String privateKey = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    //     Point PublicKey = acore.fastMultiply(new BigInteger(privateKey,16));
    //     String Account = util.getEthereumAddressWithPublicKey(PublicKey);
    //     System.out.println("真实的账户地址: ");
    //     System.out.println("Account: " + Account);


    //     // 1. 生成以太坊签名 r,s,v
    //     BigInteger random_k = new BigInteger("171963177ac61f96094e2506a1a11d5329f992a18a1d62174560a03a78767313",16);
    //     Point R0 = acore.fastMultiply(random_k);
    //     BigInteger r0 = R0.getX();
    //     BigInteger r = r0.mod(n);
    //     BigInteger s = random_k.modInverse(n).multiply(new BigInteger(message,16).add(r.multiply(new BigInteger(privateKey,16)))).mod(n);
    //     int v = acore.calculateV(R0, chainId);

    //     acore.verify(message, r.toString(16), s.toString(16), PublicKey);

    //     System.out.println("R0: " + R0);
    //     System.out.println("r: " + r.toString(16));
    //     System.out.println("s: " + s.toString(16));
    //     System.out.println("v: " + v);

    //     // 2. 根据 message, r, s, v 恢复public key
    //     Point Q = acore.recoverPubkey(message, r, s, v, chainId);
    //     String RecoveredAccount = util.getEthereumAddressWithPublicKey(Q);

    //     System.out.println("根据 message, r, s, v 恢复账户地址: ");
    //     System.out.println("Recovered Public Key Point: " + Q);
    //     System.out.println("Recovered Account: " + RecoveredAccount);

    //     // 3. 在只有 message, r, s 的情况下，恢复出两个可能的公钥
    //     Point Q1 = acore.recoverPubkey(message, r, s, 27, chainId);
    //     Point Q2 = acore.recoverPubkey(message, r, s, 28, chainId);
    //     String PotentialAccount1 = util.getEthereumAddressWithPublicKey(Q1);
    //     String PotentialAccount2 = util.getEthereumAddressWithPublicKey(Q2);

    //     System.out.println("根据 message, r, s  恢复两个可能的账户地址: ");
    //     System.out.println("PotentialAccount1: " + PotentialAccount1);
    //     System.out.println("PotentialAccount2: " + PotentialAccount2);

    // }

    
    public static void publicKeyRecoveryWithCompactEncodedSignature() {

        // String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        // BigInteger r = new BigInteger("ea8472b182012574406ac5f1f5551b64aaa99f71571e5cb87bba7b76b4b17446", 16);
        // BigInteger vs = new BigInteger("6d13122d3717f23aadc4c0899c39264450fbaa7fbb766c6cb75c2194aa08e210",16);
        // 359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40

        // 435eb303aa0e6c328ddcd10e85202f48e54538f9687d26ae9927035bb07fb2df
        // 3bce0ed067da9eef12cdb80896fd55491d95f0e51e1b8e727a84e0b7b6c8b259

        // 33b552271de38ff209f2b38fa5fea499a3d5c007ae40f52a1b6c115cffecc00c
        // 63f90c7dfd0dc83a726de04bd6dcc7e221a4cd89bdef32dcecdae538dfbdd4cc

        // 02f7625fc66ef4611f8efcaeacfc196c9293f0ac13bd1eaf16de1ceb1e36273d
        // 0fe8637e630673918d18354aef70a09c688c91d862421941c4163e07518d6190
        String message = "a94c564c4e60767331329ce43096827eb345c02ca3e5ec7a1b417318ec733554";
        String r = "33b552271de38ff209f2b38fa5fea499a3d5c007ae40f52a1b6c115cffecc00c";
        String vs = "63f90c7dfd0dc83a726de04bd6dcc7e221a4cd89bdef32dcecdae538dfbdd4cc";
        
        // Point P1 = acore.recoverPubkey(message, r, vs, 27, 1);
        // Point P2 = acore.recoverPubkey(message, r, vs, 28, 1);
        Point P = acore.recoverPubkeyCompactEncoded(message, r, vs, 1);
        String RecoveredAccount = util.getEthereumAddressWithPublicKey(P);
        System.out.println("Recovered Account with compact encoded signature: " + RecoveredAccount);
        // System.out.println("P1: " + P1);
        // System.out.println("P2: " + P2);

        // acore.verify(message,r.toString(16),vs.toString(16),P1);
        // acore.verify(message,r.toString(16),vs.toString(16),P2);

        // String RecoveredAccount1 = util.getEthereumAddressWithPublicKey(P1);
        // String RecoveredAccount2 = util.getEthereumAddressWithPublicKey(P2);
        // System.out.println("Recovered Account with compact encoded signature: " + RecoveredAccount1);
        // System.out.println("Recovered Account with compact encoded signature: " + RecoveredAccount2);






    }
    





}
