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

    public static void publicKeyRecovery() {
        String message = "df623c51d5cdf16f35695e55f1a4f20a31dcb45107fe5d368e612c02ce1af041";
        String privateKey = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
        Point PublicKey = acore.fastMultiply(new BigInteger(privateKey,16));
        String Account = util.getEthereumAddressWithPublicKey(PublicKey);
        System.out.println("真实的账户地址: ");
        System.out.println("Account: " + Account);


        // 1. 生成以太坊签名 r,s,v
        BigInteger random_k = new BigInteger("171963177ac61f96094e2506a1a11d5329f992a18a1d62174560a03a78767313",16);
        Point R0 = acore.fastMultiply(random_k);
        BigInteger r0 = R0.getX();
        BigInteger r = r0.mod(n);
        BigInteger s = random_k.modInverse(n).multiply(new BigInteger(message,16).add(r.multiply(new BigInteger(privateKey,16)))).mod(n);
        int v = acore.calculateV(R0, chainId);

        acore.verify(message, r.toString(16), s.toString(16), PublicKey);

        System.out.println("R0: " + R0);
        System.out.println("r: " + r.toString(16));
        System.out.println("s: " + s.toString(16));
        System.out.println("v: " + v);

        // 2. 根据 message, r, s, v 恢复public key
        Point Q = acore.recoverPubkey(message, r, s, v, chainId);
        String RecoveredAccount = util.getEthereumAddressWithPublicKey(Q);

        System.out.println("根据 message, r, s, v 恢复账户地址: ");
        System.out.println("Recovered Public Key Point: " + Q);
        System.out.println("Recovered Account: " + RecoveredAccount);

        // 3. 在只有 message, r, s 的情况下，恢复出两个可能的公钥
        Point Q1 = acore.recoverPubkey(message, r, s, 27, chainId);
        Point Q2 = acore.recoverPubkey(message, r, s, 28, chainId);
        String PotentialAccount1 = util.getEthereumAddressWithPublicKey(Q1);
        String PotentialAccount2 = util.getEthereumAddressWithPublicKey(Q2);

        System.out.println("根据 message, r, s  恢复两个可能的账户地址: ");
        System.out.println("PotentialAccount1: " + PotentialAccount1);
        System.out.println("PotentialAccount2: " + PotentialAccount2);

    }

    
    public static void publicKeyRecoveryWithCompactEncodedSignature() {
        // Account #2: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC (10000 ETH) 
        // 3bc7f517f4d9e9ecbee388020fb70bf48019d3d2f3694dc6d9b8d7e9aab789c9
        // faa10fec7595d019229947303da2653ddf3c3a9c405999c62c4f386117377cb6
        // 37d6713a7cbf4d75c1a0a6c7a0ada4d1552c46a29d16452083ac94b790361134

        // 597db9b3ad9fa08220abc5962ac568b00685b4474695d7ac721444e7d0c808f9
        // 58198e8519bc8bd7332f6fd5e32f1c127b36bc55fedf6b1d26e85ff802348c9c

        
        // a946ce745f444649b490b2ef9398c382013851ee2c1356ffb0f8861b6b260d2b
        // ae70d51db1d9df72b5931ad880d0cda940cc171d94b2fed337c61b8da6f7f713

        String message = "e149932e5b2717cef1f837e83790bc58911c9d4ee7f02d66bfa0f8727f495305";
        BigInteger r = new BigInteger("a946ce745f444649b490b2ef9398c382013851ee2c1356ffb0f8861b6b260d2b", 16);
        BigInteger vs = new BigInteger("ae70d51db1d9df72b5931ad880d0cda940cc171d94b2fed337c61b8da6f7f713",16);

        Point P = acore.recoverPubkeyCompactEncoded(message, r, vs, 1);
        String RecoveredAccount = util.getEthereumAddressWithPublicKey(P);
        System.out.println("Recovered Account with compact encoded signature: " + RecoveredAccount);



    }
    





}
