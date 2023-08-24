package testcase;

import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.utils.Pedersen;

import bls12381.BLS12381.BIG;

import com.okx.ecdsa.utils.PaillierBlumProof;
import com.okx.ecdsa.utils.NumericUtil;

import com.okx.ecdsa.Point;

import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.math.BigInteger;
import java.security.KeyPair;

// Prover claims that N is a Paillier Blum modulus, i.e. gcd(N, phi(N)) = 1, N = p * q, and p, q % 4 = 3
// An attack raised from lacks of this proof: 
// https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report
// https://mp.weixin.qq.com/s/Tukkx6Tb6Fe_FVc1Bb0v5w
// solution: https://eprint.iacr.org/2020/492.pdf, chapter 4.3
public class PaillierBlumProofTest {
        public static void main(String[] args) throws HomomorphicException{

            validProofTest();

            invalidProofTest();
       

    }

    private static void validProofTest() {
        // set up
        PaillierBlumProof pailBlumProof = new PaillierBlumProof();
        NumericUtil numericUtil = new NumericUtil();
        int security = 256;
        BigInteger p = numericUtil.safePrime(security);
        BigInteger q = numericUtil.safePrime(security);
        BigInteger N = p.multiply(q);
        System.out.println("p % 4 : "+p.mod(BigInteger.valueOf(4))); 
        System.out.println("q % 4 : "+q.mod(BigInteger.valueOf(4))); 

        // This is a honest prover
        pailBlumProof.prove(N, p, q, security);
        boolean ok = pailBlumProof.verify(N);
        System.out.println("honest proof verification: "+ok);
    }

    private static void invalidProofTest() {
        // set up
        PaillierBlumProof pailBlumProof = new PaillierBlumProof();
        NumericUtil numericUtil = new NumericUtil();
        int security = 256;

        // This is a malicious prover
        BigInteger p = numericUtil.prime(security);
        BigInteger q = numericUtil.prime(security);
        BigInteger N = p.multiply(q);


        System.out.println("p % 4 : "+p.mod(BigInteger.valueOf(4))); 
        System.out.println("q % 4 : "+q.mod(BigInteger.valueOf(4))); 
        pailBlumProof.prove(N, p, q, security);
        boolean ok = pailBlumProof.verify(N);
        System.out.println("malicious proof verification: "+ok);
    }
}
