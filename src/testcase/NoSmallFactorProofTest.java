package testcase;

import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.utils.Pedersen;

import bls12381.BLS12381.BIG;

import com.okx.ecdsa.utils.NoSmallFactorProof;
import com.okx.ecdsa.utils.NumericUtil;

import com.okx.ecdsa.Point;

import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.math.BigInteger;
import java.security.KeyPair;

// Prover claims that N has no small factor less than 2^l
// An attack raised from lacks of this proof: 
// https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report
// https://mp.weixin.qq.com/s/Tukkx6Tb6Fe_FVc1Bb0v5w
// solution: https://eprint.iacr.org/2020/492.pdf, chapter 4.3
public class NoSmallFactorProofTest {
        public static void main(String[] args) throws HomomorphicException{
        // set up
        NoSmallFactorProof noSmallFactorProof = new NoSmallFactorProof();
        NumericUtil numericUtil = new NumericUtil();
        int l = 256;
        int epsilon = 512;
        int security = 1024;
        
        noSmallFactorProof.init(l, epsilon, security);

        // This is a honest prover
        BigInteger p = numericUtil.prime(security);
        BigInteger q = numericUtil.prime(security);
        BigInteger N = p.multiply(q);

        noSmallFactorProof.prove(N, p, q);

        boolean ok = noSmallFactorProof.verify(N);

        System.out.println("without small factor: " + ok);

        // This is malicious prover
        p = numericUtil.prime(16);
        q = numericUtil.prime(2 * security - 16);
        N = p.multiply(q);
        noSmallFactorProof.prove(N, p, q);

        ok = noSmallFactorProof.verify(N);

        System.out.println("with small factor: " + ok);

    }

}
