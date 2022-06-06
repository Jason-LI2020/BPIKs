package testcase;


import com.vhklabs.ecdsa.ECDSAcore;
import com.vhklabs.ecdsa.Point;
import com.vhklabs.ecdsa.utils.Base58;
import com.vhklabs.ecdsa.utils.HEX;
import com.vhklabs.ecdsa.utils.HashUtil;

import java.math.BigInteger;


public class MPCtest {
    public static void main(String[] args) {

        System.out.println("==========================  ECDSA: Classical  ====================================");
        // https://okg-block.larksuite.com/docs/docuso6z74HwtSnPJzBCA5iU6Dl
        // 公共的k计算涉及到同态加密算法和零知识证明
        ecdsaClassical();

        System.out.println("==========================  ECDSA: Schnorr single sign  ============================");
        // https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        // 对 ECDSA 签名进行优化，便于批量验证签名，适用于聚合签名扩展
        schnorrSingle();

        System.out.println("==========================  ECDSA: Schnorr 2/2 sign  ===============================");
        // https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        // 存在的问题：
        // 1. 对于3个或以上的多签场景，通信会比较复杂
        // 2. 存在流氓密钥攻击问题：如果在计算联合公钥时Alice提供的不是P1而是P1-P2，会导致最终的联合公钥地址就是(P1-P2)+P2 = P1,从而完全由Alice控制
        // 3. 不能使用确定性k，需要一个好的随机数生成器来生成k

        // 对于2/2签名则只需要1轮通信：
        // 1.前端将用户生成的随机点R3传给后端（P3不需要生成，但也需要传给后端）
        // 2.后端生成用户的 R4，P4，计算公共哈希 z34和后端的签名 s4，并将R4，P4，z34和s4传给前端
        // 3.前端可以验证z34，并计算用户端的签名s3，然后合并签名 s34，并计算R34，然后将（R34，s34）合并为联合地址的签名
        schnorr22();
 
        System.out.println("==========================  ECDSA: Mulsig 2/2 sign  ===============================");
        // https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        // https://bitcointechtalk.com/scaling-bitcoin-schnorr-signatures-abe3b5c275d1
        // 解决Schnor签名中 流氓密钥攻击 的问题
        mulsig22();


     



    }

    private static void ecdsaClassical() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        String p1 = "888";
        String[] rs1 = acore.sign(message, p1);
        acore.verify(message, rs1[0], rs1[1], acore.fastMultiply(new BigInteger(p1,16)));

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        String key1 = "333";
        String key2 = "555";
        BigInteger k1 = new BigInteger("3", 16); 
        BigInteger k2 = new BigInteger("5", 16); 
        
        // 2. 根据两个private key计算出联合地址
        Point point1 = acore.fastMultiply(new BigInteger(key1, 16));
        Point point2 = acore.fastMultiply(new BigInteger(key2, 16));
        Point point3 = acore.add(point1, point2);

        // 3. 计算 r = (k1*G + k2*G)的x坐标
        String r = acore.add(acore.fastMultiply(k1), acore.fastMultiply(k2)).getX().toString(16);

        // // 4. 双方分别计算s
        // BigInteger s1 = (BigInteger(message, 16) + BigInteger(key1,16)*BigInteger(r,16))/k1;
        // BigInteger s2 = (BigInteger(message, 16) + BigInteger(key2,16)*BigInteger(r,16))/k2;
        // // 5. 计算联合签名 s = s1 + s2 - (h/k),需要计算公共的k

        // 4. 计算联合签名 s = （h + (d1+d2)*r） / (k1+k2)
        BigInteger h = new BigInteger(message,16);
        // BigInteger keys = new BigInteger(key1,16).add(new BigInteger(key2,16));
        BigInteger keys = new BigInteger(p1,16);
        
        String s = (h.add(keys.multiply(new BigInteger(r,16)))).divide(k1.add(k2)).toString(16);

        // 5. 验证签名 
        acore.verify(message, r, s, point3);
    }

    private static void schnorrSingle() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. 指定 私钥p0 和 随机数 k0
        String p0 = "888";
        BigInteger k0 = new BigInteger("3", 16); 

        // 2. 计算 点R = k×G
        Point r0 = acore.fastMultiply(k0);

        // 3. 计算 s = k + hash(P,R,m) ⋅ pk
        BigInteger Px0 = acore.fastMultiply(new BigInteger(p0, 16)).getX();
        BigInteger d = Px0.add(r0.getX()).add(new BigInteger(message, 16));
        String z = HashUtil.getSHA( d.toString(16) , "SHA-256");
        BigInteger s0 = k0.add((new BigInteger(z, 16)).multiply(new BigInteger(p0, 16)));

        // 4. verify s×G = R + hash(P,R,m)×P
        Point _sG = acore.fastMultiply(s0);
        Point sG_ = acore.add(r0, acore.fastMultiplyWithPoint(new BigInteger(z,16), acore.fastMultiply(new BigInteger(p0, 16))));
        System.out.println(_sG);
        System.out.println(sG_);
    }

    private static void schnorr22() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

       // 1. 给A和B指定key1，key2 和 随机数k1, k2
       String key1 = "333";
       String key2 = "555";
       BigInteger k1 = new BigInteger("3", 16); 
       BigInteger k2 = new BigInteger("5", 16); 

       // 2. 计算 联合公钥P 和 联合随机点R
       Point P = acore.add(acore.fastMultiply(new BigInteger(key1, 16)), acore.fastMultiply(new BigInteger(key2, 16)));
       Point R = acore.add(acore.fastMultiply(k1), acore.fastMultiply(k2));

       // 3. 计算公共哈希 z = hash(P,R,m)
       String z = HashUtil.getSHA( P.getX().add(R.getX()).add(new BigInteger(message, 16)).toString(16) , "SHA-256");

       // 4. A和B分别计算签名si = ki + hash(P,R,m) ⋅ pki, 两个签名相加得到联合签名 s
       BigInteger s1 = k1.add((new BigInteger(z, 16)).multiply(new BigInteger(key1, 16)));
       BigInteger s2 = k2.add((new BigInteger(z, 16)).multiply(new BigInteger(key2, 16)));
       BigInteger s = s1.add(s2);

       // 5. 使用 （P， s）进行验签 s×G = R + hash(P,R,m)×P
       Point _sG = acore.fastMultiply(s);
       Point sG_ = acore.add(R, acore.fastMultiplyWithPoint(new BigInteger(z,16), P));
       System.out.println(_sG);
       System.out.println(sG_);
    }



    private static void mulsig22() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
    
        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        String key1 = "333";
        String key2 = "555";
        BigInteger k1 = new BigInteger("3", 16); 
        BigInteger k2 = new BigInteger("5", 16); 

        // 2. 计算 公钥Pi 和 随机点Ri
        Point P1 = acore.fastMultiply(new BigInteger(key1, 16));
        Point P2 = acore.fastMultiply(new BigInteger(key2, 16));

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.add(R1, R2);

        // 3. 计算与所有公钥地址关联的hash L = hash(P1,..Pn)
        String L = HashUtil.getSHA(P1.getX().add(P2.getX()).toString(16), "SHA-256");

        // 4. 计算聚合公钥 P=hash(L,P1)×P1+…+hash(L,Pn)×Pn
        Point _P1 = acore.fastMultiplyWithPoint(new BigInteger(HashUtil.getSHA(new BigInteger(L,16).add(P1.getX()).toString(16), "SHA-256"), 16), P1);
        Point _P2 = acore.fastMultiplyWithPoint(new BigInteger(HashUtil.getSHA(new BigInteger(L,16).add(P2.getX()).toString(16), "SHA-256"), 16), P2);
        Point P = acore.add(_P1, _P2);

        // 5. 计算公共哈希 z = H(P, R, m)
        String z = HashUtil.getSHA(P.getX().add(R.getX()).add(new BigInteger(message, 16)).toString(16) , "SHA-256");

        // 6. 计算各自的 签名 si = ki + hash(P,R,m) ⋅ hash(L,Pi) ⋅ pki, 联合签名 s = s1 + s2
        String z1_ = HashUtil.getSHA(new BigInteger(L,16).add(P1.getX()).toString(16),"SHA-256");
        String z2_ = HashUtil.getSHA(new BigInteger(L,16).add(P2.getX()).toString(16),"SHA-256");
        BigInteger s1 = k1.add(new BigInteger(z,16).multiply(new BigInteger(z1_, 16)).multiply(new BigInteger(key1, 16)));
        BigInteger s2 = k2.add(new BigInteger(z,16).multiply(new BigInteger(z2_, 16)).multiply(new BigInteger(key2, 16)));
        BigInteger s = s1.add(s2);

        // 7. 验签 s*G = R + H(P, R, m) * P
        Point _sG = acore.fastMultiply(s);
        Point sG_ = acore.add(R, acore.fastMultiplyWithPoint(new BigInteger(z,16), P));
        System.out.println(_sG);
        System.out.println(sG_);

    }




}
