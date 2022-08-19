package testcase;

import com.vhklabs.ecdsa.ECDSAcore;
import com.vhklabs.ecdsa.Point;
import com.vhklabs.ecdsa.utils.PrivateKeyUtil;
import security.misc.HomomorphicException;
import java.math.BigInteger;

public class ECDSAPlayground {
         public static void main(String[] args) throws HomomorphicException{
            ECDSAcore acore = new ECDSAcore();
            // 1. 随机生成你的私钥
            
            String privatekey = "8";
            System.out.println("=============== 1. 随机生成私钥 =================");
            System.out.println(privatekey);

            
            // 2. 计算私钥对应的公钥
            Point publickey = acore.fastMultiply(new BigInteger(privatekey, 16));
            System.out.println("=============== 2. 使用椭圆曲线乘法计算公钥 =================");
            System.out.println(publickey);
        
            // 3. 将公钥转成比特币主网和以太坊地址
            // btc : 1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb
            // eth : 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69
            System.out.println("=============== 3. 公钥对应的比特币和以太坊地址 =================");
            System.out.println("比特币主网地址：" + PrivateKeyUtil.getBtcMainNetAddressWithPublickey(publickey));
            System.out.println("以太坊地址：" + PrivateKeyUtil.getEthereumAddressWithPublicKey(publickey));
            
            // 4. 交易hash
            String transaction = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
            
            // 5. 私钥签名
            String[] signatures = acore.sign(transaction, privatekey);
            System.out.println("=============== 4. 签名 =================");
            System.out.println("r:" + signatures[0]);
            System.out.println("s:" + signatures[1]);


            // 6. 公钥验签
            System.out.println("=============== 5. 验证签名 =================");
            acore.verify(transaction,signatures[0],signatures[1],publickey);



    }





}
