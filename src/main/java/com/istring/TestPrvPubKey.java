package com.istring;

import static com.istring.utils.EncryptUtil.generateRSAKeyPairs;

/**
 * 创建公钥私钥
 * @author d
 * @create 2019-11-28 2:35 PM
 **/
public class TestPrvPubKey {
    public static void main(String[] args) throws Exception {
        generateRSAKeyPairs();
    }
}
