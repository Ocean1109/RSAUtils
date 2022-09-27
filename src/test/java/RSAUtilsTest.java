import com.ocean.utils.IOUtils;
import com.ocean.utils.RSAUtils;
import org.junit.Assert;
import org.junit.Test;
import sun.misc.BASE64Encoder;

import java.io.File;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * @author huhaiyang
 * @date 2022/9/27
 */
public class RSAUtilsTest {
    @Test
    public void testGen() throws Exception {
        KeyPair keyPair = RSAUtils.generateKeyPair();
        RSAUtils.saveKeyWithBase64(keyPair.getPublic(), new File("src/main/java/com/ocean/utils/pub.txt"));
        RSAUtils.saveKeyWithBase64(keyPair.getPrivate(), new File("src/main/java/com/ocean/utils/pri.txt"));
    }

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        String s = "hello world!";
        PublicKey publicKey = RSAUtils.getPublicKey(IOUtils.readFromFile(new File("src/main/java/com/ocean/utils/pub.txt")));
        byte[] cipher = RSAUtils.encrypt(s.getBytes(), publicKey);
        System.out.println("cipherData:" + new String(new BASE64Encoder().encode(cipher)));
        PrivateKey privateKey = RSAUtils.getPrivateKey(IOUtils.readFromFile(new File("src/main/java/com/ocean/utils/pri.txt")));
        byte[] originalData = RSAUtils.decrypt(cipher, privateKey);
        System.out.println("originalData:" + new String(originalData));
        Assert.assertEquals("解密后内容一致", s, new String(originalData));
    }
}
