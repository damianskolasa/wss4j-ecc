package org.apache.ws.security.message;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import sun.security.ec.ECParameters;

public class GenerateECDSAKEyPair {
	
	public void gent() throws Exception {
		Date startDate =  Calendar.getInstance().getTime();
		Calendar calTo = Calendar.getInstance();
		calTo.add(Calendar.YEAR, 2);
		Date expiryDate = calTo.getTime();             // time after which certificate is not valid
		BigInteger serialNumber = new BigInteger("2");     // serial number for certificate
		KeyPair keyPair = generateECDSAKeyPair();             // EC public/private key pair
		
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal              dnName = new X500Principal("CN=Test CA Certificate");

		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA1withECDSA");

		X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
		Set<String> ff = cert.getCriticalExtensionOIDs();
		
		String pkAlg = keyPair.getPrivate().getAlgorithm();
		String certPubAlg = cert.getPublicKey().getAlgorithm();
		
		KeyStore.PrivateKeyEntry pke = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), (Certificate[]) Arrays.asList(cert).toArray());
		KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
		ks.load(null);
		
		ks.setCertificateEntry("ECDSACert", cert);
		ks.setEntry("ECDSAKey", pke, new KeyStore.PasswordProtection("123456".toCharArray()));
		FileOutputStream fos = new FileOutputStream("/home/damian/wssECC40.jks");
		ks.store(fos, "123456".toCharArray());
		fos.flush();
		fos.close();
		
		KeyStore kk = KeyStore.getInstance("PKCS12", "BC");
		kk.load(new FileInputStream("/home/damian/wssECC40.jks"), "123456".toCharArray());
		System.out.println(kk.getKey("ecdsakey", "123456".toCharArray()));
		
		
		
		
	}

	public KeyPair generateECDSAKeyPair() throws Exception {
		/*ECCurve curve = new ECCurve.Fp(
				new BigInteger(
						"883423532389192164791648750360308885314476597252960362792450860609699839"), // q
				new BigInteger(
						"7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
						16), // a
				new BigInteger(
						"6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
						16)); // b

		ECParameterSpec ecSpec = new ECParameterSpec(
				curve,
				curve.decodePoint(Hex
						.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
				new BigInteger(
						"883423532389192164791648750360308884807550341691627752275345424702807307")); // n

		KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

		g.initialize(ecSpec, new SecureRandom());

		KeyPair pair = g.generateKeyPair();
		
		System.out.println(pair.getPrivate().getClass());*/
		
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
		DERObjectIdentifier curveOid = ECUtil.getNamedCurveOid("prime192v1");
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

		g.initialize(ecSpec, new SecureRandom());

		
		KeyPair pair = g.generateKeyPair();
		
		BCECPrivateKey bcecpk = (BCECPrivateKey) pair.getPrivate();
		
		return pair;
	
	}
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		new GenerateECDSAKEyPair().gent();
		//new GenerateECDSAKEyPair().generateECDSAKeyPair();
	}

}
