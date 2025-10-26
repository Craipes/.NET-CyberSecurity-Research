namespace CyberSecurity.Controllers;

public class RsaController : Controller
{
    private const string PrivateKeySessionKey = "RsaPrivateKey";
    private const string PublicKeySessionKey = "RsaPublicKey";

    public IActionResult Index()
    {
        using var rsa = new RSACryptoServiceProvider(2048);

        HttpContext.Session.SetString(PrivateKeySessionKey, rsa.ToXmlString(true));
        var publicKey = rsa.ToXmlString(false);
        HttpContext.Session.SetString(PublicKeySessionKey, publicKey);

        var model = new RsaViewModel { PublicKey = publicKey };
        return View(model);
    }

    [HttpPost]
    public IActionResult Encrypt(RsaViewModel model)
    {
        var publicKey = HttpContext.Session.GetString(PublicKeySessionKey);
        if (publicKey == null) return Index();
        model.PublicKey = publicKey;

        if (!string.IsNullOrEmpty(model.OriginalText))
        {
            using var aes = Aes.Create();
            // Encrypt the text with AES
            var dataToEncrypt = Encoding.UTF8.GetBytes(model.OriginalText);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
            cryptoStream.FlushFinalBlock();
            var encryptedData = memoryStream.ToArray();

            // Encrypt the AES key and IV with RSA
            using var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            var aesKeyAndIv = aes.Key.Concat(aes.IV).ToArray();
            var encryptedKeyAndIv = rsa.Encrypt(aesKeyAndIv, false);

            // Combine and Base64 encode
            var finalEncryptedData = encryptedKeyAndIv.Concat(encryptedData).ToArray();
            model.EncryptedText = Convert.ToBase64String(finalEncryptedData);
        }

        ModelState.Clear();
        return View("Index", model);
    }

    [HttpPost]
    public IActionResult Decrypt(RsaViewModel model)
    {
        var privateKey = HttpContext.Session.GetString(PrivateKeySessionKey);
        var publicKey = HttpContext.Session.GetString(PublicKeySessionKey);
        if (privateKey == null || publicKey == null) return Index();
        model.PublicKey = publicKey;

        if (!string.IsNullOrEmpty(model.EncryptedTextToDecrypt))
        {
            try
            {
                var fullEncryptedData = Convert.FromBase64String(model.EncryptedTextToDecrypt);

                using var rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(privateKey);

                // Extract and decrypt the AES key and IV
                var rsaKeySizeInBytes = rsa.KeySize / 8;
                var encryptedKeyAndIv = fullEncryptedData.Take(rsaKeySizeInBytes).ToArray();
                var encryptedData = fullEncryptedData.Skip(rsaKeySizeInBytes).ToArray();

                var decryptedKeyAndIv = rsa.Decrypt(encryptedKeyAndIv, false);
                var aesKey = decryptedKeyAndIv.Take(32).ToArray(); // AES-256 key
                var aesIv = decryptedKeyAndIv.Skip(32).ToArray();

                // Decrypt the data with AES
                using var aes = Aes.Create();
                aes.Key = aesKey;
                aes.IV = aesIv;

                using var memoryStream = new MemoryStream();
                using var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
                cryptoStream.Write(encryptedData, 0, encryptedData.Length);
                cryptoStream.FlushFinalBlock();
                var decryptedData = memoryStream.ToArray();
                model.DecryptedText = Encoding.UTF8.GetString(decryptedData);
            }
            catch (Exception)
            {
                model.DecryptedText = "Error: Invalid encrypted text or key.";
            }
        }

        ModelState.Clear();
        return View("Index", model);
    }

    [HttpPost]
    public IActionResult HashText(RsaViewModel model)
    {
        var publicKey = HttpContext.Session.GetString(PublicKeySessionKey);
        model.PublicKey = publicKey;

        if (!string.IsNullOrEmpty(model.TextToHash))
        {
            var inputBytes = Encoding.UTF8.GetBytes(model.TextToHash);
            var hashBytes = MD5.HashData(inputBytes);
            model.HashedText = Convert.ToHexString(hashBytes);
        }

        ModelState.Clear();
        return View("Index", model);
    }

    [HttpPost]
    public IActionResult Sign(RsaViewModel model)
    {
        var privateKey = HttpContext.Session.GetString(PrivateKeySessionKey);
        var publicKey = HttpContext.Session.GetString(PublicKeySessionKey);
        if (privateKey == null || publicKey == null) return Index();
        model.PublicKey = publicKey;

        if (!string.IsNullOrEmpty(model.TextToSign))
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);

            var dataToSign = Encoding.UTF8.GetBytes(model.TextToSign);
            var signature = rsa.SignData(dataToSign, MD5.Create());
            model.DigitalSignature = Convert.ToBase64String(signature);
        }

        ModelState.Clear();
        return View("Index", model);
    }

    [HttpPost]
    public IActionResult Verify(RsaViewModel model)
    {
        var publicKey = HttpContext.Session.GetString(PublicKeySessionKey);
        if (publicKey == null) return Index();
        model.PublicKey = publicKey;

        if (!string.IsNullOrEmpty(model.TextToVerify) && !string.IsNullOrEmpty(model.SignatureToVerify))
        {
            try
            {
                using var rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(publicKey);

                var dataToVerify = Encoding.UTF8.GetBytes(model.TextToVerify);
                var signature = Convert.FromBase64String(model.SignatureToVerify);
                var isVerified = rsa.VerifyData(dataToVerify, MD5.Create(), signature);

                model.VerificationResult = isVerified ? "Signature is valid." : "Signature is NOT valid.";
            }
            catch (Exception)
            {
                model.VerificationResult = "Error: Invalid data or signature format.";
            }
        }

        ModelState.Clear();
        return View("Index", model);
    }
}
