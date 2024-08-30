#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

void SaveKey(const RSA::PrivateKey& privateKey, const std::string& filename) {
    Base64Encoder privkeysink(new FileSink(filename.c_str()));
    privateKey.DEREncode(privkeysink);
    privkeysink.MessageEnd();
}

void SaveKey(const RSA::PublicKey& publicKey, const std::string& filename) {
    Base64Encoder pubkeysink(new FileSink(filename.c_str()));
    publicKey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();
}

void GenerateAndSaveRSAKeyPair(int keySize, const std::string& privFilename, const std::string& pubFilename) {
    AutoSeededRandomPool rng;

    // تولید کلید خصوصی
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keySize);

    // استخراج کلید عمومی
    RSA::PublicKey publicKey(privateKey);

    // ذخیره کلید خصوصی و عمومی در فایل‌ها
    SaveKey(privateKey, privFilename);
    SaveKey(publicKey, pubFilename);

    std::cout << "RSA key pair (" << keySize << " bits) generated and saved to files: " 
              << privFilename << " (private), " << pubFilename << " (public)" << std::endl;
}

int main() {
    // تولید کلید 1024 بیتی
    GenerateAndSaveRSAKeyPair(1024, "rsa_private_1024.pem", "rsa_public_1024.pem");

    // تولید کلید 2048 بیتی
    GenerateAndSaveRSAKeyPair(2048, "rsa_private_2048.pem", "rsa_public_2048.pem");

    // تولید کلید 4096 بیتی
    GenerateAndSaveRSAKeyPair(4096, "rsa_private_4096.pem", "rsa_public_4096.pem");

    return 0;
}
