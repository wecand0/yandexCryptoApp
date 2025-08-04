#include <gtest/gtest.h>

#include "crypto_guard_ctx.h"
#include <sstream>
#include <string>

using namespace CryptoGuard;

// =============== ТЕСТЫ ДЛЯ ШИФРОВАНИЯ ===============

// Тест 1: Базовое шифрование простого текста
TEST(CryptoGuardEncrypt, BasicTextEncryption) {
    CryptoGuardCtx crypto;
    const std::string original_data = "Hello, World!!!";
    const std::string password = "test_password_";

    std::stringstream input(original_data);
    std::stringstream output;

    EXPECT_NO_THROW(crypto.EncryptFile(input, output, password));

    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, original_data);  // Зашифрованные данные должны отличаться
}

// Тест 2: Шифрование пустых данных
TEST(CryptoGuardEncrypt, EmptyDataEncryption) {
    CryptoGuardCtx crypto;
    const std::string empty_data;
    const std::string password = "password12345qwerty";

    std::stringstream input(empty_data);
    std::stringstream output;

    EXPECT_NO_THROW(crypto.EncryptFile(input, output, password));

    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());  // Даже пустые данные дают результат из-за padding
}

// Тест 3: Шифрование с разными паролями дает разные результаты
TEST(CryptoGuardEncrypt, DifferentPasswordsDifferentResults) {
    CryptoGuardCtx crypto;
    const std::string data = "payload";

    std::stringstream input1(data);
    std::stringstream output1;
    crypto.EncryptFile(input1, output1, "pass0");

    std::stringstream input2(data);
    std::stringstream output2;
    crypto.EncryptFile(input2, output2, "pass1");

    EXPECT_NE(output1.str(), output2.str());
}

// Тест 4: Шифрование больших данных
TEST(CryptoGuardEncrypt, LargeDataEncryption) {
    CryptoGuardCtx crypto;

    // Создаем данные размером больше буфера (> 1024 байт)
    std::string large_data;
    large_data.reserve(1024 * 128);
    for (auto i = 0; i < 1024 * 128; ++i) {
        large_data += static_cast<char>('A' + i % 2);
    }

    std::stringstream input(large_data);
    std::stringstream output;

    EXPECT_NO_THROW(crypto.EncryptFile(input, output, "passw0rd"));

    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());
}

// Тест 5: Шифрование с некорректным потоком
TEST(CryptoGuardEncrypt, BadStreamEncryption) {
    CryptoGuardCtx crypto;

    std::stringstream input("test");
    std::stringstream output;

    // Устанавливаем плохое состояние потока
    input.setstate(std::ios::badbit);

    EXPECT_THROW(crypto.EncryptFile(input, output, "password"), std::runtime_error);
}

// =============== ТЕСТЫ ДЛЯ ДЕШИФРОВАНИЯ ===============

// Тест 6: Базовое дешифрование - полный цикл шифрование->дешифрование
TEST(CryptoGuardDecrypt, BasicDecryptionCycle) {
    CryptoGuardCtx crypto;
    const std::string original_data = "Hello world";
    const std::string password = "password";

    // Шифруем
    std::stringstream encrypt_input(original_data);
    std::stringstream encrypted_output;
    crypto.EncryptFile(encrypt_input, encrypted_output, password);

    // Дешифруем
    std::stringstream decrypt_input(encrypted_output.str());
    std::stringstream decrypted_output;
    EXPECT_NO_THROW(crypto.DecryptFile(decrypt_input, decrypted_output, password));

    EXPECT_EQ(decrypted_output.str(), original_data);
}

// Тест 7: Дешифрование с неправильным паролем
TEST(CryptoGuardDecrypt, WrongPasswordDecryption) {
    CryptoGuardCtx crypto;
    const std::string data = "TOP SECRET INFO";
    const std::string correct_password = "correct_!_password";
    const std::string wrong_password = "wrong_@_password";

    // Шифруем с правильным паролем
    std::stringstream encrypt_input(data);
    std::stringstream encrypted_output;
    crypto.EncryptFile(encrypt_input, encrypted_output, correct_password);

    // Пытаемся дешифровать с неправильным паролем
    std::stringstream decrypt_input(encrypted_output.str());
    std::stringstream decrypted_output;

    EXPECT_THROW(crypto.DecryptFile(decrypt_input, decrypted_output, wrong_password), std::runtime_error);
}

// Тест 8: Дешифрование поврежденных данных
TEST(CryptoGuardDecrypt, CorruptedDataDecryption) {
    CryptoGuardCtx crypto;
    const std::string corrupted_data = "This is not encrypted data at all!";
    const std::string password = "password";

    std::stringstream input(corrupted_data);
    std::stringstream output;

    EXPECT_THROW(crypto.DecryptFile(input, output, password), std::runtime_error);
}

// Тест 9: Дешифрование пустых зашифрованных данных
TEST(CryptoGuardDecrypt, EmptyEncryptedDataDecryption) {
    CryptoGuardCtx crypto;
    const std::string password = "password";

    // Сначала шифруем пустые данные
    std::stringstream encrypt_input("");
    std::stringstream encrypted_output;
    crypto.EncryptFile(encrypt_input, encrypted_output, password);

    // Дешифруем
    std::stringstream decrypt_input(encrypted_output.str());
    std::stringstream decrypted_output;
    EXPECT_NO_THROW(crypto.DecryptFile(decrypt_input, decrypted_output, password));

    EXPECT_EQ(decrypted_output.str(), "");
}

// Тест 10: Дешифрование с некорректным потоком
TEST(CryptoGuardDecrypt, BadStreamDecryption) {
    CryptoGuardCtx crypto;

    std::stringstream input("some essential words in the world lololo ololol");
    std::stringstream output;

    // Устанавливаем специально для теста
    output.setstate(std::ios::badbit);

    EXPECT_THROW(crypto.DecryptFile(input, output, "password"), std::runtime_error);
}

// =============== ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ ===============

// Тест 11: Проверка, что одинаковые данные с одинаковым паролем дают одинаковый результат
TEST(CryptoGuardExtra, ConsistentEncryption) {
    CryptoGuardCtx crypto;
    const std::string data = "consistent_data";
    const std::string password = "consistent_password";

    // Первое шифрование
    std::stringstream input1(data);
    std::stringstream output1;
    crypto.EncryptFile(input1, output1, password);

    // Второе шифрование тех же данных
    std::stringstream input2(data);
    std::stringstream output2;
    crypto.EncryptFile(input2, output2, password);

    // Результаты должны быть одинаковыми (так как используется фиксированная соль)
    EXPECT_EQ(output1.str(), output2.str());
}

// Тест 12: Тест производительности - большой объем данных
TEST(CryptoGuardExtra, LargeDataPerformance) {
    CryptoGuardCtx crypto;

    // Создаем данные размером 1MB
    std::string large_data;
    large_data.reserve(5 * 1024 * 1024);
    for (int i = 0; i < 5 * 1024 * 1024; ++i) {
        large_data += static_cast<char>('A' + (i % 2));
    }

    const std::string password = "performance";

    // Шифрование
    std::stringstream encrypt_input(large_data);
    std::stringstream encrypted_output;
    EXPECT_NO_THROW(crypto.EncryptFile(encrypt_input, encrypted_output, password));

    // Дешифрование
    std::stringstream decrypt_input(encrypted_output.str());
    std::stringstream decrypted_output;
    EXPECT_NO_THROW(crypto.DecryptFile(decrypt_input, decrypted_output, password));

    EXPECT_EQ(decrypted_output.str(), large_data);
}

// Тест 13: Шифрование специальных символов и Unicode
TEST(CryptoGuardExtra, UnicodeAndSpecialChars) {
    CryptoGuardCtx crypto;
    const std::string unicode_data = "Hello, ¦® Special: !@#$%^&*()_+=()_+-=[]{}|;':\",./<>?";
    const std::string password = "unicode_password_тест_для_яндекс_测试";

    // Полный цикл с Unicode данными
    std::stringstream encrypt_input(unicode_data);
    std::stringstream encrypted_output;
    crypto.EncryptFile(encrypt_input, encrypted_output, password);

    std::stringstream decrypt_input(encrypted_output.str());
    std::stringstream decrypted_output;
    crypto.DecryptFile(decrypt_input, decrypted_output, password);

    EXPECT_EQ(decrypted_output.str(), unicode_data);
}

// =============== ТЕСТЫ ДЛЯ CHECKSUM ===============

// Тест 14: Базовый checksum
TEST(CryptoGuardChecksum, BasicChecksum) {
    CryptoGuardCtx crypto;
    const std::string data = "Hello, Checksum World!";

    std::stringstream input(data);
    std::string checksum;

    EXPECT_NO_THROW(checksum = crypto.CalculateChecksum(input));
    EXPECT_FALSE(checksum.empty());
    // SHA-256 = 32 bytes = 64 hex chars
    EXPECT_EQ(checksum.length(), 64);

    // Проверяем, что результат содержит только hex символы
    for (const char c : checksum) {
        EXPECT_TRUE(std::isxdigit(c));
    }
}

// Тест 15: Consistency - одинаковые данные дают одинаковый checksum
TEST(CryptoGuardChecksum, ConsistentChecksum) {
    CryptoGuardCtx crypto;
    const std::string data = "Consistent checksum test data";

    std::stringstream input1(data);
    std::stringstream input2(data);

    std::string checksum1 = crypto.CalculateChecksum(input1);
    std::string checksum2 = crypto.CalculateChecksum(input2);

    EXPECT_EQ(checksum1, checksum2);
}