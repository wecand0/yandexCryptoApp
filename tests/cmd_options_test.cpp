#include <gtest/gtest.h>

#include "programOptions.h"

using namespace CryptoGuard;

// Вспомогательная функция для создания argv из строк
std::vector<char *> CreateArgv(const std::vector<std::string> &args) {
    static std::vector<std::string> storage;  // static для сохранения строк
    static std::vector<char *> ptrs;

    storage = args;  // копируем строки
    ptrs.clear();

    for (auto &arg : storage) {
        ptrs.push_back(const_cast<char *>(arg.c_str()));
    }

    return ptrs;
}

// Тест 1: Валидная команда encrypt с полными параметрами
TEST(ProgramOptions, ValidEncryptCommand) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "encrypt", "--input", "/path/to/input.txt", "--output",
                            "/path/to/output.enc", "--password", "strongpassword123"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputPath(), "/path/to/input.txt");
    EXPECT_EQ(options.GetOutputPath(), "/path/to/output.enc");
    EXPECT_EQ(options.GetPassword(), "strongpassword123");
    EXPECT_FALSE(options.IsHelpRequested());
}

// Тест 2: Валидная команда decrypt
TEST(ProgramOptions, ValidDecryptCommand) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "decrypt", "--input", "encrypted_file.enc", "--output",
                            "decrypted_file.txt", "--password", "mypassword"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputPath(), "encrypted_file.enc");
    EXPECT_EQ(options.GetOutputPath(), "decrypted_file.txt");
    EXPECT_EQ(options.GetPassword(), "mypassword");
}

// Тест 3: Валидная команда checksum
TEST(ProgramOptions, ValidChecksumCommand) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "checksum", "--input", "document.pdf"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputPath(), "document.pdf");
}

// Тест 4: Help команда
TEST(ProgramOptions, HelpCommand) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--help"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_TRUE(options.IsHelpRequested());
}

// Тест 5: Короткие опции
TEST(ProgramOptions, ShortOptions) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "-c", "encrypt", "-i", "test.txt", "-o", "test.enc", "-p", "password123"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputPath(), "test.txt");
    EXPECT_EQ(options.GetOutputPath(), "test.enc");
    EXPECT_EQ(options.GetPassword(), "password123");
}

// Тест 6: Неизвестная команда
TEST(ProgramOptions, UnknownCommand) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "invalid_command", "--input", "test.txt"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
}

// Тест 7: Отсутствие команды
TEST(ProgramOptions, MissingCommand) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--input", "test.txt"});

    EXPECT_THROW(options.Parse(argv.size(), argv.data()), std::invalid_argument);
}

// Тест 8: Отсутствие input файла
TEST(ProgramOptions, MissingInputFile) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "encrypt", "--output", "output.enc", "--password", "password"});

    EXPECT_THROW(options.Parse(argv.size(), argv.data()), std::invalid_argument);
}

// Тест 9: Encrypt без output файла
TEST(ProgramOptions, EncryptWithoutOutput) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "encrypt", "--input", "test.txt", "--password", "password"});

    EXPECT_THROW(options.Parse(argv.size(), argv.data()), std::invalid_argument);
}

// Тест 10: Encrypt без пароля
TEST(ProgramOptions, EncryptWithoutPassword) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "encrypt", "--input", "test.txt", "--output", "test.enc"});

    EXPECT_THROW(options.Parse(argv.size(), argv.data()), std::invalid_argument);
}

// Тест 11: Decrypt без пароля
TEST(ProgramOptions, DecryptWithoutPassword) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "decrypt", "--input", "test.enc", "--output", "test.txt"});

    EXPECT_THROW(options.Parse(argv.size(), argv.data()), std::invalid_argument);
}

// Тест 12: Команды чувствительны к регистру
TEST(ProgramOptions, CaseSensitiveCommands) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "ENCRYPT", "--input", "test.txt", "--output", "test.enc",
                            "--password", "password"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
}

// Тест 13: Пароль со специальными символами
TEST(ProgramOptions, PasswordWithSpecialChars) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "encrypt", "--input", "test.txt", "--output", "test.enc",
                            "--password", "My P@ssw0rd! With Spaces & Symbols"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetPassword(), "My P@ssw0rd! With Spaces & Symbols");
}

// Тест 14: Пути с пробелами
TEST(ProgramOptions, PathsWithSpaces) {
    ProgramOptions options;
    auto argv = CreateArgv({"cryptoguard", "--command", "checksum", "--input", "/path/with spaces/my document.txt"});

    EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
    EXPECT_EQ(options.GetInputPath(), "/path/with spaces/my document.txt");
}

// Тест 15: Все валидные команды
TEST(ProgramOptions, AllValidCommands) {
    struct TestCase {
        std::string command;
        ProgramOptions::COMMAND_TYPE expected;
    };

    std::vector<TestCase> cases = {{"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
                                   {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
                                   {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM}};

    for (const auto &test : cases) {
        ProgramOptions options;
        auto argv = CreateArgv({"cryptoguard", "--command", test.command, "--input", "test.txt", "--output",
                                "output.txt", "--password", "password"});

        EXPECT_NO_THROW(options.Parse(argv.size(), argv.data()));
        EXPECT_EQ(options.GetCommand(), test.expected);
    }
}
