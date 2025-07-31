#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>

using namespace CryptoGuard;

int main(const int argc, char *argv[]) {
    try {

        auto ctx = std::make_unique<CryptoGuardCtx>();

        std::stringstream input("hello");
        std::stringstream output, o;

        ctx->EncryptFile(input, output, "12345");

        std::println("{}", output.str());

        ctx->DecryptFile(output, o, "12345");

        std::println("{}", o.str());

        const auto options = std::make_unique<ProgramOptions>();
        options->Parse(argc, argv);

        // Если запрашивается help, выходим
        if (options->IsHelpRequested()) {
            return 0;
        }

        // Выполнение команды
        switch (options->GetCommand()) {
        case ProgramOptions::COMMAND_TYPE::ENCRYPT: {
            std::println("File encrypted successfully!");
            break;
        }

        case ProgramOptions::COMMAND_TYPE::DECRYPT: {
            std::println("File decrypted successfully!");
            break;
        }

        case ProgramOptions::COMMAND_TYPE::CHECKSUM: {
            std::println("SHA-256: {}", "checksum");
            break;
        }

        case ProgramOptions::COMMAND_TYPE::HELP:
            // Уже обработано выше
            break;

        case ProgramOptions::COMMAND_TYPE::UNKNOWN:
            std::println(stderr, "Error: Unknown command");
            return 1;
        }

    } catch (const std::exception &e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    } catch (...) {
        std::println(stderr, "Unknown error occurred");
        return 1;
    }

    return 0;
}