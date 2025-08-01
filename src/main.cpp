#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>

using namespace CryptoGuard;

struct IfStreamDeleter {
    void operator()(std::ifstream *stream) const noexcept {
        if (stream) {
            if (stream->is_open()) {
                stream->close();
            }
            delete stream;
        }
    }
};
struct OfStreamDeleter {
    void operator()(std::ofstream *stream) const noexcept {
        if (stream) {
            if (stream->is_open()) {
                stream->close();
            }
            delete stream;
        }
    }
};

template <typename FileStream, typename Deleter>
std::unique_ptr<FileStream, Deleter> createFileStream(std::string &&path) {
    auto stream = std::unique_ptr<FileStream, Deleter>(new FileStream(std::move(path), std::ios::binary));
    if (!stream->is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }

    return stream;
}

int handleEncrypt(std::unique_ptr<CryptoGuardCtx> &&crypter, std::unique_ptr<ProgramOptions> &&options) {
    const auto inputFile = createFileStream<std::ifstream, IfStreamDeleter>(options->GetInputPath());
    const auto outputFile = createFileStream<std::ofstream, OfStreamDeleter>(options->GetOutputPath());

    std::iostream inputStream(inputFile->rdbuf());
    std::iostream outputStream(outputFile->rdbuf());

    crypter->EncryptFile(inputStream, outputStream, options->GetPassword());
    std::println("File encrypted successfully!");
    return 0;
}
int handleDecrypt(std::unique_ptr<CryptoGuardCtx> &&crypter, std::unique_ptr<ProgramOptions> &&options) {
    const auto inputFile = createFileStream<std::ifstream, IfStreamDeleter>(options->GetInputPath());
    const auto outputFile = createFileStream<std::ofstream, OfStreamDeleter>(options->GetOutputPath());

    std::iostream inputStream(inputFile->rdbuf());
    std::iostream outputStream(outputFile->rdbuf());

    crypter->DecryptFile(inputStream, outputStream, options->GetPassword());
    std::println("File decrypted successfully!");
    return 0;
}

int handleChecksum(std::unique_ptr<CryptoGuardCtx> &&crypter, std::unique_ptr<ProgramOptions> &&options) {
    const auto inputFile = createFileStream<std::ifstream, IfStreamDeleter>(options->GetInputPath());

    std::iostream inputStream(inputFile->rdbuf());

    std::println("SHA-256: {}", crypter->CalculateChecksum(inputStream));
    return 0;
}

int main(const int argc, char *argv[]) {
    try {
        auto options = std::make_unique<ProgramOptions>();
        options->Parse(argc, argv);

        // Если запрашивается help, выходим
        if (options->IsHelpRequested()) {
            return 0;
        }

        auto crypter = std::make_unique<CryptoGuardCtx>();

        // Перемещаем crypter, options, объекты больше не нужны после обработки
        switch (options->GetCommand()) {
        case ProgramOptions::COMMAND_TYPE::ENCRYPT:
            return handleEncrypt(std::move(crypter), std::move(options));
        case ProgramOptions::COMMAND_TYPE::DECRYPT:
            return handleDecrypt(std::move(crypter), std::move(options));
        case ProgramOptions::COMMAND_TYPE::CHECKSUM:
            return handleChecksum(std::move(crypter), std::move(options));
        case ProgramOptions::COMMAND_TYPE::HELP:
            // Уже обработано выше
            return 0;
        case ProgramOptions::COMMAND_TYPE::UNKNOWN:
            std::println(stderr, "Error: Unknown command");
            return 1;
        default:
            std::println(stderr, "Error: Unhandled command type");
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