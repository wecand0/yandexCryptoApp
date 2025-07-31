#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>

using namespace CryptoGuard;

struct IfStreamDeleter {
    void operator()(std::ifstream *stream) const noexcept {
        if (stream && stream->is_open())
            stream->close();
        delete stream;
    }
};
struct OfStreamDeleter {
    void operator()(std::ofstream *stream) const noexcept {
        if (stream && stream->is_open())
            stream->close();
        delete stream;
    }
};

int main(const int argc, char *argv[]) {
    try {

        auto options = std::make_unique<ProgramOptions>();
        options->Parse(argc, argv);

        // Если запрашивается help, выходим
        if (options->IsHelpRequested()) {
            return 0;
        }

        auto crypter = std::make_unique<CryptoGuardCtx>();

        switch (options->GetCommand()) {
        case ProgramOptions::COMMAND_TYPE::ENCRYPT: {
            std::unique_ptr<std::ifstream, IfStreamDeleter> inputFile(new std::ifstream(options->GetInputPath()));
            if (!inputFile->is_open()) {
                throw std::runtime_error("Cannot open input file");
            }

            std::unique_ptr<std::ofstream, OfStreamDeleter> outputFile(new std::ofstream(options->GetOutputPath()));
            if (!outputFile->is_open()) {
                throw std::runtime_error("Cannot open output file");
            }

            std::iostream input_stream(inputFile->rdbuf());
            std::iostream output_stream(outputFile->rdbuf());

            crypter->EncryptFile(input_stream, output_stream, options->GetPassword());

            std::println("File encrypted successfully!");
            break;
        }

        case ProgramOptions::COMMAND_TYPE::DECRYPT: {
            std::unique_ptr<std::ifstream, IfStreamDeleter> inputFile(
                (std::make_unique<std::ifstream>(options->GetInputPath()).get()));
            if (!inputFile->is_open()) {
                throw std::runtime_error("Cannot open input file");
            }

            std::unique_ptr<std::ofstream, OfStreamDeleter> outputFile(new std::ofstream(options->GetOutputPath()));
            if (!outputFile->is_open()) {
                throw std::runtime_error("Cannot open output file");
            }

            std::iostream input_stream(inputFile->rdbuf());
            std::iostream output_stream(outputFile->rdbuf());
            crypter->DecryptFile(input_stream, output_stream, options->GetPassword());
            std::println("File decrypted successfully!");
            break;
        }

        case ProgramOptions::COMMAND_TYPE::CHECKSUM: {
            std::unique_ptr<std::ifstream, IfStreamDeleter> inputFile(new std::ifstream(options->GetInputPath()));
            if (!inputFile->is_open()) {
                throw std::runtime_error("Cannot open input file");
            }
            std::iostream input_stream(inputFile->rdbuf());
            std::println("SHA-256: {}", crypter->CalculateChecksum(input_stream));
            break;
        }

        case ProgramOptions::COMMAND_TYPE::HELP:
            // Уже обработано выше
            break;

        case ProgramOptions::COMMAND_TYPE::UNKNOWN:
            std::println(stderr, "Error: Unknown command");
            return 1;
        default: {
        }
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