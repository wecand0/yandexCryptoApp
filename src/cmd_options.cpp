#include "cmd_options.h"

#include <boost/program_options.hpp>

// для печати 'options_description' в консоль c помощью std::println
template <>
struct std::formatter<boost::program_options::options_description> : std::formatter<std::string> {
    auto format(const boost::program_options::options_description &desc, std::format_context &ctx) const {
        std::ostringstream oss;
        oss << desc;
        return std::formatter<std::string>::format(oss.str(), ctx);
    }
};

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Print help message")("command,c", po::value<std::string>(),
                                                        "encrypt | decrypt | checksum")(
        "input,i", po::value<std::string>(),
        "Input file path")("output,o", po::value<std::string>(),
                           "Output file path")("password,p", po::value<std::string>(), "Encryption password");
}

void ProgramOptions::Parse(const int argc, char *argv[]) {
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm_);
        po::notify(vm_);

        if (vm_.contains("help")) {
            isHelp_ = true;
            std::println("{}", desc_);
            return;
        }

        ValidateOptions();
        ValidateFilePaths();

        // Парсинг команды
        if (vm_.contains("command")) {
            command_ = MapStringToCommand(vm_["command"].as<std::string>());

            // Проверяем, что команда распознана
            if (command_ == COMMAND_TYPE::UNKNOWN) {
                std::println(stderr, "Error: Unknown command '{}'. Available commands: encrypt, decrypt, checksum",
                             vm_["command"].as<std::string>());
                std::println("{}", desc_);
                return;
            }
        }

        // Парсинг остальных опций
        if (vm_.contains("input")) {
            inputFile_ = vm_["input"].as<std::string>();
        }

        if (vm_.contains("output")) {
            outputFile_ = vm_["output"].as<std::string>();
        }

        if (vm_.contains("password")) {
            password_ = vm_["password"].as<std::string>();
        }
    } catch (const po::error &e) {
        throw std::runtime_error("Command line error: " + std::string(e.what()));
    }
}

ProgramOptions::COMMAND_TYPE ProgramOptions::MapStringToCommand(const std::string_view &cmd) const {
    if (const auto it = commandMapping_.find(cmd); it != commandMapping_.end()) {
        return it->second;
    }

    // Если команда не найдена, возвращаем UNKNOWN
    return COMMAND_TYPE::UNKNOWN;
}

void ProgramOptions::ValidateOptions() const {
    // Проверяем наличие обязательных опций
    if (!vm_.contains("command")) {
        throw std::invalid_argument("Command is required. Use --help for usage information.");
    }
    if (!vm_.contains("input")) {
        throw std::invalid_argument("Input file is required.");
    }

    const auto cmd = vm_["command"].as<std::string>();

    // Для encrypt и decrypt требуется output file и password
    if (cmd == "encrypt" || cmd == "decrypt") {
        if (!vm_.contains("output")) {
            throw std::invalid_argument("Output file is required for " + cmd + " command.");
        }
        if (!vm_.contains("password")) {
            throw std::invalid_argument("Password is required for " + cmd + " command.");
        }
    }

    // Для checksum password и output не нужны, но предупреждаем, если они указаны
    if (cmd == "checksum") {
        if (vm_.contains("password")) {
            std::println("Warning: Password is not used for checksum command.");
        }
        if (vm_.contains("output")) {
            std::println("Warning: Output file is not used for checksum command.");
        }
    }
}
void ProgramOptions::ValidateFilePaths() const {
    auto hasWhitespace = [](const std::string &str) -> bool {
        return std::ranges::any_of(str, [](const unsigned char c) { return std::isspace(c); });
    };

    if (vm_.contains("input")) {
        if (const auto inputPath = vm_["input"].as<std::string>(); hasWhitespace(inputPath)) {
            throw std::invalid_argument("Input file path cannot contain spaces: " + inputPath);
        }
    }

    // Проверяем output путь на наличие пробелов
    if (vm_.contains("output")) {
        if (const auto outputPath = vm_["output"].as<std::string>(); hasWhitespace(outputPath)) {
            throw std::invalid_argument("Output file path cannot contain spaces: " + outputPath);
        }
    }
}

bool ProgramOptions::IsHelpRequested() const noexcept { return isHelp_; }

ProgramOptions::COMMAND_TYPE ProgramOptions::GetCommand() const noexcept { return command_; }

std::string ProgramOptions::GetInputPath() const noexcept { return inputFile_; }

std::string ProgramOptions::GetOutputPath() const noexcept { return outputFile_; }

std::string ProgramOptions::GetPassword() const noexcept { return password_; }

}  // namespace CryptoGuard
