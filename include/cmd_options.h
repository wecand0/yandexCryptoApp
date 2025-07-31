#pragma once

#include <boost/program_options.hpp>

#include <print>
#include <unordered_map>

namespace CryptoGuard {

namespace po = boost::program_options;

class ProgramOptions {
public:
    ProgramOptions();
    ProgramOptions(ProgramOptions &) = delete;
    ProgramOptions &operator=(const ProgramOptions &) = delete;
    ProgramOptions(ProgramOptions &&) = delete;
    ProgramOptions &operator=(ProgramOptions &&) = delete;
    ~ProgramOptions() = default;

    void Parse(int argc, char *argv[]);

    enum class COMMAND_TYPE { ENCRYPT, DECRYPT, CHECKSUM, HELP, UNKNOWN };

    bool IsHelpRequested() const noexcept;
    COMMAND_TYPE GetCommand() const noexcept;
    std::string_view GetInputPath() const noexcept;
    std::string_view GetOutputPath() const noexcept;
    std::string_view GetPassword() const noexcept;

private:
    // Маппинг строковых команд на enum
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {{"encrypt", COMMAND_TYPE::ENCRYPT},
                                                                                {"decrypt", COMMAND_TYPE::DECRYPT},
                                                                                {"checksum", COMMAND_TYPE::CHECKSUM},
                                                                                {"help", COMMAND_TYPE::HELP},
                                                                                {"unknown", COMMAND_TYPE::UNKNOWN}};
    COMMAND_TYPE MapStringToCommand(const std::string_view &cmd) const;
    void ValidateOptions() const;
    void ValidateFilePaths() const;

    bool isHelp_{};
    COMMAND_TYPE command_ = COMMAND_TYPE::UNKNOWN;

    std::string_view inputFile_;
    std::string_view outputFile_;
    std::string_view password_;

    po::variables_map vm_;
    po::options_description desc_;
};
}  // namespace CryptoGuard